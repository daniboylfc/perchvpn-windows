"""Direct Win32 IP Helper access for fast network-state capture.

The PowerShell/CIM probes used elsewhere cost 1-3 s per spawn, which pushed
TUN pre-start capture past the startup preflight budget and made post-stop
verification the slowest part of a disconnect.  The IP Helper API answers the
same questions in milliseconds via ``iphlpapi.dll``:

  GetAdaptersAddresses   -> adapters, unicast addresses, DNS servers
  GetIpForwardTable2     -> IPv4/IPv6 route table
  GetIpInterfaceEntry    -> interface metric / MTU / connected state
  SetIpInterfaceEntry    -> metric pinning
  GetBestRoute2          -> route lookup for one destination

Every function returns ``None``/``[]``/``False`` on any failure so callers can
fall back to the proven PowerShell path; native output is only trusted when
it passes the sanity guards below.  Parse helpers take raw bytes so they are
unit-testable on non-Windows hosts.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import socket
import struct
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("perchvpn_windows.iphelper")

ERROR_SUCCESS = 0
ERROR_BUFFER_OVERFLOW = 111

AF_INET = 2
AF_INET6 = 23
AF_UNSPEC = 0
MAX_ADAPTER_ADDRESS_LENGTH = 8
SCOPE_LEVEL_COUNT = 16

# GetAdaptersAddresses flag: include SWD (Wintun) software adapters.
_GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x00000100
_GAA_FLAG_SKIP_ANYCAST = 0x00000002
_GAA_FLAG_SKIP_MULTICAST = 0x00000004
_GAA_FLAGS = (
    _GAA_FLAG_INCLUDE_ALL_INTERFACES | _GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST
)

# IfOperStatus values (RFC 2863); rendered in Get-NetAdapter style text.
_OPER_STATUS = {
    1: "Up",
    2: "Down",
    3: "Testing",
    4: "Unknown",
    5: "Dormant",
    6: "Not Present",
    7: "Lower layer down",
}

_SANE_METRIC_RANGE = (1, 10000)
_SANE_MTU_RANGE = (576, 65535)
_MAX_UINT32 = 0xFFFFFFFF

_IS_WINDOWS = sys.platform == "win32"

_iphlpapi: Optional[Any] = None  # lazy WinDLL('iphlpapi.dll'); Windows only

# IP_ADAPTER_ADDRESSES_LH offsets within one row (64-bit layout):
#   Alignment(8) Next(8) AdapterName(8) FirstUnicast(8) FirstAnycast(8)
#   FirstMulticast(8) FirstDnsServer(8) DnsSuffix(8) Description(8)
#   FriendlyName(8) PhysicalAddress[8] PhysicalAddressLength(4) Flags(4)
#   Mtu(4) IfType(4) OperStatus(4) Ipv6IfIndex(4) ZoneIndices[16]
#   FirstPrefix(8) TransmitLinkSpeed(8) ReceiveLinkSpeed(8) FirstWins(8)
#   FirstGateway(8) Ipv4Metric(8) Luid(8) Dhcpv4Server(16) CompartmentId(4)
#   NetworkGuid(16) ConnectionType(4) TunnelType(4)
_OFF_ADAPTER_NAME = 16
_OFF_FIRST_UNICAST = 24
_OFF_FIRST_DNS_SERVER = 48
_OFF_DESCRIPTION = 64
_OFF_FRIENDLY_NAME = 72
_OFF_OPER_STATUS = 104

# IP_ADAPTER_UNICAST_ADDRESS_XP: Alignment(8) Next(8) SOCKET_ADDRESS(16)
#   PrefixOrigin(4) SuffixOrigin(4) ValidLifetime(4) PreferredLifetime(4)
#   OnLinkPrefixLength(1) SkipAsSource(1) DadState(4) ...
# OnLinkPrefixLength sits after Address(16) + PrefixOrigin/SuffixOrigin/
# DadState/Valid/Preferred/Lease lifetimes (offsets 32..52).  Reading 48
# returned the low byte of PreferredLifetime (0xFF), so every native prefix
# looked invalid and unicast_native() zeroed it.
_OFF_UNICAST_PREFIX_LEN = 56
_UNICAST_NODE_SIZE = 72
_DNS_NODE_SIZE = 32
# MIB_*_TABLE2 layout: ULONG NumEntries followed by rows at the row type's
# 8-byte alignment (offset 8 on x64), not immediately after the count.
# Sizes are the Windows SDK values; the ctypes shadows carry extra padding
# (MIB_UNICASTIPADDRESS_ROW reports 88 instead of 80), which silently
# truncated every table walk to its first row.
_MIB_TABLE_ROWS_OFFSET = 8
_IPFORWARD_ROW_SIZE = 104


class _SockaddrInet(ctypes.Union):
    _fields_ = [
        ("sin6", 28 * ctypes.c_ubyte),
        ("si_family", ctypes.c_ushort),
    ]


SOCKADDR_INET = _SockaddrInet


class _IpAddressPrefix(ctypes.Structure):
    _fields_ = [
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", ctypes.c_ubyte),
        ("_pad", 3 * ctypes.c_ubyte),
    ]


IP_ADDRESS_PREFIX = _IpAddressPrefix


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", ctypes.c_ubyte),
        ("_pad", 3 * ctypes.c_ubyte),
        ("ValidLifetime", ctypes.c_uint32),
        ("PreferredLifetime", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("Protocol", ctypes.c_int32),
        ("Loopback", ctypes.c_ubyte),
        ("AutoconfigureAddress", ctypes.c_ubyte),
        ("Publish", ctypes.c_ubyte),
        ("Immortal", ctypes.c_ubyte),
        ("Age", ctypes.c_uint32),
        ("Origin", ctypes.c_int32),
    ]


class MIB_IPINTERFACE_ROW(ctypes.Structure):
    _fields_ = [
        ("Family", ctypes.c_ushort),
        ("_pad0", 6 * ctypes.c_ubyte),
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("MaxReassemblySize", ctypes.c_uint32),
        ("InterfaceIdentifier", ctypes.c_uint64),
        ("MinRouterAdvertisementInterval", ctypes.c_uint32),
        ("MaxRouterAdvertisementInterval", ctypes.c_uint32),
        ("AdvertisingEnabled", ctypes.c_ubyte),
        ("ForwardingEnabled", ctypes.c_ubyte),
        ("WeakHostSend", ctypes.c_ubyte),
        ("WeakHostReceive", ctypes.c_ubyte),
        ("UseAutomaticMetric", ctypes.c_ubyte),
        ("UseNeighborUnreachabilityDetection", ctypes.c_ubyte),
        ("ManagedAddressConfigurationSupported", ctypes.c_ubyte),
        ("OtherStatefulConfigurationSupported", ctypes.c_ubyte),
        ("AdvertiseDefaultRoute", ctypes.c_ubyte),
        ("RouterDiscoveryBehavior", ctypes.c_int32),
        ("DadTransmits", ctypes.c_uint32),
        ("BaseReachableTime", ctypes.c_uint32),
        ("RetransmitTime", ctypes.c_uint32),
        ("PathMtuDiscoveryTimeout", ctypes.c_uint32),
        ("LinkLocalAddressBehavior", ctypes.c_int32),
        ("LinkLocalAddressTimeout", ctypes.c_uint32),
        ("ZoneIndices", SCOPE_LEVEL_COUNT * ctypes.c_uint32),
        ("SitePrefixLength", ctypes.c_uint32),
        ("Metric", ctypes.c_uint32),
        ("NlMtu", ctypes.c_uint32),
        ("Connected", ctypes.c_ubyte),
        ("SupportsWakeUpPatterns", ctypes.c_ubyte),
        ("SupportsNeighborDiscovery", ctypes.c_ubyte),
        ("SupportsRouterDiscovery", ctypes.c_ubyte),
        ("ReachableTime", ctypes.c_uint32),
        ("TransmitOffload", ctypes.c_ubyte),
        ("ReceiveOffload", ctypes.c_ubyte),
        ("DisableDefaultRoutes", ctypes.c_ubyte),
    ]


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("_pad0", 4 * ctypes.c_ubyte),
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("PrefixOrigin", ctypes.c_int32),
        ("SuffixOrigin", ctypes.c_int32),
        ("ValidLifetime", ctypes.c_uint32),
        ("PreferredLifetime", ctypes.c_uint32),
        ("OnLinkPrefixLength", ctypes.c_ubyte),
        ("SkipAsSource", ctypes.c_ubyte),
        ("_pad1", 2 * ctypes.c_ubyte),
        ("DadState", ctypes.c_int32),
        ("ScopeId", ctypes.c_uint32),
        ("_pad2", 4 * ctypes.c_ubyte),
        ("CreationTimeStamp", ctypes.c_int64),
    ]


class _SocketAddress(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


def _dll():
    """Lazy iphlpapi handle; ``None`` anywhere except Windows."""
    global _iphlpapi
    if not _IS_WINDOWS:
        return None
    if _iphlpapi is None:
        try:
            dll = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
            dll.GetAdaptersAddresses.restype = ctypes.c_long
            dll.GetIpForwardTable2.restype = ctypes.c_long
            dll.GetIpInterfaceEntry.restype = ctypes.c_long
            dll.SetIpInterfaceEntry.restype = ctypes.c_long
            dll.GetBestRoute2.restype = ctypes.c_long
            dll.GetUnicastIpAddressTable.restype = ctypes.c_long
            dll.FreeMibTable.restype = None
            _iphlpapi = dll
        except OSError:
            logger.warning("iphlpapi.dll unavailable; native capture disabled")
            return None
    return _iphlpapi


def available() -> bool:
    """True when the native path can be attempted on this platform."""
    return _IS_WINDOWS and _dll() is not None


def _sockaddr_text(blob: bytes) -> Optional[tuple]:
    """Decode a raw sockaddr into ``(text, family)`` or ``None``."""
    if len(blob) < 4:
        return None
    family = struct.unpack_from("<H", blob)[0]
    if family == AF_INET:
        if len(blob) < 8:
            return None
        return socket.inet_ntop(socket.AF_INET, blob[4:8]), AF_INET
    if family == AF_INET6:
        if len(blob) < 24:
            return None
        return socket.inet_ntop(socket.AF_INET6, blob[8:24]), AF_INET6
    return None


def _read_wstr_ptr(buffer: bytes, offset: int) -> Optional[str]:
    """Read a NUL-terminated UTF-16LE string through an absolute pointer.

    ``ctypes.wstring_at`` follows the host's wchar_t width (4 bytes on
    Linux), so the bytes are decoded manually; the bounded scan never runs
    past the next NUL.
    """
    if offset + 8 > len(buffer):
        return None
    ptr = struct.unpack_from("<Q", buffer, offset)[0]
    if not ptr:
        return None
    try:
        raw = ctypes.string_at(ptr, 1024)
    except Exception:
        return None
    try:
        text = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return None
    return text.split("\x00", 1)[0] or None


def _read_str_ptr(buffer: bytes, offset: int) -> Optional[str]:
    if offset + 8 > len(buffer):
        return None
    ptr = struct.unpack_from("<Q", buffer, offset)[0]
    if not ptr:
        return None
    try:
        return ctypes.string_at(ptr).decode("utf-8", "replace")
    except Exception:
        return None


def _parse_address_chain(
    buffer: bytes, head_offset: int, node_size: int
) -> List[Dict[str, Any]]:
    """Walk a ``First*Address`` linked list whose nodes live in ``buffer``.

    Each node starts with ``Length(4) + Reserved/Flags(4)``, then ``Next``,
    then a ``SOCKET_ADDRESS`` whose ``lpSockaddr`` points into the buffer.
    """
    if head_offset + 8 > len(buffer):
        return []
    cursor = struct.unpack_from("<Q", buffer, head_offset)[0]
    entries: List[Dict[str, Any]] = []
    seen = set()
    while cursor and cursor not in seen:
        seen.add(cursor)
        try:
            node = ctypes.string_at(cursor, node_size)
        except Exception:
            break
        next_ptr = struct.unpack_from("<Q", node, 8)[0]
        sock_ptr = struct.unpack_from("<Q", node, 16)[0]
        sock_len = struct.unpack_from("<i", node, 24)[0]
        if sock_ptr and 0 < sock_len <= 64:
            try:
                blob = ctypes.string_at(sock_ptr, sock_len)
                decoded = _sockaddr_text(blob)
            except Exception:
                decoded = None
            if decoded:
                text, family = decoded
                entry: Dict[str, Any] = {"IPAddress": text, "AddressFamily": family}
                if node_size >= _OFF_UNICAST_PREFIX_LEN + 1:
                    entry["PrefixLength"] = node[_OFF_UNICAST_PREFIX_LEN]
                entries.append(entry)
        cursor = next_ptr
    return entries


def _adapter_row(row: bytes, if_index: int) -> Dict[str, Any]:
    """Build one capture-shaped row from an ``IP_ADAPTER_ADDRESSES`` blob."""
    return {
        "Name": _read_wstr_ptr(row, _OFF_FRIENDLY_NAME) or "",
        "InterfaceDescription": _read_wstr_ptr(row, _OFF_DESCRIPTION) or "",
        "InterfaceGuid": (_read_str_ptr(row, _OFF_ADAPTER_NAME) or "").strip("{}"),
        "InterfaceIndex": int(if_index),
        "Status": _OPER_STATUS.get(
            struct.unpack_from("<I", row, _OFF_OPER_STATUS)[0], "Unknown"
        ),
        "unicast": _parse_address_chain(row, _OFF_FIRST_UNICAST, _UNICAST_NODE_SIZE),
        "dns": _parse_address_chain(row, _OFF_FIRST_DNS_SERVER, _DNS_NODE_SIZE),
    }


def parse_adapter_buffer(buffer: bytes, size: Optional[int] = None) -> List[Dict[str, Any]]:
    """Parse a contiguous GetAdaptersAddresses blob into capture-shaped rows.

    Pure and platform-independent so tests can feed synthetic buffers.  Live
    buffers are *not* guaranteed contiguous (variable-length strings and
    address chains are packed between rows), so :func:`_walk_adapter_rows`
    follows the ``Next`` pointers for real captures.
    """
    rows: List[Dict[str, Any]] = []
    offset = 0
    seen_offsets = set()
    while offset + 8 <= len(buffer):
        length = struct.unpack_from("<I", buffer, offset)[0]
        if_index = struct.unpack_from("<I", buffer, offset + 4)[0]
        if length < 8 or offset + length > len(buffer) or (size and offset + length > size):
            break
        if offset in seen_offsets:
            break
        seen_offsets.add(offset)
        row = bytes(buffer[offset : offset + length])
        rows.append(_adapter_row(row, if_index))
        offset += length
    return rows


def _walk_adapter_rows(base_addr: int, buffer_size: int) -> List[Dict[str, Any]]:
    """Walk the live adapter list through its ``Next`` pointers.

    Advancing by the ``Length`` field silently truncates the list after the
    first adapter (its 2026-11-18 regression hid Wi-Fi from DNS selection and
    reported the PairedVPN TUN adapter as absent, freezing readiness at
    ``starting``).  Pointers are absolute addresses into the caller's buffer,
    which must stay alive for the duration of the walk.
    """
    rows: List[Dict[str, Any]] = []
    seen = set()
    addr = base_addr
    while addr and addr not in seen and 0 <= addr - base_addr < buffer_size:
        seen.add(addr)
        try:
            length = ctypes.c_uint32.from_address(addr).value
            if length < 8 or addr - base_addr + length > buffer_size:
                break
            row = ctypes.string_at(addr, length)
            if_index = ctypes.c_uint32.from_address(addr + 4).value
            rows.append(_adapter_row(row, if_index))
            addr = ctypes.c_uint64.from_address(addr + 8).value
        except Exception:
            logger.warning("adapter row walk failed", exc_info=True)
            break
    return rows


def adapters_native() -> List[Dict[str, Any]]:
    """Snapshot rows shaped like ``capture_adapters`` plus unicast/DNS data.

    Returns ``[]`` when native capture is unavailable or fails.
    """
    dll = _dll()
    if dll is None:
        return []
    size = 64 * 1024
    for _ in range(6):
        buf = (ctypes.c_ubyte * size)()
        needed = ctypes.c_ulong(size)
        status = dll.GetAdaptersAddresses(
            AF_UNSPEC, _GAA_FLAGS, None, buf, ctypes.byref(needed)
        )
        if status == ERROR_SUCCESS:
            try:
                return _walk_adapter_rows(ctypes.addressof(buf), int(needed.value))
            except Exception:
                logger.warning("adapter buffer parse failed", exc_info=True)
                return []
        if status != ERROR_BUFFER_OVERFLOW:
            logger.warning("GetAdaptersAddresses failed with status %s", status)
            return []
        size = max(int(needed.value), size * 2)
    return []


def unicast_native(family: int = AF_UNSPEC) -> List[Dict[str, Any]]:
    """Rows shaped like ``capture_ip_addresses`` from the adapter chains.

    ``GetUnicastIpAddressTable`` needs a hand-maintained row stride: the real
    ``MIB_UNICASTIPADDRESS_ROW`` is 80 bytes on x64, not the 88 its ctypes
    shadow reports, and a wrong stride decodes only the first row.  The
    ``GetAdaptersAddresses`` unicast chains already parse with verified
    offsets, so they are the single source of truth here.
    """
    rows: List[Dict[str, Any]] = []
    for adapter in adapters_native():
        if_index = int(adapter.get("InterfaceIndex") or 0)
        for entry in adapter.get("unicast") or ():
            fam = entry.get("AddressFamily")
            text = str(entry.get("IPAddress") or "").strip()
            if not text or fam not in (AF_INET, AF_INET6):
                continue
            if family != AF_UNSPEC and fam != family:
                continue
            prefix = int(entry.get("PrefixLength") or 0)
            rows.append(
                {
                    "InterfaceIndex": if_index,
                    "IPAddress": text,
                    "PrefixLength": prefix if 0 <= prefix <= 128 else 0,
                    "AddressFamily": fam,
                }
            )
    return rows


def routes_native(family: int = AF_INET) -> List[Dict[str, Any]]:
    """Rows shaped like ``capture_routes`` from GetIpForwardTable2."""
    dll = _dll()
    if dll is None:
        return []
    table = ctypes.c_void_p()
    status = dll.GetIpForwardTable2(family, ctypes.byref(table))
    if status != ERROR_SUCCESS or not table.value:
        return []
    try:
        # GetIpForwardTable2 returns {ULONG NumEntries; rows...} where the
        # rows start at the 8-byte alignment boundary, not at offset 4.
        count = ctypes.c_uint32.from_address(table.value).value
        stride = _IPFORWARD_ROW_SIZE
        rows: List[Dict[str, Any]] = []
        for i in range(count):
            row = MIB_IPFORWARD_ROW2.from_address(
                table.value + _MIB_TABLE_ROWS_OFFSET + i * stride
            )
            decoded = _sockaddr_text(bytes(row.DestinationPrefix.Prefix))
            if not decoded:
                continue
            text, _fam = decoded
            nexthop = _sockaddr_text(bytes(row.NextHop))
            rows.append(
                {
                    "DestinationPrefix": "%s/%d"
                    % (text, int(row.DestinationPrefix.PrefixLength)),
                    "NextHop": nexthop[0] if nexthop else "0.0.0.0",
                    "InterfaceIndex": int(row.InterfaceIndex),
                    "RouteMetric": int(row.Metric),
                    "PolicyStore": "ActiveStore",
                    # GetIpForwardTable2 does not expose the per-interface
                    # metric; the schema key is nullable but must be present.
                    "ifMetric": None,
                }
            )
        return rows
    finally:
        dll.FreeMibTable(table)


def interface_entry_native(
    ifindex: int, family: int = AF_INET
) -> Optional[Dict[str, Any]]:
    """GetIpInterfaceEntry for one ``(ifindex, family)`` pair.

    Returns ``None`` when the row is absent or any value fails the sanity
    guard — callers fall back to PowerShell rather than trust garbage.
    """
    dll = _dll()
    if dll is None:
        return None
    row = MIB_IPINTERFACE_ROW()
    row.Family = family
    row.InterfaceIndex = int(ifindex)
    row.InterfaceLuid = 0
    status = dll.GetIpInterfaceEntry(ctypes.byref(row))
    if status != ERROR_SUCCESS:
        return None
    metric = int(row.Metric)
    mtu = int(row.NlMtu)
    # 0 is the OS's "automatic metric" (Get-NetIPInterface renders it as null)
    # for down adapters and tunnel interfaces; loopback reports an MTU of
    # 0xFFFFFFFF ("infinite").  Both are legitimate, not capture garbage.
    if not (0 <= metric <= _SANE_METRIC_RANGE[1]):
        return None
    if not (mtu == _MAX_UINT32 or _SANE_MTU_RANGE[0] <= mtu <= _SANE_MTU_RANGE[1]):
        return None
    return {
        "InterfaceIndex": int(ifindex),
        "AddressFamily": int(family),
        "InterfaceMetric": metric,
        "NlMtu": mtu,
        "Connected": bool(row.Connected) if row.Connected in (0, 1) else None,
        "UseAutomaticMetric": bool(row.UseAutomaticMetric),
        "SitePrefixLength": int(row.SitePrefixLength),
        "DisableDefaultRoutes": bool(row.DisableDefaultRoutes),
    }


def set_interface_metric_native(ifindex: int, family: int, metric: int) -> bool:
    """Pin ``InterfaceMetric`` via SetIpInterfaceEntry (read-modify-write).

    The row is first fetched so unrelated fields are preserved.  The setter
    requires ``SitePrefixLength`` to be 0; forcing 0xFF (a value only valid
    for reads) made every call fail with ERROR_INVALID_PARAMETER, so the
    caller silently fell back to two PowerShell round-trips (measured 8 s on
    the 2-vCPU sandbox guest).
    Returns ``False`` on any failure; callers may fall back to PowerShell.
    """
    dll = _dll()
    if dll is None:
        return False
    if not (1 <= int(metric) <= 9999):
        return False
    row = MIB_IPINTERFACE_ROW()
    row.Family = family
    row.InterfaceIndex = int(ifindex)
    row.InterfaceLuid = 0
    if dll.GetIpInterfaceEntry(ctypes.byref(row)) != ERROR_SUCCESS:
        return False
    row.SitePrefixLength = 0
    row.Metric = int(metric)
    row.UseAutomaticMetric = 0
    return dll.SetIpInterfaceEntry(ctypes.byref(row)) == ERROR_SUCCESS


def _sockaddr_inet_text(address: str) -> Optional[bytes]:
    """28-byte SOCKADDR_INET blob for an IP literal, or ``None``."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return None
    blob = bytearray(28)
    if ip.version == 4:
        blob[0:2] = struct.pack("<H", AF_INET)
        blob[4:8] = socket.inet_pton(socket.AF_INET, str(ip))
    else:
        blob[0:2] = struct.pack("<H", AF_INET6)
        blob[8:24] = socket.inet_pton(socket.AF_INET6, str(ip))
    return bytes(blob)


def best_route_interface(destination: str) -> Optional[int]:
    """Interface index the OS route table selects for ``destination``.

    Uses GetBestRoute2 with a zero LUID/source so the lookup reflects the
    live policy table; a longest-prefix walk over GetIpForwardTable2 is the
    fallback.  Returns ``None`` on failure (fail closed).
    """
    dll = _dll()
    if dll is None:
        return None
    blob = _sockaddr_inet_text(destination)
    if blob is None:
        return None
    dest = SOCKADDR_INET.from_buffer_copy(blob)
    best_route = MIB_IPFORWARD_ROW2()
    best_source = SOCKADDR_INET()
    luid = ctypes.c_uint64(0)
    status = dll.GetBestRoute2(
        ctypes.byref(luid),
        0,
        None,
        ctypes.byref(dest),
        0,
        ctypes.byref(best_route),
        ctypes.byref(best_source),
    )
    if status == ERROR_SUCCESS and best_route.InterfaceIndex:
        return int(best_route.InterfaceIndex)
    # Longest-prefix fallback across the route table.
    try:
        ip = ipaddress.ip_address(str(destination).strip())
    except ValueError:
        return None
    best: Optional[tuple] = None
    for row in routes_native(AF_INET if ip.version == 4 else AF_INET6):
        try:
            net = ipaddress.ip_network(row["DestinationPrefix"], strict=False)
        except (ValueError, KeyError):
            continue
        if net.version != ip.version or ip not in net:
            continue
        key = (int(net.prefixlen), -int(row.get("RouteMetric", 0) or 0))
        if best is None or key > best[0]:
            best = (key, row["InterfaceIndex"])
    return best[1] if best else None


def adapter_present_native(
    adapter_guid: Optional[str], adapter_name: str, *, require_up: bool = False
) -> Optional[bool]:
    """True/False when a matching adapter row exists, ``None`` if unknown.

    Matches by interface GUID (braces stripped) or exact friendly name —
    the same identity rules as the PowerShell probe it replaces.

    ``require_up`` counts only an operational (``Status == "Up"``) row as
    present.  Recovery verification uses it because a Wintun device that the
    driver has already torn down can linger in the adapter table with
    IfOperStatus Down: it cannot carry traffic, so it must not latch a clean
    teardown as unverified.
    """
    rows = adapters_native()
    if not rows:
        return None
    guid = str(adapter_guid or "").strip("{}").lower()
    name = str(adapter_name or "").strip()
    for row in rows:
        matched = bool(guid) and (
            str(row.get("InterfaceGuid") or "").strip("{}").lower() == guid
        )
        if not matched and name:
            matched = str(row.get("Name") or "") == name
        if not matched:
            continue
        if not require_up or str(row.get("Status") or "") == "Up":
            return True
    return False


def dns_servers_native(interface_index: int, family_name: str = "IPv4") -> List[str]:
    """Configured DNS servers for one interface index."""
    wanted = AF_INET if str(family_name) != "IPv6" else AF_INET6
    servers: List[str] = []
    for row in adapters_native():
        if int(row.get("InterfaceIndex") or 0) != int(interface_index):
            continue
        for entry in row.get("dns") or ():
            if entry.get("AddressFamily") == wanted:
                text = str(entry.get("IPAddress") or "").strip()
                if text and text not in servers:
                    servers.append(text)
    return servers


def virtual_nat_subnets_native() -> List[str]:
    """Prefixes of live WSL virtual NAT interfaces.

    Detects ``vEthernet (WSL ...)`` adapters and their unicast prefixes so
    ``route_exclude_address`` can carve out exactly the host-local subnets
    instead of relying on blanket RFC1918 ranges.  Returns ``[]`` when
    nothing matches or native enumeration is unavailable.
    """
    subnets: List[str] = []
    for row in adapters_native():
        name = str(row.get("Name") or "")
        if "vEthernet" not in name or "(WSL" not in name:
            continue
        for entry in row.get("unicast") or ():
            text = str(entry.get("IPAddress") or "")
            plen = entry.get("PrefixLength")
            if ":" in text or not text or plen is None:
                continue
            try:
                net = ipaddress.ip_network("%s/%s" % (text, plen), strict=False)
            except ValueError:
                continue
            normalized = str(net)
            if normalized not in subnets:
                subnets.append(normalized)
    return subnets
