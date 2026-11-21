import json, sys
sys.path.insert(0, r"C:\PerchGuest\client\site-packages")
sys.path.insert(0, r"C:\PerchGuest\client\src")
from perchvpn_windows import tun_state_capture as tsc
try:
    snap = tsc.capture_snapshot()
    routes = [r for r in (snap.routes or []) if str(r.get("DestinationPrefix", "")).strip() == "0.0.0.0/0"]
    print("ROUTES_DEFAULT:", json.dumps(routes))
    adapters = [
        {k: a.get(k) for k in ("InterfaceIndex", "Name", "Status", "ifIndex", "InterfaceAlias")}
        for a in (snap.adapters or [])
    ]
    print("ADAPTERS:", json.dumps(adapters))
    egress = tsc.detect_physical_egress(snap)
    print("IP_ADDRESSES:", json.dumps([
        {k: r.get(k) for k in ("InterfaceIndex", "IPAddress")} for r in (snap.ip_addresses or [])
    ]))
    print("IFACE_CFG:", json.dumps(snap.interface_config or []))
    print("EGRESS:", egress)
except Exception as exc:
    import traceback; traceback.print_exc()
