#Requires -Version 5.1
<#
.SYNOPSIS
    Offline acceptance test: PerchVPN TUN as a standalone VPN over the
    normal physical Wi-Fi/Ethernet adapter.

.DESCRIPTION
    Run this while the PattN / sing-box client is DISABLED (the script
    refuses to run otherwise, because its tunnel would be the carrier and
    the test would prove nothing).

    The script is deliberately evidence-based and read-only towards the
    host apart from the app's own mode switch:

      1. Refuses to run when a foreign tunnel adapter is Up.
      2. Records the pre-TUN physical Wi-Fi/Ethernet address, gateway and
         interface index (no external service, no mutation).
      3. POSTs {"mode":"tun","apply":true} to the local PerchVPN API and
         triggers the same UAC prompt as clicking "TUN" in the UI.
      4. Polls /api/status until the elevated helper reports READY/failed.
      5. Verifies, from Windows itself:
           - the PerchVPN adapter exists and is Up
           - 0.0.0.0/1 + 128.0.0.0/1 exist on it with RouteMetric 1
           - the adapter's InterfaceMetric is 1
           - every journaled upstream /32 (and /128) pin sits on the
             physical adapter via the physical gateway with metric 1
           - the adapter resolves IPv4 DNS, with no dead fec0:: resolvers
           - system egress reports a public IP different from the physical
             LAN address (i.e. traffic really entered the tunnel)
      6. Writes a machine-readable report to
         %APPDATA%\PerchVPN\wifi-tun-verification.json

    The tunnel is LEFT RUNNING by default so the operator can browse and
    confirm. Pass -RestoreProxy to switch back to SOCKS5+upstream mode at
    the end (or after a failed run).

.PARAMETER BaseUrl
    Local PerchVPN API base URL (default http://127.0.0.1:8765).

.PARAMETER TimeoutSeconds
    How long to wait for the elevated helper to reach READY (default 900;
    a slow on-access AV host has been observed at ~6.5 minutes).

.PARAMETER RestoreProxy
    Switch back to proxy mode when the checks finish, pass or fail.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\verify-normal-wifi-tun.ps1

.EXAMPLE
    .\scripts\verify-normal-wifi-tun.ps1 -RestoreProxy
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:8765',
    [string]$TunAdapter = 'PerchVPN',
    [int]$TimeoutSeconds = 900,
    [switch]$RestoreProxy,
    [switch]$AllowForeignTunnel
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$reportDir = Join-Path $env:APPDATA 'PerchVPN'
$reportPath = Join-Path $reportDir 'wifi-tun-verification.json'
$journalPath = Join-Path $reportDir 'tun-helper-journal.json'
$checks = New-Object System.Collections.ArrayList
$report = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    host         = $env:COMPUTERNAME
    base_url     = $BaseUrl
    result       = 'fail'
    checks       = $checks
    pre_tun      = $null
    post_tun     = $null
    status       = $null
    error        = ''
}

function Add-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $null = $checks.Add([ordered]@{ name = $Name; ok = $Ok; detail = $Detail })
    $prefix = $(if ($Ok) { 'PASS' } else { 'FAIL' })
    Write-Host ("[{0}] {1}: {2}" -f $prefix, $Name, $Detail)
}

function Save-Report {
    if (-not (Test-Path $reportDir)) {
        $null = New-Item -ItemType Directory -Force -Path $reportDir
    }
    $report.checks = @($checks)
    $json = $report | ConvertTo-Json -Depth 8
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($reportPath, $json, $utf8)
    Write-Host ("Report written to {0}" -f $reportPath)
}

function Invoke-Api {
    param(
        [string]$Method = 'Get',
        [string]$Path,
        $Body,
        [int]$TimeoutSec = 30
    )
    $uri = $BaseUrl.TrimEnd('/') + $Path
    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -TimeoutSec $TimeoutSec
    }
    return Invoke-RestMethod -Method $Method -Uri $uri -TimeoutSec $TimeoutSec `
        -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress)
}

function Get-PhysicalLayout {
    # Query the actual IPv4 default route directly. TunnelBear's /1
    # split-default routes must not be mistaken for the physical default route.
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -match 'Wi-Fi|Ethernet' } |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
    if (-not $route) {
        # Fallback to any active non-tunnel default route
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch 'sing|tun|tap|wireguard|wintun|tunnelbear|tailscale|vethernet' } |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1
    }
    if (-not $route) {
        throw 'no IPv4 default route found'
    }
    $index = [int]$route.InterfaceIndex
    $adapter = Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop |
        Select-Object -First 1
    $address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notlike '169.254.*' } |
        Select-Object -First 1
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses)
    [ordered]@{
        adapter         = $adapter.Name
        interface_index = $index
        ipv4            = $(if ($address) { $address.IPAddress } else { '' })
        gateway         = [string]$route.NextHop
        dns             = $dns
    }
}

function Get-ForeignTunnelSnapshot {
    param(
        [string]$TunnelAdapterName = $null,
        [int]$PhysicalInterfaceIndex = -1,
        [string]$ExcludeAdapterName = $null
    )
    # Normalized read-only snapshot of every foreign tunnel adapter and its
    # associated route/DNS/proxy state.  Nothing is mutated.
    #
    # The return value is a structured envelope, never $null, so callers can
    # distinguish three outcomes that were previously conflated:
    #   collection_ok=$false                 -> evidence could not be collected
    #   collection_ok=$true,  present=$false -> no foreign tunnel exists
    #   collection_ok=$true,  present=$true  -> foreign tunnel(s) snapshotted
    # Returning $null for "no tunnel" made a legitimate empty result look
    # identical to a collection failure.
    $empty = {
        param([bool]$ok, [string]$err)
        [ordered]@{
            collection_ok          = $ok
            present                = $false
            count                  = 0
            adapter_ids            = @()
            adapter                = $null
            interface_index        = $null
            interface_guid         = $null
            status                 = $null
            link_speed             = $null
            ipv4                   = $null
            prefix_length          = $null
            dns                    = @()
            dns_v6                 = @()
            routes                 = @()
            wininet_proxy_enable   = $null
            wininet_proxy_server   = $null
            wininet_proxy_override = $null
            winhttp_proxy          = $null
            error                  = $err
        }
    }
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop)
        if ($TunnelAdapterName) {
            $foreign = @($adapters | Where-Object { $_.Name -eq $TunnelAdapterName })
        } else {
            $physicalIndex = $PhysicalInterfaceIndex
            if ($physicalIndex -lt 0) {
                # Fall back to an explicit physical-carrier probe instead of
                # "first default route", which may be owned by the tunnel.
                $physicalRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 `
                    -ErrorAction Stop |
                    Where-Object {
                        $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -match 'Wi-Fi|Ethernet'
                    } |
                    Select-Object -First 1
                if (-not $physicalRoute) {
                    return (& $empty $false 'could not identify the physical default-route carrier')
                }
                $physicalIndex = [int]$physicalRoute.InterfaceIndex
            }
            $foreign = @($adapters | Where-Object {
                $_.Name -ne $ExcludeAdapterName -and
                $_.Status -eq 'Up' -and [int]$_.InterfaceIndex -ne $physicalIndex -and (
                    $_.Name -match 'sing-tun|tun|tap|wireguard|wintun|tunnelbear' -or
                    $_.InterfaceDescription -match 'sing-tun|tun|tap|wireguard|wintun|tunnelbear'
                )
            } | Sort-Object { [int]$_.InterfaceIndex })
        }
        if ($foreign.Count -eq 0) {
            return (& $empty $true '')
        }

        $adapterIds     = @()
        $primary        = $null
        $primaryIndex   = $null
        $primaryAddress = $null
        $primaryDns     = @()
        $primaryDns6    = @()
        $primaryRoutes  = @()
        foreach ($adapter in $foreign) {
            $index = [int]$adapter.InterfaceIndex
            $address = Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
                Where-Object { $_.IPAddress -notlike '169.254.*' } |
                Select-Object -First 1
            $dns = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 `
                    -ErrorAction Stop |
                Select-Object -ExpandProperty ServerAddresses)
            $dns6 = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv6 `
                    -ErrorAction Stop |
                Select-Object -ExpandProperty ServerAddresses)
            $routes = @(Get-NetRoute -InterfaceIndex $index -ErrorAction Stop |
                Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, PolicyStore, AddressFamily)
            $adapterIds += ('{0}|{1}' -f $index, [string]$adapter.InterfaceGuid)
            if (-not $primary) {
                $primary        = $adapter
                $primaryIndex   = $index
                $primaryAddress = $address
                $primaryDns     = $dns
                $primaryDns6    = $dns6
                $primaryRoutes  = $routes
            }
        }
        $wininet = $null
        $winhttp = $null
        try {
            $wininet = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
                -ErrorAction SilentlyContinue | Select-Object ProxyEnable, ProxyServer, ProxyOverride
        } catch { }
        try {
            $winhttp = & netsh winhttp show proxy 2>$null
        } catch { }
        [ordered]@{
            collection_ok          = $true
            present                = $true
            count                  = $foreign.Count
            adapter_ids            = @($adapterIds)
            adapter                = $primary.Name
            interface_index        = $primaryIndex
            interface_guid         = [string]$primary.InterfaceGuid
            status                 = $primary.Status
            link_speed             = [string]$primary.LinkSpeed
            ipv4                   = $(if ($primaryAddress) { $primaryAddress.IPAddress } else { '' })
            prefix_length          = $(if ($primaryAddress) { [int]$primaryAddress.PrefixLength } else { $null })
            dns                    = $primaryDns
            dns_v6                 = $primaryDns6
            routes                 = @($primaryRoutes | ForEach-Object {
                [ordered]@{
                    destination_prefix = [string]$_.DestinationPrefix
                    next_hop           = [string]$_.NextHop
                    route_metric       = $(if ($_.RouteMetric) { [int]$_.RouteMetric } else { $null })
                    interface_metric   = $(if ($_.InterfaceMetric) { [int]$_.InterfaceMetric } else { $null })
                    policy_store       = [string]$_.PolicyStore
                    address_family     = [string]$_.AddressFamily
                }
            })
            wininet_proxy_enable   = $(if ($wininet) { [bool]$wininet.ProxyEnable } else { $null })
            wininet_proxy_server   = $(if ($wininet) { [string]$wininet.ProxyServer } else { $null })
            wininet_proxy_override = $(if ($wininet) { [string]$wininet.ProxyOverride } else { $null })
            winhttp_proxy          = $winhttp
            error                  = ''
        }
    } catch {
        return (& $empty $false $_.Exception.Message)
    }
}

function Test-GeneralConnectivity {
    # Observational only: attempt a TCP connect to a public endpoint through
    # the default route.  This is general connectivity, not proof of any
    # specific VPN's transport preservation.  Does not change settings/routes.
    $target = '1.1.1.1'
    $port = 443
    try {
        $sock = New-Object System.Net.Sockets.TcpClient
        $result = $sock.BeginConnect($target, $port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(3000, $false)
        if ($success) { $sock.EndConnect($result) }
        $sock.Close()
        return $true
    } catch {
        return $false
    }
}

function Compare-ForeignTunnelSnapshots {
    param($Pre, $Post)
    $diffs = @()

    # Fail closed on incomplete evidence.  Absence of a tunnel is a valid
    # empty snapshot, not missing evidence.
    $preOk  = ($null -ne $Pre)  -and ($Pre.collection_ok  -eq $true)
    $postOk = ($null -ne $Post) -and ($Post.collection_ok -eq $true)
    if (-not $preOk)  { $diffs += 'pre-snapshot collection failed or missing' }
    if (-not $postOk) { $diffs += 'post-snapshot collection failed or missing' }
    if (-not $preOk -or -not $postOk) { return $diffs }

    $prePresent  = [bool]$Pre.present
    $postPresent = [bool]$Post.present
    if (-not $prePresent -and -not $postPresent) {
        return $diffs   # no foreign tunnel before or after = preserved
    }
    if ($prePresent -and -not $postPresent) {
        $diffs += 'foreign tunnel disappeared during the test'
        return $diffs
    }
    if (-not $prePresent -and $postPresent) {
        $diffs += 'foreign tunnel appeared during the test'
        return $diffs
    }

    # Set of foreign tunnels (ifIndex|GUID) must not change.
    $preIds  = @($Pre.adapter_ids  | Sort-Object)
    $postIds = @($Post.adapter_ids | Sort-Object)
    if (($preIds -join ',') -ne ($postIds -join ',')) {
        $diffs += ("foreign tunnel set changed '{0}' -> '{1}'" -f ($preIds -join ','), ($postIds -join ','))
    }

    # Adapter identity and status
    if ([string]$Pre.adapter -ne [string]$Post.adapter) {
        $diffs += ("adapter name changed '{0}' -> '{1}'" -f $Pre.adapter, $Post.adapter)
    }
    if ([string]$Pre.interface_guid -ne [string]$Post.interface_guid) {
        $diffs += ("adapter GUID changed '{0}' -> '{1}'" -f $Pre.interface_guid, $Post.interface_guid)
    }
    if ([int]$Pre.interface_index -ne [int]$Post.interface_index) {
        $diffs += ("adapter ifIndex changed {0} -> {1}" -f $Pre.interface_index, $Post.interface_index)
    }
    if ([string]$Pre.status -ne [string]$Post.status) {
        $diffs += ("adapter status changed '{0}' -> '{1}'" -f $Pre.status, $Post.status)
    }
    if ([string]$Pre.link_speed -ne [string]$Post.link_speed) {
        $diffs += ("adapter link speed changed '{0}' -> '{1}'" -f $Pre.link_speed, $Post.link_speed)
    }
    if ([string]$Pre.ipv4 -ne [string]$Post.ipv4) {
        $diffs += ("adapter IPv4 changed '{0}' -> '{1}'" -f $Pre.ipv4, $Post.ipv4)
    }
    if ([int]$Pre.prefix_length -ne [int]$Post.prefix_length) {
        $diffs += ("adapter prefix length changed {0} -> {1}" -f $Pre.prefix_length, $Post.prefix_length)
    }
    # DNS
    $preDns = @($Pre.dns | Sort-Object)
    $postDns = @($Post.dns | Sort-Object)
    if ($preDns.Count -ne $postDns.Count -or
        ($preDns -join ',') -ne ($postDns -join ',')) {
        $diffs += ("DNS servers changed '{0}' -> '{1}'" -f ($Pre.dns -join ','), ($Post.dns -join ','))
    }
    # Routes: order-independent comparison; detect added, removed, changed
    $preRouteKeys = @{}
    foreach ($r in $Pre.routes) {
        $key = "$($r.destination_prefix)|$($r.next_hop)|$($r.address_family)"
        $preRouteKeys[$key] = $r
    }
    $postRouteKeys = @{}
    foreach ($r in $Post.routes) {
        $key = "$($r.destination_prefix)|$($r.next_hop)|$($r.address_family)"
        $postRouteKeys[$key] = $r
    }
    $preKeys = @($preRouteKeys.Keys | Sort-Object)
    $postKeys = @($postRouteKeys.Keys | Sort-Object)
    # Removed routes
    foreach ($k in $preKeys) {
        if (-not $postRouteKeys.ContainsKey($k)) {
            $diffs += ("route removed: $k")
        }
    }
    # Added routes
    foreach ($k in $postKeys) {
        if (-not $preRouteKeys.ContainsKey($k)) {
            $diffs += ("route added: $k")
        }
    }
    # Changed properties on common routes
    foreach ($k in $preKeys) {
        if ($postRouteKeys.ContainsKey($k)) {
            $pr = $preRouteKeys[$k]
            $po = $postRouteKeys[$k]
            if ([int]$pr.route_metric -ne [int]$po.route_metric) {
                $diffs += ("route[{0}] route_metric changed {1} -> {2}" -f $k, $pr.route_metric, $po.route_metric)
            }
            if ([int]$pr.interface_metric -ne [int]$po.interface_metric) {
                $diffs += ("route[{0}] interface_metric changed {1} -> {2}" -f $k, $pr.interface_metric, $po.interface_metric)
            }
            if ([string]$pr.policy_store -ne [string]$po.policy_store) {
                $diffs += ("route[{0}] policy_store changed '{1}' -> '{2}'" -f $k, $pr.policy_store, $po.policy_store)
            }
        }
    }
    # Proxy: WinINET
    if ([bool]$Pre.wininet_proxy_enable -ne [bool]$Post.wininet_proxy_enable) {
        $diffs += ("WinINET ProxyEnable changed '{0}' -> '{1}'" -f $Pre.wininet_proxy_enable, $Post.wininet_proxy_enable)
    }
    if ([string]$Pre.wininet_proxy_server -ne [string]$Post.wininet_proxy_server) {
        $diffs += ("WinINET ProxyServer changed '{0}' -> '{1}'" -f $Pre.wininet_proxy_server, $Post.wininet_proxy_server)
    }
    if ([string]$Pre.wininet_proxy_override -ne [string]$Post.wininet_proxy_override) {
        $diffs += ("WinINET ProxyOverride changed '{0}' -> '{1}'" -f $Pre.wininet_proxy_override, $Post.wininet_proxy_override)
    }
    # Proxy: WinHTTP
    if ([string]$Pre.winhttp_proxy -ne [string]$Post.winhttp_proxy) {
        $diffs += ("WinHTTP proxy changed: '{0}' -> '{1}'" -f $Pre.winhttp_proxy, $Post.winhttp_proxy)
    }
    return $diffs
}

try {
    # ---------------------------------------------------------------
    # 0. Pre-flight: no foreign tunnel may be the carrier.
    # ---------------------------------------------------------------
    $foreign = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and (
            $_.Name -match 'singbox|sing[-_ ]?tun|sing-tun' -or
            $_.InterfaceDescription -match 'singbox|sing-tun'
        )
    })
    if ($foreign.Count -gt 0) {
        $names = ($foreign | ForEach-Object { $_.Name }) -join ', '
        if ($AllowForeignTunnel) {
            Add-Check 'foreign_tunnel_allowed' $true (
                "coexisting tunnel allowed: {0}" -f $names)
            Write-Host ("[WARN] foreign_tunnel_allowed: Proceeding with coexisting tunnel(s): {0}" -f $names) -ForegroundColor Yellow
        } else {
            Add-Check 'foreign_tunnel_disabled' $false (
                "foreign tunnel adapter(s) Up: {0}; disable PattN/sing-box and rerun" -f $names)
            $report.error = 'foreign tunnel is Up; the test would only prove chaining'
            Save-Report
        Write-Host ("ERROR: " + $report.error) -ForegroundColor Red
            exit 1
        }
    } else {
        Add-Check 'foreign_tunnel_disabled' $true 'no sing-box / PattN tunnel adapter is Up'
    }

    # ---------------------------------------------------------------
    # 1. Pre-TUN physical layout (read-only).  A tunnel that is already Up
    #    would make both the baseline and the egress comparison meaningless.
    # ---------------------------------------------------------------
    $preStatus = Invoke-Api -Path '/api/status'
    if ($preStatus.tunnel -and $preStatus.tunnel.enabled) {
        Add-Check 'tun_initially_off' $false (
            "TUN is already {0}; switch to proxy mode first" -f $preStatus.tunnel.state)
        $report.error = 'TUN was already enabled before the test'
        Save-Report
        Write-Host ("ERROR: " + $report.error) -ForegroundColor Red
        exit 1
    }
    Add-Check 'tun_initially_off' $true 'TUN was not enabled before the test'

    $pre = Get-PhysicalLayout
    $report.pre_tun = $pre
    Add-Check 'pre_tun_physical_adapter' ([bool]$pre.ipv4 -and [bool]$pre.gateway) (
        "{0} (if{1}) {2} via gateway {3}" -f $pre.adapter, $pre.interface_index, $pre.ipv4, $pre.gateway)
    Add-Check 'pre_tun_adapter_is_not_virtual' (
        $pre.adapter -notmatch 'singbox|wintun|tailscale|vethernet|tun2proxy|perchvpn'
    ) $pre.adapter

    # ---------------------------------------------------------------
    # 1b. Foreign tunnel pre-test snapshot (read-only, before Perch startup).
    #     Fail closed only on incomplete evidence; a legitimate empty
    #     snapshot (no foreign tunnel) is expected in standalone mode.
    # ---------------------------------------------------------------
    $foreignPre = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex ([int]$pre.interface_index) -ExcludeAdapterName $TunAdapter
    $report.foreign_pre = $foreignPre
    Add-Check 'foreign_pre_snapshot' ([bool]$foreignPre.collection_ok) (
        $(if (-not $foreignPre.collection_ok) {
            'snapshot collection failed: {0}' -f $foreignPre.error
        } elseif ($foreignPre.present) {
            '{0} if{1} {2} status={3} IPv4={4} (count={5})' -f $foreignPre.adapter, $foreignPre.interface_index, $foreignPre.interface_guid, $foreignPre.status, $foreignPre.ipv4, $foreignPre.count
        } else {
            'no foreign tunnel present (legitimate empty snapshot)'
        }))
    Add-Check 'general_connectivity_pre' (Test-GeneralConnectivity) (
        $(if ($foreignPre.collection_ok) { 'TCP 1.1.1.1:443 general connectivity (not VPN transport proof)' } else { 'skipped: snapshot collection failed' }))

    if (-not $foreignPre.collection_ok) {
        $report.error = 'could not obtain foreign tunnel pre-test snapshot: ' + $foreignPre.error
        Save-Report
        Write-Host ("ERROR: " + $report.error) -ForegroundColor Red
        exit 1
    }
    if (-not $foreignPre.present) {
        Add-Check 'foreign_pre_absent' $true 'no foreign tunnel detected; nothing to preserve'
        Write-Host '[INFO] no foreign tunnel detected; proceeding with a standalone test' -ForegroundColor Cyan
    } elseif ($AllowForeignTunnel) {
        Write-Host ('[WARN] coexistence snapshot captured: {0} foreign tunnel(s)' -f $foreignPre.count) -ForegroundColor Yellow
    }

    # ---------------------------------------------------------------
    # 2. Ask the app to enter TUN mode (this triggers UAC).
    # ---------------------------------------------------------------
    $status = Invoke-Api -Path '/api/status'
    Write-Host ("PerchVPN is running: status={0}" -f $status.status)
    $modeResponse = Invoke-Api -Method Post -Path '/api/mode' -TimeoutSec ($TimeoutSeconds + 120) `
        -Body @{ mode = 'tun'; apply = $true }
    Add-Check 'mode_switch_accepted' ([bool]$modeResponse.success) (
        "mode={0} detail={1}" -f $modeResponse.mode, $modeResponse.detail)

    # ---------------------------------------------------------------
    # 3. Wait for the elevated helper to settle.
    # ---------------------------------------------------------------
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $tunnel = $null
    $lastDetail = ''
    while ((Get-Date) -lt $deadline) {
        try {
            $status = Invoke-Api -Path '/api/status'
            $tunnel = $status.tunnel
            $phase = [string]$tunnel.helper_phase
            $state = [string]$tunnel.state
            $lastDetail = [string]$tunnel.detail
            if ($phase -eq 'ready' -or $state -eq 'traffic_verified') { break }
            if ($phase -eq 'failed' -or $phase -eq 'recovery_required' -or
                $state -eq 'failed' -or $state -eq 'recovery_required') { break }
        } catch {
            $lastDetail = $_.Exception.Message
        }
        # Observational only: general connectivity while Perch tunnel is active.
        $script:generalConnectivityDuring = Test-GeneralConnectivity
        Start-Sleep -Seconds 5
    }
    $report.status = $tunnel
    # Re-test after the helper is settled; the in-loop sample can land while
    # split routes are still being installed and understate steady state.
    $script:generalConnectivityDuring = Test-GeneralConnectivity
    if (-not $script:generalConnectivityDuring) {
        Start-Sleep -Seconds 5
        $script:generalConnectivityDuring = Test-GeneralConnectivity
    }
    if (-not $script:generalConnectivityDuring) {
        Start-Sleep -Seconds 5
        $script:generalConnectivityDuring = Test-GeneralConnectivity
    }
    Add-Check 'general_connectivity_during' ([bool]$script:generalConnectivityDuring) (
        $(if ($script:generalConnectivityDuring) { 'TCP 1.1.1.1:443 general connectivity with Perch TUN active' } else { 'TCP 1.1.1.1:443 not reachable during TUN' }))
    $phase = [string]$tunnel.helper_phase
    Add-Check 'helper_reached_ready' ($phase -eq 'ready') (
        "phase={0} state={1} detail={2}" -f $phase, $tunnel.state, $lastDetail)
    if ($phase -ne 'ready') {
        $report.error = 'elevated TUN helper never reached ready: ' + $lastDetail
        Save-Report
        Write-Host ("ERROR: " + $report.error) -ForegroundColor Red
        if ($RestoreProxy) {
            $null = Invoke-Api -Method Post -Path '/api/mode' -Body @{ mode = 'proxy'; apply = $true }
        }
        exit 1
    }

    # ---------------------------------------------------------------
    # 4. Windows-side evidence.
    # ---------------------------------------------------------------
    $egressDeadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $egressDeadline) {
        if ($tunnel.system_egress -and $tunnel.system_egress.ipv4 -and
            $tunnel.system_egress.ipv4.ok) { break }
        Start-Sleep -Seconds 2
        try {
            $status = Invoke-Api -Path '/api/status'
            $tunnel = $status.tunnel
        } catch {
            break
        }
    }
    $report.status = $tunnel

    $adapter = Get-NetAdapter -Name $TunAdapter -ErrorAction SilentlyContinue |
        Select-Object -First 1
    Add-Check 'tun_adapter_up' ([bool]$adapter -and $adapter.Status -eq 'Up') (
        $(if ($adapter) { "{0} status={1}" -f $adapter.Name, $adapter.Status } else { 'adapter missing' }))

    $routes = @(Get-NetRoute -InterfaceAlias $TunAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue)
    foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1')) {
        $match = $routes | Where-Object { $_.DestinationPrefix -eq $prefix } | Select-Object -First 1
        Add-Check ("split_route_" + $prefix.Replace('/', '_')) ([bool]$match) (
            $(if ($match) { "{0} metric={1}" -f $prefix, $match.RouteMetric } else { 'missing' }))
        if ($match) {
            Add-Check ("split_route_metric_" + $prefix.Replace('/', '_')) (
                [int]$match.RouteMetric -eq 1) ("RouteMetric={0} (expected 1)" -f $match.RouteMetric)
        }
    }

    $iface = Get-NetIPInterface -InterfaceAlias $TunAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue
    Add-Check 'tun_interface_metric' ([bool]$iface -and [int]$iface.InterfaceMetric -eq 1) (
        $(if ($iface) { "InterfaceMetric={0} (expected 1)" -f $iface.InterfaceMetric } else { 'missing' }))

    $tunDns = @(Get-DnsClientServerAddress -InterfaceAlias $TunAdapter -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses)
    $tunDns6 = @(Get-DnsClientServerAddress -InterfaceAlias $TunAdapter -AddressFamily IPv6 `
            -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses)
    Add-Check 'tun_dns_configured' ($tunDns.Count -gt 0 -and
        -not ($tunDns6 | Where-Object { $_ -like 'fec0:*' })) (
        "IPv4={0} IPv6={1}" -f ($tunDns -join ','), ($tunDns6 -join ','))

    # Journaled upstream pins: identity, carrier and next hop.
    if (Test-Path $journalPath) {
        try {
            $journal = Get-Content -Raw -Path $journalPath | ConvertFrom-Json
        } catch {
            $journal = $null
        }
        $pins = @()
        if ($journal -and $journal.pinned_routes) { $pins = @($journal.pinned_routes) }
        Add-Check 'upstream_pins_present' ($pins.Count -gt 0) ("journaled pins: {0}" -f $pins.Count)
        $pinFailures = @()
        foreach ($pin in $pins) {
            $prefix = [string]$pin.destination_prefix
            $index = [int]$pin.interface_index
            $expectedHop = [string]$pin.next_hop
            if ($index -ne [int]$pre.interface_index) {
                $pinFailures += ("{0} on if{1} (expected physical if{2})" -f $prefix, $index, $pre.interface_index)
                continue
            }
            $family = $(if ($prefix -match ':') { 'IPv6' } else { 'IPv4' })
            $found = Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $index `
                -AddressFamily $family -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $found) {
                $pinFailures += ("{0} missing on if{1}" -f $prefix, $index)
                continue
            }
            if ([string]$found.NextHop -ne $expectedHop) {
                $pinFailures += ("{0} next hop {1} (expected {2})" -f $prefix, $found.NextHop, $expectedHop)
            }
            if ([int]$found.RouteMetric -ne 1) {
                $pinFailures += ("{0} metric {1} (expected 1)" -f $prefix, $found.RouteMetric)
            }
        }
        Add-Check 'upstream_pins_use_physical_gateway' ($pinFailures.Count -eq 0) (
            $(if ($pinFailures.Count -eq 0) {
                "all {0} pins on if{1} via {2}" -f $pins.Count, $pre.interface_index, $pre.gateway
            } else {
                $pinFailures -join '; '
            }))
    } else {
        Add-Check 'upstream_pins_present' $false ("journal not found: {0}" -f $journalPath)
    }

    # Egress proof from the helper's own system probe (no proxy, OS route).
    $egress = $tunnel.system_egress
    $egressIp = ''
    if ($egress -and $egress.ipv4 -and $egress.ipv4.ok) { $egressIp = [string]$egress.ipv4.ip }
    if (-not $egressIp -and (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
        try {
            $egressIp = (& curl.exe -4 -s --max-time 10 https://api.ipify.org).Trim()
        } catch {
            $egressIp = ''
        }
    }
    $report.post_tun = [ordered]@{
        egress_ipv4   = $egressIp
        egress        = $egress
        tun_dns       = $tunDns
        tun_dns_v6    = $tunDns6
        interface_metric = $(if ($iface) { $iface.InterfaceMetric } else { $null })
        physical      = $tunnel.physical
    }
    Add-Check 'egress_public_ip' ([bool]$egressIp) ("egress IPv4={0}" -f $egressIp)
    $privateEgress = $egressIp -match '^10\.' -or $egressIp -match '^192\.168\.' -or
        $egressIp -match '^172\.(1[6-9]|2[0-9]|3[01])\.'
    Add-Check 'egress_differs_from_lan_ip' (
        [bool]$egressIp -and $egressIp -ne [string]$pre.ipv4 -and -not $privateEgress
    ) ("egress {0} vs physical LAN {1}" -f $egressIp, $pre.ipv4)
    Add-Check 'helpers_physical_underlay' (
        $tunnel.physical -and [int]$tunnel.physical.interface_index -eq [int]$pre.interface_index -and
        [string]$tunnel.physical.gateway -eq [string]$pre.gateway
    ) (
        $(if ($tunnel.physical) {
            "helper pinned to {0} (if{1}) via {2}" -f $tunnel.physical.adapter,
                $tunnel.physical.interface_index, $tunnel.physical.gateway
        } else { 'helper did not publish a physical underlay' }))

    # ---------------------------------------------------------------
    # 5b. Foreign tunnel post-test snapshot (read-only, after Perch teardown).
    #     Compare against pre-test snapshot; fail on any property diff.
    # ---------------------------------------------------------------
    $foreignPost = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex ([int]$pre.interface_index) -ExcludeAdapterName $TunAdapter
    $report.foreign_post = $foreignPost
    $foreignDiffs = Compare-ForeignTunnelSnapshots $foreignPre $foreignPost
    Add-Check 'foreign_post_snapshot' ([bool]$foreignPost.collection_ok) (
        $(if (-not $foreignPost.collection_ok) {
            'snapshot collection failed: {0}' -f $foreignPost.error
        } elseif ($foreignPost.present) {
            '{0} if{1} {2} status={3} IPv4={4} (count={5})' -f $foreignPost.adapter, $foreignPost.interface_index, $foreignPost.interface_guid, $foreignPost.status, $foreignPost.ipv4, $foreignPost.count
        } else {
            'no foreign tunnel present after teardown (legitimate empty snapshot)'
        }))
    Add-Check 'foreign_state_preserved' ($foreignDiffs.Count -eq 0) (
        $(if ($foreignDiffs.Count -eq 0) {
            'Foreign tunnel state unchanged across Perch TUN lifecycle'
        } else {
            $foreignDiffs -join '; '
        }))

    $failed = @($checks | Where-Object { -not $_.ok })
    $report.result = $(if ($failed.Count -eq 0) { 'pass' } else { 'fail' })
    $report.error = $(if ($failed.Count -eq 0) { '' } else { ($failed | ForEach-Object { $_.name }) -join ', ' })
    Save-Report

    if ($RestoreProxy) {
        Write-Host 'Restoring proxy mode...'
        $null = Invoke-Api -Method Post -Path '/api/mode' -TimeoutSec ($TimeoutSeconds + 120) `
            -Body @{ mode = 'proxy'; apply = $true }
    }

    if ($failed.Count -eq 0) {
        $scope = if ($AllowForeignTunnel -and $foreignPre.present) {
            'with coexisting tunnel(s)'
        } else {
            'standalone over the physical adapter'
        }
        Write-Host ('RESULT: PASS - TUN runs {0}.' -f $scope)
        exit 0
    }
    Write-Host ('RESULT: FAIL - {0}' -f $report.error)
    exit 1
} catch {
    $report.error = $_.Exception.Message
    Add-Check 'verification_completed' $false $report.error
    Save-Report
    if ($RestoreProxy) {
        try {
            $null = Invoke-Api -Method Post -Path '/api/mode' -TimeoutSec ($TimeoutSeconds + 120) `
                -Body @{ mode = 'proxy'; apply = $true }
        } catch { }
    }
        Write-Host ("ERROR: " + $report.error) -ForegroundColor Red
    exit 1
}
