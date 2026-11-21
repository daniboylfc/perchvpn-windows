#Requires -Version 5.1
<#
.SYNOPSIS
    Targeted synthetic tests for the foreign-tunnel snapshot logic in
    scripts/verify-normal-wifi-tun.ps1.

.DESCRIPTION
    Loads only Get-ForeignTunnelSnapshot and Compare-ForeignTunnelSnapshots
    from the acceptance script (via the PowerShell AST, so the script's
    top-level workflow never runs), shadows the Net* cmdlets with in-memory
    mocks, and asserts the absence / presence / failure distinctions plus
    fail-closed comparison behaviour.

    Covers: no tunnel, one tunnel, multiple tunnels, collection failure,
    honest empty snapshots, state change, and fail-closed incomplete
    evidence.
#>
[CmdletBinding()]
param(
    [string]$ScriptPath = $null
)

$ErrorActionPreference = 'Stop'

if (-not $ScriptPath) {
    $selfDir = if ($PSScriptRoot) {
        $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        (Get-Location).Path
    }
    $ScriptPath = Join-Path (Split-Path -Parent $selfDir) 'scripts/verify-normal-wifi-tun.ps1'
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "acceptance script not found: $ScriptPath"
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path -LiteralPath $ScriptPath).ProviderPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw ("parse errors in {0}: {1}" -f $ScriptPath, (($parseErrors | ForEach-Object { $_.Message }) -join '; '))
}

foreach ($name in @('Get-ForeignTunnelSnapshot', 'Compare-ForeignTunnelSnapshots')) {
    $fn = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true) | Select-Object -First 1
    if (-not $fn) { throw "function $name not found in $ScriptPath" }
    Invoke-Expression $fn.Extent.Text
}

$script:Passed = 0
$script:Failed = 0

function Check {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        Write-Host ("PASS  {0}" -f $Name) -ForegroundColor Green
        $script:Passed++
    } else {
        Write-Host ("FAIL  {0}  ({1})" -f $Name, $Detail) -ForegroundColor Red
        $script:Failed++
    }
}

function New-MockAdapter {
    param([string]$Name, [int]$Index, [string]$Guid, [string]$Status = 'Up', [string]$Description = '')
    if (-not $Description) { $Description = $Name }
    [pscustomobject]@{
        Name                 = $Name
        InterfaceIndex       = $Index
        InterfaceGuid        = $Guid
        Status               = $Status
        InterfaceDescription = $Description
        LinkSpeed            = '1 Gbps'
    }
}

function Reset-MockState {
    $script:MockFail         = $false
    $script:MockAdapters     = @(New-MockAdapter 'Wi-Fi' 12 '{WIFI-GUID}' 'Up' 'Intel Wi-Fi 6')
    $script:MockDefaultRoute = @([pscustomobject]@{
            InterfaceIndex    = 12
            NextHop           = '192.168.1.1'
            InterfaceAlias    = 'Wi-Fi'
            DestinationPrefix = '0.0.0.0/0'
            AddressFamily     = 'IPv4'
        })
    $script:MockRoutesByIndex  = @{}
    $script:MockAddressByIndex = @{}
    $script:MockDnsByIndex     = @{}
}

function Add-MockAdapterState {
    param(
        [int]$Index,
        [string]$Ipv4,
        [int]$PrefixLength = 24,
        [string[]]$Dns = @('1.1.1.1'),
        [object[]]$Routes = @()
    )
    $script:MockAddressByIndex[$Index] = [pscustomobject]@{
        IPAddress    = $Ipv4
        PrefixLength = $PrefixLength
    }
    $script:MockDnsByIndex["$Index|IPv4"] = @($Dns)
    $script:MockDnsByIndex["$Index|IPv6"] = @()
    $script:MockRoutesByIndex[$Index]     = @($Routes)
}

function New-MockRoute {
    param([string]$Destination, [string]$NextHop, [string]$Family = 'IPv4', [int]$Metric = 1)
    [pscustomobject]@{
        DestinationPrefix = $Destination
        NextHop           = $NextHop
        RouteMetric       = $Metric
        InterfaceMetric   = 1
        PolicyStore       = 'ActiveStore'
        AddressFamily     = $Family
    }
}

# --- cmdlet shadows (functions win over the real cmdlets) -----------------
function Get-NetAdapter {
    [CmdletBinding()]
    param([string]$Name)
    if ($script:MockFail) { throw 'synthetic adapter enumeration failure' }
    if ($Name) { return @($script:MockAdapters | Where-Object { $_.Name -eq $Name }) }
    return @($script:MockAdapters)
}

function Get-NetRoute {
    [CmdletBinding()]
    param([string]$DestinationPrefix, [string]$AddressFamily, [int]$InterfaceIndex)
    if ($script:MockFail) { throw 'synthetic route enumeration failure' }
    if ($DestinationPrefix) { return @($script:MockDefaultRoute) }
    if ($PSBoundParameters.ContainsKey('InterfaceIndex')) {
        $value = $script:MockRoutesByIndex[$InterfaceIndex]
        if ($null -eq $value) { return @() }
        return @($value)
    }
    return @()
}

function Get-NetIPAddress {
    [CmdletBinding()]
    param([int]$InterfaceIndex, [string]$AddressFamily)
    if ($script:MockFail) { throw 'synthetic address enumeration failure' }
    $value = $script:MockAddressByIndex[$InterfaceIndex]
    if ($null -eq $value) { return @() }
    return @($value)
}

function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param([int]$InterfaceIndex, [string]$AddressFamily)
    if ($script:MockFail) { throw 'synthetic DNS enumeration failure' }
    $value = $script:MockDnsByIndex["$InterfaceIndex|$AddressFamily"]
    if ($null -eq $value) { return @() }
    return @($value | ForEach-Object { [pscustomobject]@{ ServerAddresses = @($_) } })
}

function Get-ItemProperty {
    [CmdletBinding()]
    param([string]$Path)
    [pscustomobject]@{ ProxyEnable = 0; ProxyServer = ''; ProxyOverride = '' }
}

# =========================================================================
# 4.1 No foreign tunnel -> honest empty snapshot, not a failure.
# =========================================================================
Reset-MockState
$snap = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
Check 'no-foreign: collection_ok' ($snap.collection_ok -eq $true) $snap.error
Check 'no-foreign: present=false' ($snap.present -eq $false) ($snap | Out-String)
Check 'no-foreign: count=0' ($snap.count -eq 0) ([string]$snap.count)
Check 'no-foreign: not null' ($null -ne $snap) 'snapshot was null'

# =========================================================================
# 4.2 One foreign tunnel -> captured with identity and status.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
$snap = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
Check 'one-foreign: collection_ok' ($snap.collection_ok -eq $true) $snap.error
Check 'one-foreign: present=true' ($snap.present -eq $true) ($snap | Out-String)
Check 'one-foreign: count=1' ($snap.count -eq 1) ([string]$snap.count)
Check 'one-foreign: adapter name' ($snap.adapter -eq 'singbox_tun') ([string]$snap.adapter)
Check 'one-foreign: ifIndex' ($snap.interface_index -eq 65) ([string]$snap.interface_index)
Check 'one-foreign: guid' ($snap.interface_guid -eq '{SING-GUID}') ([string]$snap.interface_guid)

# =========================================================================
# 4.3 Multiple foreign tunnels -> deterministic set, sorted by ifIndex.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
$script:MockAdapters += New-MockAdapter 'wg0' 70 '{WG-GUID}' 'Up' 'WireGuard Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
Add-MockAdapterState -Index 70 -Ipv4 '10.9.0.2' -PrefixLength 24 `
    -Routes @((New-MockRoute '10.9.0.0/24' '0.0.0.0'))
$snap = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
Check 'multi-foreign: collection_ok' ($snap.collection_ok -eq $true) $snap.error
Check 'multi-foreign: count=2' ($snap.count -eq 2) ([string]$snap.count)
Check 'multi-foreign: deterministic primary' ($snap.adapter -eq 'singbox_tun') ([string]$snap.adapter)
Check 'multi-foreign: both ids' (($snap.adapter_ids -join ',') -eq '65|{SING-GUID},70|{WG-GUID}') ($snap.adapter_ids -join ',')

# =========================================================================
# 4.3b The adapter under test must never be classified as foreign.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
$script:MockAdapters += New-MockAdapter 'PerchVPN' 72 '{PERCH-GUID}' 'Up' 'PerchVPN Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
Add-MockAdapterState -Index 72 -Ipv4 '10.0.0.33' -PrefixLength 24 `
    -Routes @((New-MockRoute '0.0.0.0/1' '0.0.0.0'))
$snap = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12 -ExcludeAdapterName 'PerchVPN'
Check 'exclude-own: collection_ok' ($snap.collection_ok -eq $true) $snap.error
Check 'exclude-own: count=1' ($snap.count -eq 1) ([string]$snap.count)
Check 'exclude-own: own adapter absent' (($snap.adapter_ids -join ',') -eq '65|{SING-GUID}') ($snap.adapter_ids -join ',')

# =========================================================================
# 4.4 Collection failure -> fail-closed evidence flag.
# =========================================================================
Reset-MockState
$script:MockFail = $true
$snap = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
Check 'failure: collection_ok=false' ($snap.collection_ok -eq $false) ($snap | Out-String)
Check 'failure: present=false' ($snap.present -eq $false) ($snap | Out-String)
Check 'failure: error recorded' (-not [string]::IsNullOrEmpty([string]$snap.error)) ([string]$snap.error)

# =========================================================================
# 4.5 Compare: no tunnel before or after -> preserved.
# =========================================================================
Reset-MockState
$pre  = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$post = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$diffs = Compare-ForeignTunnelSnapshots $pre $post
Check 'compare: absent-both preserved' ($diffs.Count -eq 0) ($diffs -join '; ')

# =========================================================================
# 4.6 Compare: unchanged single tunnel -> preserved.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
$pre  = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$post = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$diffs = Compare-ForeignTunnelSnapshots $pre $post
Check 'compare: unchanged preserved' ($diffs.Count -eq 0) ($diffs -join '; ')

# =========================================================================
# 4.7 Compare: foreign tunnel state changes during the test -> diff.
# =========================================================================
$pre = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$script:MockRoutesByIndex[65] += New-MockRoute '10.0.0.0/8' '0.0.0.0'
$post = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$diffs = Compare-ForeignTunnelSnapshots $pre $post
Check 'compare: change detected' ($diffs.Count -gt 0) ($diffs -join '; ')
Check 'compare: change is a route' (($diffs -join '; ') -match 'route (added|removed)') ($diffs -join '; ')

# =========================================================================
# 4.8 Compare: tunnel disappears during the test -> diff.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
$pre = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$script:MockAdapters = @($script:MockAdapters | Where-Object { $_.Name -ne 'singbox_tun' })
$post = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$diffs = Compare-ForeignTunnelSnapshots $pre $post
Check 'compare: disappeared flagged' (($diffs -join '; ') -match 'disappeared') ($diffs -join '; ')

# =========================================================================
# 4.9 Compare: incomplete post evidence -> fail closed, never pass.
# =========================================================================
Reset-MockState
$script:MockAdapters += New-MockAdapter 'singbox_tun' 65 '{SING-GUID}' 'Up' 'sing-tun Tunnel'
Add-MockAdapterState -Index 65 -Ipv4 '172.18.0.2' -PrefixLength 30 `
    -Routes @((New-MockRoute '0.0.0.0/0' '0.0.0.0'))
$pre = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$script:MockFail = $true
$post = Get-ForeignTunnelSnapshot -PhysicalInterfaceIndex 12
$diffs = Compare-ForeignTunnelSnapshots $pre $post
Check 'compare: incomplete fails closed' (($diffs -join '; ') -match 'post-snapshot collection failed') ($diffs -join '; ')

# =========================================================================
# 4.10 Caller invariant: no truthiness abort on the pre-snapshot.
# =========================================================================
$raw = Get-Content -LiteralPath $ScriptPath -Raw
Check 'caller: pre fails only on collection_ok' `
    ($raw.Contains('if (-not $foreignPre.collection_ok) {')) 'missing collection_ok abort'
Check 'caller: no null/truthiness abort' `
    (-not $raw.Contains('if (-not $foreignPre) {')) 'legacy truthiness abort still present'

# =========================================================================
$total = $script:Passed + $script:Failed
Write-Host ''
Write-Host ("{0}/{1} checks passed" -f $script:Passed, $total) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })
if ($script:Failed -gt 0) { exit 1 }
exit 0
