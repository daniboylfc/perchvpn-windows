$ErrorActionPreference = 'Continue'
$authDir = Join-Path $env:APPDATA 'PerchVPN'
Remove-Item -Force -ErrorAction SilentlyContinue "$authDir\tokens.json"
'TOKENS_DELETED'
$hits = @()
Get-ChildItem $authDir -File -ErrorAction SilentlyContinue | ForEach-Object {
    $text = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($text -match 'access_token|refresh_token|session_token|Bearer [A-Za-z0-9_-]{20,}') {
        $hits += $_.Name
    }
}
if ($hits) { 'AUTH_LEAK_IN: ' + ($hits -join ',') } else { 'AUTH_SCAN_CLEAN' }
'FILES_LEFT: ' + ((Get-ChildItem $authDir -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ',')
# hygiene: remove staged probe artifacts from C:\PerchGuest
@('cfginfo.py','tls_probe.py','egress_probe.py','ps_timing.py','install_socksio.py','socksio.whl','authroot.stl','roots.sst','GlobalSign_Root_E46.crt','Sectigo_Public_Server_Authentication_Root_E46.crt','add-roots.ps1','add-roots2.ps1','fix-roots.ps1','fix-roots2.ps1') | ForEach-Object {
    Remove-Item -Force -ErrorAction SilentlyContinue ("C:\PerchGuest\" + $_)
}
'C:\PerchGuest cleanup done'
'GHOSTS: ' + @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -like 'SWD\WINTUN*' }).Count
'ROUTES: ' + ((Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceIndex }) -join ',')
