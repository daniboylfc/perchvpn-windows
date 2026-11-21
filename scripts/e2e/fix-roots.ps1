$ErrorActionPreference = 'Continue'
certutil -generateSSTFromWU C:\PerchGuest\roots.sst | Out-Null
if (Test-Path C:\PerchGuest\roots.sst) {
    certutil -addstore -f Root C:\PerchGuest\roots.sst | Select-String -Pattern 'added|Error' | Select-Object -First 3
} else {
    'SST_MISSING'
}
$root = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*GlobalSign Root E46*' }
if ($root) { 'ROOT_E46_PRESENT' } else { 'ROOT_E46_ABSENT' }
'TOTAL_ROOTS=' + (Get-ChildItem Cert:\LocalMachine\Root).Count
