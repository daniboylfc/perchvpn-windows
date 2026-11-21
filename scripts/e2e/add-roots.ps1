$ErrorActionPreference = 'Continue'
certutil -addstore -f Root C:\PerchGuest\authroot.stl | Select-String -Pattern 'added|Error|CertUtils' | Select-Object -First 4
$g = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*GlobalSign Root E46*' }
if ($g) { 'ROOT_E46=PRESENT' } else { 'ROOT_E46=ABSENT' }
'TOTAL_ROOTS=' + (Get-ChildItem Cert:\LocalMachine\Root).Count
