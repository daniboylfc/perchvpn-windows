$ErrorActionPreference = 'Continue'
certutil -addstore -f Root C:\PerchGuest\GlobalSign_Root_E46.crt | Select-String -Pattern 'added|Error' | Select-Object -First 2
certutil -addstore -f Root C:\PerchGuest\Sectigo_Public_Server_Authentication_Root_E46.crt | Select-String -Pattern 'added|Error' | Select-Object -First 2
$g = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*GlobalSign Root E46*' }
$s = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*Sectigo Public Server Authentication Root E46*' }
'GS_E46=' + $(if ($g) {'PRESENT'} else {'ABSENT'})
'SECTIGO_E46=' + $(if ($s) {'PRESENT'} else {'ABSENT'})
'TOTAL_ROOTS=' + (Get-ChildItem Cert:\LocalMachine\Root).Count
