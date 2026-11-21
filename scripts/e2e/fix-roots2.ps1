$ErrorActionPreference = 'Continue'
certutil -generateSSTFromWU C:\PerchGuest\roots.sst
'TST_EXIST=' + (Test-Path C:\PerchGuest\roots.sst)
'TEST_HTTP=' + ((Invoke-WebRequest -UseBasicParsing -Uri 'https://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authroot.stl' -TimeoutSec 20).StatusCode)
