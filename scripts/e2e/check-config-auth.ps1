$c = Get-Content (Join-Path $env:APPDATA 'PerchVPN\config.json') -Raw
foreach ($pat in @('access_token', 'refresh_token', 'session_token')) {
    if ($c -match $pat) {
        $idx = $c.IndexOf($pat)
        $start = [Math]::Max(0, $idx - 30)
        $len = [Math]::Min(90, $c.Length - $start)
        $snippet = $c.Substring($start, $len) -replace '[A-Za-z0-9_-]{16,}', '<REDACTED>'
        'MATCH ' + $pat + ' ctx: ' + $snippet
    }
}
if ($c -match 'Bearer ') { 'BEARER_WORD_FOUND' } else { 'NO_BEARER' }
