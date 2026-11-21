# ----------------------------------------------------
# Minimal PyInstaller candidate build for Perch VPN Windows
# ----------------------------------------------------
# Builds a *candidate* onedir bundle in isolated directories under the native
# Windows venv (%LOCALAPPDATA%\PerchVPN-Windows-venv). It does NOT modify
# any existing dist\PerchVPN.exe.
#
# Requirements on the Windows side (one-time):
#   py -m venv "$env:LOCALAPPDATA\PerchVPN-Windows-venv"
#   & "$env:LOCALAPPDATA\PerchVPN-Windows-venv\Scripts\pip.exe" install pyinstaller
#   & "$env:LOCALAPPDATA\PerchVPN-Windows-venv\Scripts\pip.exe" install -e \\wsl.localhost\<distro>\home\<user>\foxyvpn-windows
#
# The web UI is bundled from src\perchvpn_windows\web (package-relative).
# sing-box.exe and wintun.dll are staged beside the generated EXE so
# the onedir bundle is self-contained and requires no runtime extraction
# into %TEMP%\_MEI* (which caused startup latency and file-lock cleanup
# failures with --onefile).
# ----------------------------------------------------

param(
    [string]$Project = "",
    [string]$Venv = "",
    [string]$DistPath = "",
    [string]$WorkPath = "",
    [string]$SpecPath = "",
    [switch]$NoUpx
)

# 1. Set the Windows-accessible project root and venv path
$project = if ($Project) { $Project } else { Split-Path $PSScriptRoot -Parent }
$venv   = if ($Venv) { $Venv } else { Join-Path $env:LOCALAPPDATA 'PerchVPN-Windows-venv' }

# 2. Verify required directories exist before proceeding
if (-not (Test-Path $project)) {
    Write-Error "Project not found at $project"
    return
}
$srcPath = Join-Path $project 'src'
if (-not (Test-Path $srcPath)) {
    Write-Error "src directory not found at $srcPath"
    return
}
$webPath = Join-Path $srcPath 'perchvpn_windows\web'
if (-not (Test-Path $webPath)) {
    Write-Error "web assets not found at $webPath"
    return
}
$iconPath = Join-Path $project 'assets\perch.ico'
if (-not (Test-Path $iconPath)) {
    Write-Error "Application icon not found: $iconPath"
    return
}
$sidecarPath = Join-Path $project 'bin'
$sidecars = @('sing-box.exe', 'wintun.dll')
foreach ($name in $sidecars) {
    $candidate = Join-Path $sidecarPath $name
    if (-not (Test-Path $candidate)) {
        Write-Error "Required sidecar not found: $candidate"
        return
    }
}

# 3. Resolve the native Windows PyInstaller executable
$pyinstaller = Join-Path $venv 'Scripts\pyinstaller.exe'
if (-not (Test-Path $pyinstaller)) {
    Write-Error "PyInstaller executable not found at $pyinstaller"
    return
}

# 3b. Guard: uvicorn needs the websockets package to serve /ws/* routes.
# Without it the bundle builds clean but every websocket endpoint 404s at
# runtime (the UI's live /ws/status flip channel dies silently).
& (Join-Path $venv 'Scripts\pip.exe') show websockets 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build venv is missing the 'websockets' package (uvicorn WebSocket support). Install it: & `"$venv\Scripts\pip.exe`" install websockets"
    return
}

# 4. Candidate output directories (isolated from any existing dist\)
$distCandidate  = if ($DistPath) { $DistPath } else { Join-Path $venv 'dist-candidate' }
$buildCandidate = if ($WorkPath) { $WorkPath } else { Join-Path $venv 'build-candidate' }
$specCandidate  = if ($SpecPath) { $SpecPath } else { Join-Path $venv 'spec-candidate' }

# 5. Build the onedir candidate bundle
$pyinstallerArgs = @(
    '--noconfirm',
    '--onedir',
    '--windowed',
    '--clean',
    '--name', 'PerchVPN',
    '--distpath', $distCandidate,
    '--workpath', $buildCandidate,
    '--specpath', $specCandidate,
    '--paths', $srcPath,
    '--collect-all', 'curl_cffi',
    '--icon', $iconPath,
    '--add-data', "$webPath;web"
)
if ($NoUpx) {
    $pyinstallerArgs += '--noupx'
}
$pyinstallerArgs += (Join-Path $project 'src\perchvpn_windows\main.py')
& $pyinstaller @pyinstallerArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
    return
}

# 6. Stage runtime sidecars beside the generated EXE (bundle root). Also
#    refresh the legacy dist-candidate root so an existing config pointing
#    at that path keeps working.
$bundleDir = Join-Path $distCandidate 'PerchVPN'
$bundleExe = Join-Path $bundleDir 'PerchVPN.exe'
if (-not (Test-Path $bundleExe)) {
    Write-Error "Onedir EXE not found at $bundleExe"
    return
}
foreach ($targetDir in @($bundleDir, $distCandidate)) {
    foreach ($name in $sidecars) {
        Copy-Item -LiteralPath (Join-Path $sidecarPath $name) -Destination (Join-Path $targetDir $name) -Force
    }
}

$artifactSize = (Get-Item -LiteralPath $bundleExe).Length
Write-Output "Candidate bundle: $bundleDir"
Write-Output ("Candidate EXE: {0} ({1:N0} bytes)" -f $bundleExe, $artifactSize)
Write-Output "Bundled sidecars: $($sidecars -join ', ')"

# 7. (Optional) Launch the candidate to verify the GUI
# & $bundleExe
