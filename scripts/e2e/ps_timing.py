import subprocess
import time

script = (
    "$ErrorActionPreference='Stop';"
    "$n='perchvpn-tun';"
    "try {"
    "  $a = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {"
    "    ($null -ne $_.Name -and $_.Name -eq $n)"
    "  };"
    "  if ($a) { exit 1 } else { exit 0 }"
    "} catch { exit 2 }"
)
for i in range(3):
    t0 = time.monotonic()
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, timeout=30.0, check=False,
    )
    print("probe%d rc=%d ms=%.0f" % (i, completed.returncode, (time.monotonic() - t0) * 1000))
