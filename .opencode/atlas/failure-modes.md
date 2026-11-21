# Atlas: Failure-Mode Gotchas

Hard-won operational lessons. Add new entries as they are discovered; do not delete without recording why.

## Host / WSL boundary
- This repo is checked out in WSL2 but the product targets Windows 11. Tests must not assume Windows-only behavior unless marked; platform-specific code lives behind `perchvpn_windows/platform.py`.
- Anything requiring elevation (wintun adapter install, service control, UAC) cannot run non-interactively from WSL — route through elevated PowerShell on the host per `~/.config/opencode/memory/human.md`.
- Never assume operational success: verify with pytest, process checks, or SHA-256 of build candidates.

## Network namespace isolation
- Hyper-V, WSL, Tailscale, wintun, and sing-box each own virtual interfaces. Diagnostic commands must target the specific interface, never "the default route" blindly.
- Never stop/disconnect a non-`PerchVPN` Wintun adapter or the host's active tunnel; blanket kills (`taskkill /IM sing-box.exe`) are forbidden.
- Fastly MASQUE upstream edges refuse `CONNECT` to non-443 ports (observed: `1.1.1.1:53` → HTTP 502, 2026-11-13). Any sing-box DNS/transport routed `detour: perch-socks` must target port 443 (DoH), or tunnel DNS dies while the sandbox stand-in relay masks it.
- sing-box config changes must respect `tests/test_singbox_config.py` expectations (port exposure, DNS handling); see also `tests/test_socks5_exposure.py`.

## Build / artifact hygiene
- PyInstaller candidates and crash dumps go to transient scratch paths, never the repo or drive C: root (gitignored: `dist/`, `build/`, `artifacts/`, `*.spec`).
- Verify candidates by SHA-256, not by file presence.

## Test-suite gotchas
- ~1,002 tests as of 2026-11-09; run the full suite before declaring done (see `.opencode/memory/test-baseline.md` for the current baseline and known skips).
- `tests/verify-foreign-snapshot.tests.ps1` is a Pester suite, not pytest — it does not count toward the pytest baseline.
- `test_live_physical_preflight.py` and other `test_live_*`/`test_physical_*` tests may depend on host network state; check `.opencode/memory/operational-state.md` before attributing failures to code.

## Code conventions
- `src/foxyvpn` and `src/foxyvpn_windows` are legacy shims — fixes go in `perchvpn*` packages; do not "fix" the shims to diverge.
- After code edits run `graphify update .`; dirty `graphify-out/` files are expected and not a problem (see AGENTS.md).
