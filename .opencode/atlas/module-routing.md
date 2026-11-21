# Atlas: Module Routing — "which file do I touch?"

Deterministic task → module map. Verify with `graphify query` before editing if unsure.

## Task → module

| Task | Primary module(s) |
|---|---|
| SOCKS5 protocol / proxy server | `src/perchvpn/proxy/socks.py`, `tests/test_socks5_*.py` |
| Upstream / relay transport | `src/perchvpn/proxy/relay.py`, `upstream_proxy.py`, `pool.py` |
| HTTP/2 sessions | `src/perchvpn/headers.py`, `http_client.py` (h2) |
| HTTP/3 / QUIC sessions | `src/perchvpn/proxy/h3_session.py` (aioquic) |
| DNS over HTTPS | `src/perchvpn/doh_resolver.py`, `tests/test_resolver_dns.py`, `test_physical_dns_doh.py` |
| Server list / latency / failover | `src/perchvpn/serverlist.py`, `fastly.py`, `tests/test_api_countries_cache.py`, `test_candidate_failover.py`, `test_latency_probe.py` |
| Auth / FXA / OAuth / tokens | `src/perchvpn/auth.py`, `fxa.py`, `tokens.py`, `session_tokens.py`; `src/perchvpn_windows/oauth.py` |
| CLI | `src/perchvpn_windows/cli.py`, `src/perchvpn/cli.py` |
| GUI (webview) | `src/perchvpn_windows/webview.py`, `ui.py`, `frontend.py`, `winconsole.py` |
| Web UI (FastAPI) | `src/perchvpn_windows/api.py`, `app.py`, `web/` assets, `tests/test_web_*.py` |
| sing-box / TUN config generation | `src/perchvpn_windows/singbox_config.py`, `tun_frontend.py` |
| TUN lifecycle | `tun_frontend.py`, `tun_helper.py`, `tun_recovery.py`, `tun_state_capture.py`, `tun_status.py`, `tun_trial_runner.py`, `tun_trial_journal.py` |
| Physical adapter / DNS on host | `src/perchvpn_windows/physical_dns.py`, `platform.py`, `tests/test_physical_*.py` |
| Diagnostics / metrics | `src/perchvpn_windows/diagnostics.py`, `metrics.py` |
| Exit / kill-switch verification | `src/perchvpn/exitcheck.py`, `guardian.py`, `proxystate.py`, `tests/test_exit_verification.py` |
| Packaging / frozen builds | `scripts/build-candidate.ps1`, `src/perchvpn/buildinfo.py`, `tests/test_packaging.py`, `test_frozen_entry.py` |

## Conventions
- New protocol logic belongs in `src/perchvpn` (library), new host/UI integration in `src/perchvpn_windows`.
- Every behavior change needs a matching `tests/test_*.py` entry; baselines live in `.opencode/memory/test-baseline.md`.
- After code edits run `graphify update .` (AST-only) per AGENTS.md.
