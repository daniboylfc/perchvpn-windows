# Atlas: Interface Lifecycles

State machines and lifecycle ordering that tests and fixes must respect. Confirm details against source/graphify before relying on edge cases.

## Connection lifecycle (perchvpn_windows)
1. **Bootstrap** — `main.py` / `app.py` select mode (GUI / web / CLI); signed-out boot path covered by `tests/test_signedout_boot.py`.
2. **Auth** — FXA/OAuth via `perchvpn/auth.py` + `perchvpn_windows/oauth.py`; token persistence/refresh in `tokens.py`, `session_tokens.py` (`tests/test_runtime_token_refresh.py`, `test_token_cache.py`).
3. **Server selection** — `serverlist.py` + `fastly.py`; latency probes and candidate failover (`test_latency_probe.py`, `test_candidate_failover.py`).
4. **TUN / sing-box bring-up** — `singbox_config.py` generates config; `tun_frontend.py` + `tun_helper.py` orchestrate; trial runs are journaled (`tun_trial_runner.py` → `tun_trial_journal.py`).
5. **Physical side-effects** — `physical_dns.py` and `platform.py` apply host DNS/adapter changes; preflight in `tests/test_live_physical_preflight.py`.
6. **Steady state** — `guardian.py` + `exitcheck.py` monitor egress; `proxystate.py` tracks state.
7. **Teardown** — graceful shutdown path `tests/test_tun_graceful_shutdown.py`; recovery from torn states via `tun_recovery.py`.

## TUN trial state machine
`tun_trial_runner.py` executes a trial; every attempt appends to `tun_trial_journal.py`; final observed state is snapshotted by `tun_state_capture.py` and exposed via `tun_status.py`. Recovery (`tun_recovery.py`) consumes journal + snapshot. Tests: `test_tun_trial_runner.py`, `test_tun_trial_journal.py`, `test_tun_state_capture.py`, `test_tun_status.py`, `test_tun_recovery.py`.

## Token refresh lifecycle
Tokens migrate (`test_token_migration.py`), cache (`test_token_cache.py`), refresh in runtime (`test_runtime_token_refresh.py`), and quota-limited accounts (`test_quota_account.py`) follow the same refresh path. Never bypass `session_tokens.py` helpers when touching this.

## Country / hot-swap path
Switching server region mid-session goes through `tests/test_country_hot_swap.py` / `test_country_sort.py` paths — it must not re-run full bootstrap.

## Update rule
When you change a lifecycle's ordering or add a state, update this file and the corresponding tests in the same session.
