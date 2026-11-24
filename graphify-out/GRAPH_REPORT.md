# Graph Report - foxyvpn-windows  (2026-11-24)

## Corpus Check
- 181 files · ~260,989 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 8 file(s) not represented in the graph (top: (none) 3, .ico 2, .wxs 1)

## Summary
- 5907 nodes · 13733 edges · 273 communities (152 shown, 121 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 1325 edges (avg confidence: 0.87)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f01f721d`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_install_path_parity.py
- get_urltest
- relayer.py
- fxa.py
- TestGateVerification
- h3_session.py
- test_fxa_antibot.py
- _FakeWindll
- Dashboard
- TunRecoveryGate
- test_tun_graceful_shutdown.py
- classify
- test_tun_recovery.py
- SessionPool
- set_country
- subprocess
- test_runtime_fixes.py
- _read
- oauth_complete
- tun_state_capture.py
- client_e2e.py
- http_client.py
- test_winconsole.py
- _app
- TestWaitForApiReady
- WindowsConfig
- TrayIcon
- NetworkSnapshot
- _guardian_quota_fetch
- test_h2_upload_flow_control.py
- test_country_hot_swap.py
- test_tun_helper.py
- TestRunHelper
- patch
- test_android_parity_v107.py
- webview.py
- socket
- platform.py
- PerchVPNApp
- session.py
- _read
- detect_physical_ipv4
- RuntimeAuth
- oauth.py
- MockWriter
- httpx
- test_physical_dns_doh.py
- FakeHostRoutes
- test_candidate_failover.py
- test_latency_probe.py
- build_config
- upstream_proxy.py
- TestGuardianQuotaRemaining
- Socks5Frontend
- fastly.py
- test_win_process.py
- api.py
- _spec
- PhysicalDnsError
- test_api_mode_urlping.py
- _record
- test_physical_dns.py
- test_account_lifecycle.py
- physical_dns.py
- TunFrontend
- pytest
- _dispatch
- test_status_presentation.py
- test_resolver_dns.py
- perchvpn/cli.py
- .reconcile
- _session
- test_lifecycle.py
- MockUpstreamStream
- diagnostics.py
- test_fxa_login_v2.py
- ._dial
- test_physical_egress.py
- test_live_physical_preflight.py
- Get-ForeignTunnelSnapshot
- doh_resolver.py
- config.py
- _read
- test_iphelper_native.py
- .initialize
- .start
- env
- _FakeSocket
- NetworkConfig
- load_journal
- _stub_build_status
- _Response
- test_fastly_solver.py
- set_connection_mode
- FakeProcess
- test_pool_churn_and_fallback.py
- _FakeProc
- tun_trial_runner.py
- test_packaging.py
- TestBuildConfig
- TestExitVerificationStateTransitions
- test_web_mode_perf.py
- disconnect
- test_startup_diagnostics.py
- json
- guardian.py
- test_tun_diagnostic_fixes.py
- test_tun_state_capture.py
- iphelper.py
- auth.py
- ProxyCandidate
- asyncio
- load_tokens
- test_upstream_proxy_pin.py
- fetch_server_list
- TestRunPsWriteSemantics
- StateDifference
- threading
- H2Stream
- .emit
- Socks5Server
- TestStateResolutionMapping
- test_guardian_retry.py
- test_e2e_split_routes.py
- test_masque_port_gating.py
- test_tray.py
- test_tun_recovery.py
- test_close_storm_fires_once_within_renotify_window
- TestNodeStatusContractHarness
- app.js
- TestControllerPassReuse
- ._start_tun_helper
- TestEnforceAdapterMetric
- socket
- tun_helper.py
- _FakeSocket
- auth_helper_command
- _FakeH2Session
- TestIdentitySettleAndRetry
- PerchVPNApp
- FakeSession
- _DyingSession
- test_fxa_identity.py
- _Client
- ProxyController
- setTextIfChanged
- _preflight_interactive_auth
- stream
- TestWriteAndValidate
- FakeController
- ._client
- TestLiveBypassRoutes
- .test_recoverable_orphan_is_reconciled_then_spawned
- TestRuntimeWriteRoots
- TestParitySettingsControls
- status-contract.js
- ProxyError
- TestWsl2Routing
- TestStaleWintunCleanup
- TestCountryListRendering
- country-sort.js
- TestTunHelperNativeStubs
- perchvpn-windows
- _LazyModule
- perchvpn
- _Win32Tray
- _RecordingSession
- _adapter_rows
- TestStatusWebSocketPush
- detect_competing_tunnel
- SessionTokenPool
- TestConnectionButtonSignedOutFlow
- test_parse_adapter_buffer_reads_onlink_prefix_length
- TestDatapathParityControls
- _run_in_api_pool
- _FakeWindow
- _FakeSocket
- test_interface_entry_false_values_rejected
- TestResolveDeadline
- test_adapters_native_resizes_from_needed_value
- test_http_client_rebuild_race.py
- TestUnifiedDelaySweep
- server
- .loadCountries
- launch_webview
- TestRecoveryProbeFallback
- _KeepAliveSession
- test_physical_bootstrap.py
- test_tun_frontend.py
- _panel
- tun_status.py
- TestPhysicalResolutionPath
- TestDashboardStackedInfoRows
- test_set_interface_metric_uses_zero_site_prefix_length
- app.py
- TestHttpClientPinning
- perchvpn_windows/cli.py
- account_signin
- capture_snapshot_batched
- test_web_structure.py
- _FakeEvent
- TestReleaseParityFiles
- test_tray_toggle_posts_connect_when_idle
- redact
- TestWindowedAuthFlow
- TransportOptions
- FakeHostRoutes
- test_launch_webview_stops_the_tray_on_exit
- TestRecoverCli
- _FakeBackend
- fixture

## God Nodes (most connected - your core abstractions)
1. `WindowsConfig` - 183 edges
2. `PerchVPNApp` - 145 edges
3. `PerchVPNApp` - 139 edges
4. `TunFrontend` - 124 edges
5. `NetworkSnapshot` - 77 edges
6. `_gate()` - 61 edges
7. `SessionPool` - 55 edges
8. `NetworkConfig` - 54 edges
9. `TunRecoveryGate` - 53 edges
10. `ProxyError` - 52 edges

## Surprising Connections (you probably didn't know these)
- `initialize()` --calls--> `TokenInvalidError`  [INFERRED]
  tests/test_lifecycle.py → src/perchvpn/exceptions.py
- `fake_exchange()` --calls--> `FxaApiError`  [INFERRED]
  tests/test_fxa_antibot.py → src/perchvpn/exceptions.py
- `fake_login()` --calls--> `FxaApiError`  [INFERRED]
  tests/test_signin_errors.py → src/perchvpn/exceptions.py
- `executor()` --calls--> `RollbackError`  [INFERRED]
  tests/test_tun_trial_journal.py → src/perchvpn_windows/tun_state_capture.py
- `boom()` --calls--> `CaptureError`  [INFERRED]
  tests/test_physical_egress.py → src/perchvpn_windows/tun_state_capture.py

## Import Cycles
- 3-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_frontend.py -> src/perchvpn_windows/__init__.py`
- 3-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_helper.py -> src/perchvpn_windows/__init__.py`
- 4-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_frontend.py -> src/perchvpn_windows/tun_helper.py -> src/perchvpn_windows/__init__.py`

## Communities (273 total, 121 thin omitted)

### Community 0 - "test_install_path_parity.py"
Cohesion: 0.12
Nodes (6): TestApiSmokeMode, TestConsolelessStartup, TestPersistentWebviewProfile, TestStartupTimingMarks, TestWritableCwd, user_dirs()

### Community 1 - "get_urltest"
Cohesion: 0.06
Nodes (15): TokenInvalidError, get_urltest(), _get_urltest_raw_token(), _remember_failure(), _pass_ttl_seconds(), TestUrlTestEndpoint, _app_with_auth(), _reset_globals() (+7 more)

### Community 2 - "relayer.py"
Cohesion: 0.06
Nodes (22): build_relayer_url(), candidate_relayers(), configure(), current_state(), _direct_request(), match_category(), measure_relayer_rtt(), RelayerState (+14 more)

### Community 3 - "fxa.py"
Cohesion: 0.06
Nodes (33): resend_verification_code(), send_unblock_code(), FxaApiError, FxaUnblockCodeRequired, authorization_code_from_session(), CredentialStatus, _derive_auth_pw(), _derive_auth_pw_v2() (+25 more)

### Community 5 - "h3_session.py"
Cohesion: 0.05
Nodes (8): _format_authority(), _H3ClientProtocol, H3ProxySession, create_protocol(), H3Stream, _PinnedQuicConnect, _FakeQuicConnectCM, test_h3_configuration_pins_strict_verification()

### Community 6 - "test_fxa_antibot.py"
Cohesion: 0.08
Nodes (11): _FakeClient, _FakeResponse, TestAccountUiWiring, TestMetricsFlow, TestSessionTokenImport, fake_exchange(), fake_exchange(), TestSigninEndpointUnblock (+3 more)

### Community 7 - "_FakeWindll"
Cohesion: 0.17
Nodes (3): fake_windll(), _FakeCfunc, _FakeWindll

### Community 8 - "Dashboard"
Cohesion: 0.07
Nodes (12): _c(), Dashboard, DashboardData, demo(), _fmt_bytes(), _fmt_speed(), _fmt_uptime(), _pad() (+4 more)

### Community 9 - "TunRecoveryGate"
Cohesion: 0.09
Nodes (6): RecoveryRun, RecoveryUnverified, TunRecoveryGate, _without_transient_trial_adapter(), failing_capture(), TestPreStartParallelStep

### Community 10 - "test_tun_graceful_shutdown.py"
Cohesion: 0.08
Nodes (28): _BlockingProcess, _ExitedProcess, _fake_frontend_ps(), _frontend(), _GracefulProcess, _identity(), _recovery_gate_and_run(), _no_sleep() (+20 more)

### Community 11 - "classify"
Cohesion: 0.05
Nodes (10): ui_status_from_controller(), _default_probe(), AdapterEvidence, classify(), _parse_probe(), probe_adapter(), TestNativeFastPath, TestAdapterParsing (+2 more)

### Community 12 - "test_tun_recovery.py"
Cohesion: 0.12
Nodes (5): _FakeProcess, _frontend(), TestBaselineRestoration, TestFrontendGate, failing_write()

### Community 13 - "SessionPool"
Cohesion: 0.15
Nodes (14): SessionPool, test_born_dead_growth_dial_records_close_event(), test_dead_session_open_stream_records_close_and_retries(), test_growth_dials_share_the_gate(), test_replacement_dials_are_rate_limited(), factory(), test_concurrent_growth_never_exceeds_max_sessions(), test_controller_config_parity_defaults() (+6 more)

### Community 14 - "set_country"
Cohesion: 0.07
Nodes (10): _attach_status_notifier(), CountrySelection, lifespan(), _retain_failed_app(), set_country(), _startup(), TestCountryEndpointHotPath, TestCountryHotPathAdapterIsolation (+2 more)

### Community 15 - "subprocess"
Cohesion: 0.06
Nodes (15): _default_spawn(), hidden_process_kwargs(), hidden_startupinfo(), popen_hidden(), _rule(), test_real_chromium_bounding_boxes(), TestAccountAlignment, TestPasswordToggle (+7 more)

### Community 16 - "test_runtime_fixes.py"
Cohesion: 0.06
Nodes (12): broadcast_log(), _shutdown(), test_broadcast_log_handles_concurrent_set_changes(), test_broadcast_log_prunes_failed_clients(), test_lifespan_runs_startup_and_shutdown(), test_quota_monitor_calls_synchronous_fetch_user_info(), test_restart_refreshes_global_config(), test_restart_task_cancellation_completes_old_shutdown() (+4 more)

### Community 17 - "_read"
Cohesion: 0.26
Nodes (3): _read(), TestRenderingPerformance, TestTacticalRadar

### Community 18 - "oauth_complete"
Cohesion: 0.11
Nodes (16): oauth_complete(), OAuthCompleteRequest, cancel_oauth_flow(), get_flow(), oauth_flow_status(), start_oauth_flow(), _app_mock(), _callback_url() (+8 more)

### Community 19 - "tun_state_capture.py"
Cohesion: 0.06
Nodes (33): established_remote_endpoints(), _accepts_require_up(), _boot_time(), _default_creation_time(), _posix_creation_time(), _powershell_adapter_probe(), _ps_quote(), _windows_creation_time() (+25 more)

### Community 20 - "client_e2e.py"
Cohesion: 0.06
Nodes (40): add_check(), as_list(), curl_get(), dns_packet(), dns_query_tcp(), dns_query_udp(), _e2e_cert_paths(), _e2e_h1_tls_context() (+32 more)

### Community 21 - "http_client.py"
Cohesion: 0.09
Nodes (14): DoHTransport, _build_client(), control_plane_proxy_url(), _env_proxy_url(), get_async_client(), _local_addr_kwargs(), _normalize_proxy_url(), physical_interface_socket_options() (+6 more)

### Community 22 - "test_winconsole.py"
Cohesion: 0.07
Nodes (7): fake_win32(), _FakeKernel32, _reset_std_streams(), TestAuthOnlyHelperAttachesConsole, TestEnsureInteractiveConsole, TestRestoreStreams, TestWebviewReExports

### Community 23 - "_app"
Cohesion: 0.09
Nodes (8): _app(), FakeHelper, _ready_frontend(), TestApplyMode, start_helper(), TestBeginModeApply, TestLocalSocksPrerequisite, TestResolveTunExecutable

### Community 24 - "TestWaitForApiReady"
Cohesion: 0.08
Nodes (3): _wait_for_api_ready(), TestWaitForApiReadyProxyOnly, TestWaitForApiReady

### Community 25 - "WindowsConfig"
Cohesion: 0.05
Nodes (14): is_newer_version(), _parse_version_parts(), _LogCaptureHandler, WindowsConfig, TestEffectiveUseHttp3, TestParityDefaults, TestParityPersistence, TestParityValidation (+6 more)

### Community 26 - "TrayIcon"
Cohesion: 0.09
Nodes (9): is_supported(), TrayIcon, _api_status(), _start_tray(), _menu(), _on_closing(), _tray_toggle(), _work() (+1 more)

### Community 27 - "NetworkSnapshot"
Cohesion: 0.10
Nodes (8): compare_snapshots(), _is_tproxy_route(), NetworkSnapshot, partition_diffs(), TestCompareSnapshotsValidation, TestPartitionDiffsTproxyOwnership, TestStateCapture, _snap()

### Community 28 - "_guardian_quota_fetch"
Cohesion: 0.08
Nodes (18): get_account_quota(), get_app(), _guardian_quota_fetch(), _parse_int_bytes(), _parse_reset_epoch(), _quota_error_response(), _quota_token_key(), QuotaResponse (+10 more)

### Community 29 - "test_h2_upload_flow_control.py"
Cohesion: 0.09
Nodes (5): _Peer, _pump(), test_multi_megabyte_upload_flows_through_flow_control(), test_upload_waiting_for_a_window_fails_as_proxy_error(), _Wire

### Community 30 - "test_country_hot_swap.py"
Cohesion: 0.14
Nodes (10): _app(), _clean_instances(), FakeFrontend, FakeTunHelper, _patch_switch_deps(), _target(), TestHotSwap, TestHotSwapPinsBeforeDial (+2 more)

### Community 31 - "test_tun_helper.py"
Cohesion: 0.16
Nodes (10): _adapter(), _default_route(), _iface(), _ip(), _snapshot(), TestAdapterReusePlan, TestConflictDetection, TestPhysicalSelection (+2 more)

### Community 32 - "TestRunHelper"
Cohesion: 0.09
Nodes (17): _evidence(), TestActivationSafety, probe(), probe(), probe(), probe(), TestRunHelper, do_spawn() (+9 more)

### Community 33 - "patch"
Cohesion: 0.06
Nodes (10): _run_auth_only(), _has_valid_token(), _run_auth_flow(), _spawn_auth_helper(), _wait_for_token_ready(), TestRunAuthFlow, TestRunAuthOnly, TestSpawnAuthHelper (+2 more)

### Community 34 - "test_android_parity_v107.py"
Cohesion: 0.11
Nodes (5): _client_with_remote_max(), _FakeConn, _NullWriter, TestH2StreamSlot, TestH2StreamSlotConcurrency

### Community 35 - "webview.py"
Cohesion: 0.05
Nodes (31): _install_startup_reporting(), append_crash_log(), append_startup_log(), _base_dir(), crash_log_path(), focus_existing_instance(), install_excepthook(), _hook() (+23 more)

### Community 36 - "socket"
Cohesion: 0.07
Nodes (12): _dial_direct(), _format_authority(), H1ProxySession, H1Stream, _handshake_sync(), SessionAtCapacity, _ScriptedServer, TestH1ConnectionLoss (+4 more)

### Community 38 - "platform.py"
Cohesion: 0.06
Nodes (20): _appdata_base(), discard_legacy_tokens(), ensure_config_dir(), get_config_dir(), get_legacy_config_dir(), get_legacy_migration_marker_path(), get_local_app_data_dir(), get_proxy_state_path() (+12 more)

### Community 40 - "session.py"
Cohesion: 0.11
Nodes (11): _tls_context(), stream_id_for_stream(), configure_client_hello(), certifi_cafile(), load_certifi_roots(), test_certifi_cafile_points_at_existing_bundle(), test_h1_tls_context_is_strict_and_loads_certifi(), spy() (+3 more)

### Community 41 - "_read"
Cohesion: 0.11
Nodes (6): _read(), TestAllowanceGauge, TestLiveLogsUI, TestNoRegression, TestRadarMarkup, TestRadarStateLogic

### Community 42 - "detect_physical_ipv4"
Cohesion: 0.32
Nodes (4): detect_physical_ipv4(), _snapshot(), TestDetectPhysicalIpv4, boom()

### Community 43 - "RuntimeAuth"
Cohesion: 0.08
Nodes (22): AccessTokenExpiredError, refresh_runtime_auth(), RuntimeAuth, _expired_token_file(), TestObtainAuthRefreshFallback, boom(), fake_login(), wrapper() (+14 more)

### Community 44 - "oauth.py"
Cohesion: 0.07
Nodes (21): generate_pkce(), new_state(), _begin_flow(), _begin_guardian_flow(), _CallbackServer, complete_oauth_flow(), complete_oauth_flow_async(), _generate_pkce() (+13 more)

### Community 45 - "MockWriter"
Cohesion: 0.09
Nodes (5): MockReader, MockWriter, TestSocks5NoAuthConnect, TestSocks5ReplyFormat, TestSocks5UserPassAuth

### Community 46 - "httpx"
Cohesion: 0.17
Nodes (11): _adapt_egress_for_sandbox(), _adapt_recovery_probe_for_sandbox(), patient(), ghost_present_count(), main(), transit_probe(), parse_cloudflare_trace(), route_snapshot() (+3 more)

### Community 47 - "test_physical_dns_doh.py"
Cohesion: 0.20
Nodes (26): query_doh_ipv4(), _fake_network(), factory(), _http(), _http_with(), _name(), _response(), _set_platform() (+18 more)

### Community 48 - "FakeHostRoutes"
Cohesion: 0.14
Nodes (5): add(), TestRecoveryOwnership, remove(), TestRunHelperP0, parent_alive()

### Community 49 - "test_candidate_failover.py"
Cohesion: 0.10
Nodes (16): _candidate(), _controller(), _countries(), _fake_pass(), FakeSession, TestAlternateCandidates, TestControllerFailover, fake_initial() (+8 more)

### Community 50 - "test_latency_probe.py"
Cohesion: 0.11
Nodes (13): get_latency(), _FakeWriter, test_latency_ipv4_validated(), test_latency_link_local_rejected(), test_latency_loopback_rejected(), test_latency_mixed_dns_answers_rejected(), test_latency_private_rejected(), test_latency_success_against_public_destination() (+5 more)

### Community 51 - "build_config"
Cohesion: 0.07
Nodes (17): available_mixed_port(), build_config(), _custom_doh_endpoint(), dumps_config(), _exclude_addresses(), excluded_networks(), _normalize_cidr(), tunnel_dns_endpoint() (+9 more)

### Community 52 - "upstream_proxy.py"
Cohesion: 0.22
Nodes (8): _apply_physical_interface(), _apply_source_bind(), _connect_http(), _connect_socks5(), connect_through_upstream_proxy(), _proxy_connection_target(), _recv_exact(), UpstreamProxyError

### Community 54 - "Socks5Frontend"
Cohesion: 0.14
Nodes (3): Socks5Frontend, TestSocks5Frontend, TestFrontendLifecycle

### Community 55 - "fastly.py"
Cohesion: 0.13
Nodes (14): FastlyChallengeError, _answer_challenge(), _base_origin(), _browser_session(), _client_metrics_answer(), _fetch_pat(), _install_challenge_cookies(), _NoChallengePage (+6 more)

### Community 56 - "test_win_process.py"
Cohesion: 0.15
Nodes (6): _FakeStartupInfo, test_popen_hidden_forwards_hidden_launch_parameters(), test_run_hidden_forwards_hidden_launch_parameters(), fake_run(), test_stale_wintun_removal_uses_hidden_pnputil(), test_terminate_pid_uses_hidden_taskkill()

### Community 57 - "api.py"
Cohesion: 0.03
Nodes (69): dns_cache_stats(), account_login(), account_resend_verification(), account_send_unblock_code(), account_session_token(), account_verify_cancel(), AccountActionResponse, AccountResponse (+61 more)

### Community 58 - "_spec"
Cohesion: 0.11
Nodes (5): FakeClock, _spec(), TestSidecarCommand, TestTunHelperClient, launcher()

### Community 59 - "PhysicalDnsError"
Cohesion: 0.11
Nodes (20): _doh_fallback_reason(), PhysicalDnsError, resolve_ipv4(), _validated_ipv4_endpoints(), _doh_result(), test_resolve_does_not_fall_back_after_later_authoritative_error(), doh(), query() (+12 more)

### Community 60 - "test_api_mode_urlping.py"
Cohesion: 0.10
Nodes (10): url_ping(), UrlPingRequest, _FakeAsyncClient, _FakeResponse, _FakeStreamCtx, _get_status(), _proxy_only_app(), _reset_globals() (+2 more)

### Community 61 - "_record"
Cohesion: 0.07
Nodes (9): _drifted_snapshot_dict(), _gate(), _record(), _snapshot_dict(), executor(), executor(), TestNetworkBaseline, TestStaleOwnershipReconciliation (+1 more)

### Community 62 - "test_physical_dns.py"
Cohesion: 0.18
Nodes (16): parse_response(), query_a(), _a(), _FakeSocket, _name(), _response(), _rr(), test_build_query_encodes_recursive_a_record() (+8 more)

### Community 63 - "test_account_lifecycle.py"
Cohesion: 0.18
Nodes (15): account_logout(), test_account_logout_failure_does_not_report_success(), test_account_logout_success(), test_load_persisted_auth_disabled_during_logout(), test_load_persisted_auth_failed_credentials_not_installed(), test_load_persisted_auth_failed_then_retry_succeeds(), test_load_persisted_auth_rejects_invalid(), test_load_persisted_auth_serializes_concurrent_handoff() (+7 more)

### Community 64 - "physical_dns.py"
Cohesion: 0.13
Nodes (10): _bind_physical_interface(), build_query(), _decode_name(), _encode_name(), _query_doh_endpoint(), _read_doh_body(), _verifying_tls_context(), test_doh_tls_context_falls_back_to_platform_store() (+2 more)

### Community 65 - "TunFrontend"
Cohesion: 0.10
Nodes (7): _check_tun_prerequisites(), TunFrontend, TestBuildCommand, TestBuildCommandBypass, TestCaptureLimits, TestIdempotencyAndMtu, TestResolveExecutable

### Community 66 - "pytest"
Cohesion: 0.17
Nodes (8): HttpProxyServer, _is_local_network(), test_http_proxy_binds_and_rejects_without_session(), test_http_proxy_stop_terminates_active_connect_tunnel(), test_loopback_bind_accepted(), test_nonloopback_bind_rejected(), test_wildcard_bind_accepted_with_local_proxy_auth(), test_wildcard_bind_rejected()

### Community 67 - "_dispatch"
Cohesion: 0.10
Nodes (7): acquire(), _kernel32(), release(), _dispatch(), _helper_spec(), TestEntrypointDashboardDispatch, TestEntrypointDispatch

### Community 68 - "test_status_presentation.py"
Cohesion: 0.08
Nodes (13): _FakeMetrics, _get_status(), _make_app_pair(), TestCanonicalTunStatusContract, TestControllerReasonTranslation, TestStatusConnectedExitVerificationFailed, TestStatusConnectedExitVerificationNotApplicable, TestStatusConnectedExitVerificationPending (+5 more)

### Community 69 - "test_resolver_dns.py"
Cohesion: 0.08
Nodes (18): _clear_overrides(), test_authorized_request_dials_only_the_verified_pin(), _dns_response(), FakeClient, FakeResponse, test_automatic_fails_closed_on_total_failure(), test_cancelled_race_cancels_every_query(), test_custom_resolver_requires_ip() (+10 more)

### Community 70 - "perchvpn/cli.py"
Cohesion: 0.07
Nodes (18): version_string(), _async_main(), build_parser(), _format_socks_authority(), _install_benign_future_exception_filter(), main(), _parse_listen(), _validate_args() (+10 more)

### Community 72 - "_session"
Cohesion: 0.09
Nodes (6): FakeConn, FakeWriter, _noop_read_loop(), _session(), TestOpenStreamTimeout, fake_open_connection()

### Community 73 - "test_lifecycle.py"
Cohesion: 0.10
Nodes (6): _apply_mode_flags(), restart(), _make_app(), TestRestart, initialize(), TestShutdown

### Community 74 - "MockUpstreamStream"
Cohesion: 0.11
Nodes (4): MockReader, MockUpstreamStream, MockWriter, TestRelayBidirectional

### Community 75 - "diagnostics.py"
Cohesion: 0.22
Nodes (4): DiagnosticsBuffer, install_logger_handler(), LoggingDiagnosticsHandler, TestLoggingHandler

### Community 76 - "test_fxa_login_v2.py"
Cohesion: 0.16
Nodes (4): _hkdf_auth_pw(), TestEdgeBlockMessage, TestKeyStretching, TestVerificationMethodNormalization

### Community 78 - "test_physical_egress.py"
Cohesion: 0.12
Nodes (8): ProxyCandidate, _controller_config(), test_control_plane_bypass_ips_times_out_and_falls_back_to_os(), TestControllerWiring, TestCountrySwitchPins, slow_physical(), TestEdgeHostPins, UpstreamStub

### Community 79 - "test_live_physical_preflight.py"
Cohesion: 0.08
Nodes (29): _adapter_bytes(), _bind_physical(), _bulk_download(), _burst(), _decode_unicast_if(), _discover_tunnel_adapter(), _discover_wifi_index(), _discover_wifi_ipv4() (+21 more)

### Community 80 - "Get-ForeignTunnelSnapshot"
Cohesion: 0.19
Nodes (14): Add-Check(), Compare-ForeignTunnelSnapshots(), Get-ForeignTunnelSnapshot(), Get-PhysicalLayout(), Invoke-Api(), Save-Report(), Test-GeneralConnectivity(), Get-DnsClientServerAddress() (+6 more)

### Community 81 - "doh_resolver.py"
Cohesion: 0.14
Nodes (13): _build_query(), _cache_key(), _cache_lookup(), _cache_store(), DoHResolver, _local_addr_kwargs(), _parse_answers(), _parse_answers_with_ttl() (+5 more)

### Community 82 - "config.py"
Cohesion: 0.08
Nodes (25): _restart_worker(), set_network_config(), _config_path(), _CRYPT_INTEGER_BLOB, _cryptprotect(), _cryptunprotect(), _decrypt_password(), _encrypt_password() (+17 more)

### Community 83 - "_read"
Cohesion: 0.18
Nodes (5): _read(), TestAuthStateAfterSignIn, TestOnboardingPromptMarkup, TestOnboardingVisibilityLogic, TestSignedOutLatencyGating

### Community 84 - "test_iphelper_native.py"
Cohesion: 0.15
Nodes (5): socket_inet_pton(), socket_inet_pton6(), test_dll_sentinel_initialised_at_module_level(), test_dns_servers_native_groups_by_family(), test_walk_adapter_rows_follows_next_not_length()

### Community 85 - ".initialize"
Cohesion: 0.15
Nodes (9): _initial_dial_backoff(), alternate_candidates(), available_country_codes(), _candidates_for_country(), _default_connect_protocol(), _parse_host_port(), _PersistedState, ProxyStateStore (+1 more)

### Community 88 - "env"
Cohesion: 0.05
Nodes (36): defaults, runs-on, steps, timeout-minutes, run, env, GH_TOKEN, MANUFACTURER (+28 more)

### Community 89 - "_FakeSocket"
Cohesion: 0.11
Nodes (5): context(), _FakeContext, _FakeSocket, _FakeTLS, factory()

### Community 90 - "NetworkConfig"
Cohesion: 0.08
Nodes (7): NetworkConfig, TestNetworkRequestValidation, TestTlsFragmentApiFields, test_network_config_accepts_lan_bind(), test_network_config_lan_bind_with_http_proxy(), test_network_config_relayer_pair_validation(), test_upstream_proxy_validation_requires_host_when_enabled()

### Community 91 - "load_journal"
Cohesion: 0.23
Nodes (3): load_journal(), compute_file_identity(), TestTrialJournalValidation

### Community 93 - "_stub_build_status"
Cohesion: 0.05
Nodes (30): broadcast_status(), _build_status_response(), _ensure_status_monitor(), get_status(), notify_status_changed(), _push_now(), _push_status_frame(), _status_metrics_signature() (+22 more)

### Community 94 - "_Response"
Cohesion: 0.26
Nodes (3): _Response, _RoutedClient, TestCredentialStatusSelection

### Community 95 - "test_fastly_solver.py"
Cohesion: 0.22
Nodes (5): _FakeSession, _pow_data(), _Resp, test_api_host_406_falls_through_and_cookies_are_installed(), test_captcha_challenge_raises_clear_error()

### Community 96 - "set_connection_mode"
Cohesion: 0.05
Nodes (10): _app_can_apply_mode(), ConnectionModeRequest, _modes_payload_of(), set_connection_mode(), TestConnectionModeEndpoint, _config(), TestBootIdle, TestModeDispatch (+2 more)

### Community 97 - "FakeProcess"
Cohesion: 0.15
Nodes (3): TestReconcileCaptureCadence, TestReconcileTrafficVerified, FakeProcess

### Community 98 - "test_pool_churn_and_fallback.py"
Cohesion: 0.19
Nodes (11): _is_quic_timeout(), _bare_controller(), _controller_config(), _FakePool, test_close_storm_falls_back_to_http2_and_repoints_frontend(), on_pool_replaced(), test_fallback_failure_keeps_the_current_pool(), test_http2_pool_does_not_react_to_close_storms() (+3 more)

### Community 99 - "_FakeProc"
Cohesion: 0.15
Nodes (3): _FakeProc, _StubbornProc, TestTerminateProcessEscalation

### Community 100 - "tun_trial_runner.py"
Cohesion: 0.05
Nodes (20): reconcile_stale_ownership(), clear_journal(), _journal_path(), JournalError, load_journal(), save_journal(), TrialJournal, TrialPreparationError (+12 more)

### Community 102 - "test_packaging.py"
Cohesion: 0.17
Nodes (3): TestCliSurface, TestPackageIdentity, TestWebAssetResolution

### Community 105 - "test_web_mode_perf.py"
Cohesion: 0.11
Nodes (5): _read(), TestClientPerfEndpoint, TestIdleRepaintGuards, TestModeUi, TestRadarPerformance

### Community 106 - "disconnect"
Cohesion: 0.07
Nodes (11): _await_background_shutdown(), disconnect(), _run_in_urltest_pool(), _noop_broadcast(), _reset_globals(), TestBoundedDisconnect, run(), run() (+3 more)

### Community 107 - "test_startup_diagnostics.py"
Cohesion: 0.12
Nodes (7): _FakeFunction, _FakeKernel32, TestCrashLog, TestExceptionHooks, TestInstanceGuard, fake_windll(), _wire_mutex()

### Community 108 - "json"
Cohesion: 0.06
Nodes (17): build_harness(), evaluate(), main(), run_size(), windows_path(), _default_identity(), _atomic_write(), compute_file_identity() (+9 more)

### Community 110 - "guardian.py"
Cohesion: 0.08
Nodes (27): GuardianHTTPError, QuotaExceededError, activate_guardian(), _authorized_request(), _coerce_optional_int(), _detect_proxy_pass_claim_time_offset(), Entitlement, fetch_proxy_pass() (+19 more)

### Community 111 - "test_tun_diagnostic_fixes.py"
Cohesion: 0.07
Nodes (8): TestBoundedDisconnect, TestCgnatExclusion, TestDnsRefusalNamesCompetingIfIndex, TestPostPinEgressStallFastFail, fake_foreign(), TestPreStartGateUsesFastSnapshot, TestRouteCoverageVsExcludedSentinels, TestSingBoxLogOutput

### Community 112 - "test_tun_state_capture.py"
Cohesion: 0.18
Nodes (5): _patch_captures(), test_capture_snapshot_native_skips_adapters_without_ip_interface(), test_capture_snapshot_preserves_capture_error_message(), test_capture_snapshot_runs_all_captures_and_assembles(), fake()

### Community 113 - "iphelper.py"
Cohesion: 0.04
Nodes (39): adapter_present_native(), _adapter_row(), adapters_native(), available(), best_route_interface(), _dll(), dns_servers_native(), interface_entry_native() (+31 more)

### Community 114 - "auth.py"
Cohesion: 0.06
Nodes (31): complete_link_verification(), _from_single_session_token(), InteractiveLoginRequired, _is_permanent_refresh_rejection(), _login_interactively(), login_with_password(), login_with_session_token(), obtain_auth() (+23 more)

### Community 115 - "ProxyCandidate"
Cohesion: 0.10
Nodes (5): _app(), TestControlPlaneEndpointPinning, _socks_ready(), TestFailClosedTunGate, TestTunBypassIps

### Community 116 - "asyncio"
Cohesion: 0.11
Nodes (4): test_control_plane_bypass_ips_falls_back_to_cached_ip(), TestControlPlanePinRefresh, TestH3SourceBind, TestStartupPhysicalPreflight

### Community 117 - "load_tokens"
Cohesion: 0.15
Nodes (4): delete_tokens(), load_tokens(), _token_path(), TestTokenPathOverride

### Community 118 - "test_upstream_proxy_pin.py"
Cohesion: 0.27
Nodes (11): UpstreamProxyConfig, _controller(), test_interface_pin_sets_ip_unicast_if_before_connect(), test_literal_proxy_ip_needs_no_pin(), test_no_interface_pin_means_no_socket_option(), test_non_literal_pin_is_not_accepted_as_verified(), test_pinning_requirement_is_off_without_the_tunnel(), test_proxy_connection_dials_the_pin_and_keeps_the_target_name() (+3 more)

### Community 119 - "fetch_server_list"
Cohesion: 0.09
Nodes (16): _cache_path(), City, Country, fetch_server_list(), load_cached_server_list(), _parse_server_list(), print_server_list(), Protocol (+8 more)

### Community 120 - "TestRunPsWriteSemantics"
Cohesion: 0.20
Nodes (3): TestRunPsWriteSemantics, executor(), executor()

### Community 121 - "StateDifference"
Cohesion: 0.10
Nodes (15): _adapter_indexes(), _difference_interface_index(), _is_virtual_adapter(), _dns_rollback_command(), generate_rollback_commands(), _rollback_adapter(), _rollback_dns(), _rollback_interface() (+7 more)

### Community 122 - "threading"
Cohesion: 0.29
Nodes (7): _default_clock(), _serve(), test_http_proxy_connect(), test_http_proxy_rejects_non_2xx(), test_socks5_no_auth_connect(), handler(), test_socks5_userpass_connect()

### Community 123 - "H2Stream"
Cohesion: 0.17
Nodes (4): _pump_client_to_upstream(), _pump_upstream_to_client(), relay_bidirectional(), H2Stream

### Community 125 - "Socks5Server"
Cohesion: 0.19
Nodes (10): Socks5Server, test_api_rejects_nonloopback_http_proxy_bind(), test_config_rejects_nonloopback_http_proxy_bind(), test_config_wildcard_http_proxy_bind_requires_auth(), test_api_wildcard_socks_bind_requires_local_proxy_auth(), test_config_accepts_loopback_socks_bind(), test_config_wildcard_socks_bind_requires_local_proxy_auth(), test_socks_server_accepts_loopback_bind() (+2 more)

### Community 127 - "test_guardian_retry.py"
Cohesion: 0.18
Nodes (8): _FakeClient, _FakeResponse, patched(), test_challenge_error_propagates_and_stops_retrying(), failing_solve(), test_challenge_then_success_solves_once_and_retries(), test_initial_success_makes_one_request_without_challenge(), test_persistent_406_capped_at_five_retries()

### Community 128 - "test_e2e_split_routes.py"
Cohesion: 0.26
Nodes (8): _load_support(), _route(), support(), test_decomposed_public_halves_satisfy_check(), test_literal_split_routes_satisfy_check(), test_other_adapter_routes_are_ignored(), test_private_and_onlink_routes_do_not_count(), test_single_half_is_not_enough()

### Community 129 - "test_masque_port_gating.py"
Cohesion: 0.25
Nodes (9): _connect_rep(), _make_server(), _negotiate(), test_502_refusal_does_not_break_other_targets_on_same_port(), test_502_refusal_trips_per_target_breaker(), test_custom_upstream_disables_port_gating(), test_disconnect_cancels_in_flight_restart_task(), test_non_masque_port_rejected_locally_without_upstream_stream() (+1 more)

### Community 130 - "test_tray.py"
Cohesion: 0.19
Nodes (10): _icon(), test_a_failing_backend_reports_that_the_icon_is_unavailable(), test_a_failing_callback_does_not_break_the_loop(), _boom(), test_api_status_defaults_to_disconnected_when_unreachable(), test_menu_exposes_open_toggle_and_quit(), test_menu_provider_failure_falls_back_to_the_cached_menu(), test_messages_dispatch_to_the_callbacks() (+2 more)

### Community 131 - "test_tun_recovery.py"
Cohesion: 0.08
Nodes (10): _capture_of(), _FakeApp, _identity(), _instant_sleep(), _sequence_capture(), _capture(), TestCliInterruption, TestGatePreStart (+2 more)

### Community 132 - "test_close_storm_fires_once_within_renotify_window"
Cohesion: 0.22
Nodes (5): _factory_ok(), test_close_storm_fires_once_within_renotify_window(), on_storm(), test_scattered_closes_do_not_signal_storm(), test_storm_callback_failure_does_not_break_serving()

### Community 135 - "app.js"
Cohesion: 0.47
Nodes (9): apply(), boot(), init(), pause(), radianceFactor(), setRadiance(), setTransforms(), start() (+1 more)

### Community 136 - "TestControllerPassReuse"
Cohesion: 0.39
Nodes (3): TestControllerPassReuse, fake_acquire(), pool_start()

### Community 137 - "._start_tun_helper"
Cohesion: 0.06
Nodes (14): _is_ip(), set_control_plane_address_overrides(), _getaddrinfo_ipv4_addresses(), _resolve_host(), _pin_host(), _add(), _add(), _physical_dns_servers() (+6 more)

### Community 138 - "TestEnforceAdapterMetric"
Cohesion: 0.27
Nodes (3): TestEnforceAdapterMetric, fake_write(), TestEnforceSplitRouteMetrics

### Community 141 - "tun_helper.py"
Cohesion: 0.04
Nodes (50): _route_interface(), _adapter_has_ipv4(), _adapter_present(), adapter_reuse_plan(), apply_bypass_routes(), _atomic_write_json(), build_sidecar_command(), bypass_route_changes() (+42 more)

### Community 143 - "auth_helper_command"
Cohesion: 0.24
Nodes (4): auth_helper_command(), test_auth_helper_command_env_frozen_flag_forces_exe_argv(), test_auth_helper_command_frozen_uses_exe_argv(), test_auth_helper_command_source_uses_module_invocation()

### Community 146 - "PerchVPNApp"
Cohesion: 0.04
Nodes (25): PerchVPNApp, test_parse_edge_address_empty(), test_parse_edge_address_host_only(), test_parse_edge_address_host_port(), test_parse_edge_address_ipv6_with_port(), test_close_storm_fallback_reverifies_exit(), test_exit_check_cancelled_during_shutdown(), test_exit_check_disabled_is_not_applicable() (+17 more)

### Community 147 - "FakeSession"
Cohesion: 0.20
Nodes (4): FakeSession, factory(), factory(), factory()

### Community 148 - "_DyingSession"
Cohesion: 0.10
Nodes (13): _affinity_with_hash_mod(), _AtCapSession, _DyingSession, _FakeClock, _HealthySession, _Session, factory(), factory() (+5 more)

### Community 149 - "test_fxa_identity.py"
Cohesion: 0.29
Nodes (5): _FakeResponse, _HeaderCapturingClient, _responder(), test_fxa_api_uses_product_ua_with_browser_headers(), test_hawk_requests_also_send_product_ua_and_never_reuse_signatures()

### Community 150 - "_Client"
Cohesion: 0.05
Nodes (15): _Response, TestOauthSuccessInterception, TestPkceUrlParity, TestStateReset, TestTokenUaSplit, fake_post(), fake_post(), _Client (+7 more)

### Community 151 - "ProxyController"
Cohesion: 0.07
Nodes (4): ControllerConfig, ProxyController, _write(), test_transport_property_maps_versions()

### Community 153 - "_preflight_interactive_auth"
Cohesion: 0.28
Nodes (3): _get_token_path(), _preflight_interactive_auth(), TestPreflightInteractiveAuth

### Community 159 - "TestLiveBypassRoutes"
Cohesion: 0.14
Nodes (3): TestEstablishedEndpointProtection, TestLiveBypassRoutes, boom()

### Community 168 - "ProxyError"
Cohesion: 0.11
Nodes (9): _is_ip_literal(), ProxyError, _format_authority(), H2ProxySession, _probe(), _read_response_headers(), _urltest_request_for(), _connect_pair() (+1 more)

### Community 175 - "TestTunHelperNativeStubs"
Cohesion: 0.20
Nodes (3): TestTunHelperNativeStubs, TestWsl2CarveOut, boom()

### Community 189 - "_adapter_rows"
Cohesion: 0.18
Nodes (9): buf(), _adapter_rows(), _write_chain(), _write_string(), test_adapter_present_native_matches_guid_and_name(), test_parse_adapter_buffer_basic_fields(), test_parse_adapter_buffer_down_status_text(), test_parse_adapter_buffer_stops_on_zero_length() (+1 more)

### Community 192 - "detect_competing_tunnel"
Cohesion: 0.24
Nodes (3): detect_competing_tunnel(), TestCompetingTunnelPreflight, fake_pre_start()

### Community 199 - "_run_in_api_pool"
Cohesion: 0.31
Nodes (3): RelayerTestRequest, test_relayer_latency(), TestRelayerTestEndpoint

### Community 201 - "_FakeWindow"
Cohesion: 0.17
Nodes (6): _FakeWindow, test_a_tray_that_cannot_start_leaves_the_x_button_alone(), test_close_hides_the_window_instead_of_quitting(), test_tray_menu_label_follows_the_api_state(), test_tray_open_restores_the_hidden_window(), test_tray_quit_closes_the_window_and_allows_it()

### Community 208 - "test_http_client_rebuild_race.py"
Cohesion: 0.21
Nodes (6): _isolate_shared_client(), _patch_mock_build(), fake_build(), test_rebuild_does_not_kill_in_flight_request(), test_rebuild_twice_keeps_each_in_flight_request_alive(), handler()

### Community 210 - "server"
Cohesion: 0.50
Nodes (3): mock_pool(), server(), fake_start_api_server()

### Community 212 - "launch_webview"
Cohesion: 0.09
Nodes (3): FakeServer, FakeThread, TestLaunchWebviewShutdown

### Community 220 - "test_physical_bootstrap.py"
Cohesion: 0.12
Nodes (12): _app(), _reset_http_client(), _reset_https_and_overrides(), test_activation_installs_the_proxy_pin_and_tightens_the_controller(), test_bootstrap_fails_closed_when_the_guardian_cannot_be_resolved(), test_bootstrap_fails_closed_without_a_physical_egress(), test_bootstrap_is_a_no_op_off_windows(), test_bootstrap_pins_both_endpoints_and_defers_binding_to_the_caller() (+4 more)

### Community 221 - "test_tun_frontend.py"
Cohesion: 0.11
Nodes (9): _disable_default_recovery_gate(), _sleep_proc_args(), TestDisabledByDefault, TestOptInAndElevation, TestOrderlyShutdown, TestOutputCaptureBounded, TestStartupFailure, TestStopRequiresProvenDeathRetention (+1 more)

### Community 226 - "tun_status.py"
Cohesion: 0.09
Nodes (9): _default_egress(), _direct_https_trace(), _direct_tcp_probe(), _parse_trace(), probe_system_egress(), probe_system_egress_identity(), wait_for_system_egress(), TestEgressProbe (+1 more)

### Community 240 - "app.py"
Cohesion: 0.06
Nodes (12): configure_logger(), _JsonFormatter, parse_log_format(), parse_log_level(), _rfc3339_timestamp(), _TextFormatter, _is_singbox_name(), _is_windows() (+4 more)

### Community 244 - "perchvpn_windows/cli.py"
Cohesion: 0.10
Nodes (10): build_parser(), main(), run_app(), _parse_listen(), _run_app(), _run_app_with_shutdown(), _validate_args(), ensure_interactive_console() (+2 more)

### Community 247 - "account_signin"
Cohesion: 0.10
Nodes (15): account_signin(), account_verify(), _normalize_verification_method(), SigninRequest, VerifyRequest, _app_mock(), _reset_signin_state(), TestCredentialHygiene (+7 more)

### Community 259 - "capture_snapshot_batched"
Cohesion: 0.16
Nodes (7): _batched_payload(), _pins_app(), _run_batched_with(), TestBatchedSnapshotCapture, __call__(), TestParallelControlPlanePins, slow_physical()

### Community 269 - "_FakeEvent"
Cohesion: 0.22
Nodes (4): backend(), _FakeEvent, tray_env(), __init__()

### Community 272 - "test_tray_toggle_posts_connect_when_idle"
Cohesion: 0.20
Nodes (3): test_tray_toggle_posts_connect_when_idle(), test_tray_toggle_posts_disconnect_when_connected(), _urlopen()

### Community 282 - "TransportOptions"
Cohesion: 0.13
Nodes (7): _flush_outgoing(), fragment_bytes(), packet_segments(), split_tls_records(), TransportOptions, TestFragmentBytes, TestTlsRecordSplitting

### Community 294 - "fixture"
Cohesion: 0.20
Nodes (5): no_metrics(), install_dir(), _fake_frontend_ps(), windows_startupinfo(), _reset_ws_globals()

## Knowledge Gaps
- **1 isolated node(s):** `perchvpn-windows`
  These have ≤1 connection - possible missing edges. (Counts symbols only; 2022 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **121 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `WindowsConfig` connect `WindowsConfig` to `get_urltest`, `test_tun_recovery.py`, `._start_tun_helper`, `set_country`, `test_runtime_fixes.py`, `PerchVPNApp`, `oauth_complete`, `_app`, `_guardian_quota_fetch`, `test_country_hot_swap.py`, `platform.py`, `api.py`, `test_api_mode_urlping.py`, `test_account_lifecycle.py`, `TunFrontend`, `pytest`, `test_status_presentation.py`, `test_lifecycle.py`, `test_physical_egress.py`, `config.py`, `_stub_build_status`, `set_connection_mode`, `TestExitVerificationStateTransitions`, `app.py`, `ProxyCandidate`, `perchvpn_windows/cli.py`, `account_signin`, `Socks5Server`?**
  _High betweenness centrality (0.059) - this node is a cross-community bridge._
- **Are the 44 inferred relationships involving `WindowsConfig` (e.g. with `test_load_persisted_auth_disabled_during_logout()` and `test_load_persisted_auth_failed_credentials_not_installed()`) actually correct?**
  _`WindowsConfig` has 44 INFERRED edges - model-reasoned connections that need verification._
- **What connects `perchvpn-windows` to the rest of the system?**
  _1 weakly-connected nodes found - possible missing edges._
- **Should `test_install_path_parity.py` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._
- **Why does `TunFrontend` connect `TunFrontend` to `test_tun_recovery.py`, `._start_tun_helper`, `TestEnforceAdapterMetric`, `test_tun_graceful_shutdown.py`, `test_tun_recovery.py`, `TestIdentitySettleAndRetry`, `PerchVPNApp`, `client_e2e.py`, `._track_egress_stall`, `.test_recoverable_orphan_is_reconciled_then_spawned`, `api.py`, `detect_competing_tunnel`, `.reconcile`, `.start`, `test_tun_frontend.py`, `FakeProcess`, `_FakeProc`, `test_tun_diagnostic_fixes.py`, `app.py`, `iphelper.py`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Are the 38 inferred relationships involving `PerchVPNApp` (e.g. with `TunFrontend` and `test_load_persisted_auth_disabled_during_logout()`) actually correct?**
  _`PerchVPNApp` has 38 INFERRED edges - model-reasoned connections that need verification._
- **Should `get_urltest` be split into smaller, more focused modules?**
  _Cohesion score 0.06259426847662142 - nodes in this community are weakly interconnected._