# Graph Report - foxyvpn-windows  (2026-11-22)

## Corpus Check
- 174 files · ~247,904 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 8 file(s) not represented in the graph (top: (none) 3, .ico 2, .wxs 1)

## Summary
- 5569 nodes · 13102 edges · 289 communities (142 shown, 147 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 1274 edges (avg confidence: 0.87)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `33197956`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- test_pool_churn_and_fallback.py
- _get_urltest_raw_token
- relayer.py
- fxa.py
- TestGateVerification
- H3ProxySession
- layout_check.py
- _FakeWindll
- Dashboard
- TunRecoveryGate
- test_tun_graceful_shutdown.py
- AdapterEvidence
- test_tun_recovery.py
- SessionPool
- account_signin
- pytest
- test_runtime_fixes.py
- _read
- oauth_complete
- tun_state_capture.py
- Any
- http_client.py
- test_winconsole.py
- _app
- HttpProxyServer
- WindowsConfig
- _cached_countries
- NetworkSnapshot
- _guardian_quota_fetch
- tun_recovery.py
- test_country_hot_swap.py
- test_tun_helper.py
- TestRunHelper
- webview.py
- H2ProxySession
- _FakeClock
- socket
- upstream_proxy.py
- PerchVPNApp
- _phase3_h1
- _read
- detect_physical_ipv4
- RuntimeAuth
- oauth.py
- Socks5Server
- httpx
- test_physical_dns_doh.py
- FakeHostRoutes
- test_candidate_failover.py
- test_latency_probe.py
- build_config
- .from_dict
- TestGuardianQuotaRemaining
- Socks5Frontend
- fastly.py
- test_win_process.py
- exitcheck.py
- _spec
- PhysicalDnsError
- test_api_mode_urlping.py
- _record
- test_physical_dns.py
- test_account_lifecycle.py
- physical_dns.py
- TunFrontend
- test_fxa_antibot.py
- _dispatch
- test_status_presentation.py
- test_resolver_dns.py
- perchvpn/cli.py
- ipaddress
- H2Stream
- test_lifecycle.py
- MockUpstreamStream
- .emit
- test_fxa_login_v2.py
- get_urltest
- test_physical_egress.py
- test_live_physical_preflight.py
- Get-ForeignTunnelSnapshot
- doh_resolver.py
- config.py
- _read
- test_iphelper_native.py
- proxystate.py
- httpx
- env
- _FakeSocket
- NetworkConfig
- TunHelperClient
- _stub_build_status
- ._dial
- test_fastly_solver.py
- adapters_native
- FakeProcess
- TestEnforceAdapterMetric
- _FakeProc
- tun_trial_runner.py
- test_tun_state_capture.py
- TestBuildConfig
- TestExitVerificationStateTransitions
- test_web_mode_perf.py
- SocksRelay
- ._handle_client_or_raise
- _socks_ready
- typing
- test_tun_diagnostic_fixes.py
- api.py
- iphelper.py
- obtain_auth
- ProxyCandidate
- .test_changed_answer_is_pinned_before_the_dial_override_changes
- _phase3_api
- test_upstream_proxy_pin.py
- fetch_server_list
- TestRunPsWriteSemantics
- StateDifference
- threading
- .prepare
- TestAuthOnlyHelperAttachesConsole
- build_parser
- TestStateResolutionMapping
- probe_system_egress
- test_e2e_split_routes.py
- tokens.py
- TestCliSurface
- asyncio
- h3_session.py
- DoHResolver
- TestNodeStatusContractHarness
- app.js
- TestControllerPassReuse
- _FakeApp
- .__init__
- _rule
- tun_helper.py
- _FakeSocket
- ui_status_from_controller
- TrafficMetrics
- TestIdentitySettleAndRetry
- set_country
- test_tun_perf.py
- _DyingSession
- test_fxa_identity.py
- _Client
- ProxyController
- setTextIfChanged
- _parse_probe
- set_country
- TestNetworkRequestValidation
- test_singbox_config.py
- FakeController
- ._client
- .test_unexpected_sidecar_exit_is_reported_as_failure
- .test_recoverable_orphan_is_reconciled_then_spawned
- _authorized_request
- TestParitySettingsControls
- status-contract.js
- _FakeH2Session
- probe_adapter
- _KeepAliveSession
- test_singbox_config.py
- TestStaleWintunCleanup
- TestCountryListRendering
- country-sort.js
- TestTunHelperNativeStubs
- configure_client_hello
- FakeSession
- perchvpn-windows
- test_verify_exit_country_normalizes_socks5_to_socks5h
- perchvpn
- CoexistenceError
- _tls_context
- DiagnosticsBuffer
- TestStatusWebSocketPush
- capture_adapter_dns
- SessionTokenPool
- TestConnectionButtonSignedOutFlow
- split_route_evidence
- TestDatapathParityControls
- RelayerTestRequest
- redact
- _FakeSocket
- .from_dict
- TrialJournal
- ._app
- TestResolveDeadline
- test_adapters_native_resizes_from_needed_value
- _ImmutableAssets
- TestUnifiedDelaySweep
- test_http_client_rebuild_race.py
- .loadCountries
- ._wire
- TestRecoveryProbeFallback
- find_route_interface
- get_token_path
- reconcile_stale_ownership
- _LogCaptureHandler
- test_physical_bootstrap.py
- test_tun_frontend.py
- _panel
- test_fxa_pkce.py
- TestPhysicalResolutionPath
- TestDashboardStackedInfoRows
- test_set_interface_metric_uses_zero_site_prefix_length
- app.py
- .test_permanent_rejection_falls_back_to_login
- TestMixedPortSelection
- _RecordingSession
- httpx
- websocket_logs
- PerchVPNApp
- test_web_structure.py
- TestWsl2Routing
- _FakeSocket
- TestHttpClientPinning
- TokenResponse
- TestWindowedAuthFlow
- TestWebAssetResolution
- split_tls_records
- TestRecoveryOwnership
- test_restart_task_cancellation_completes_old_shutdown
- test_status_reports_connecting_while_background_init_running
- test_shell_execute_runas_quotes_spec_path_with_spaces
- TestRecoverCli
- buf

## God Nodes (most connected - your core abstractions)
1. `WindowsConfig` - 184 edges
2. `PerchVPNApp` - 144 edges
3. `PerchVPNApp` - 139 edges
4. `TunFrontend` - 124 edges
5. `NetworkSnapshot` - 78 edges
6. `_gate()` - 60 edges
7. `SessionPool` - 55 edges
8. `TunRecoveryGate` - 54 edges
9. `NetworkConfig` - 54 edges
10. `ProxyError` - 51 edges

## Surprising Connections (you probably didn't know these)
- `initialize()` --calls--> `TokenInvalidError`  [INFERRED]
  tests/test_lifecycle.py → src/perchvpn/exceptions.py
- `boom()` --calls--> `CaptureError`  [INFERRED]
  tests/test_physical_egress.py → src/perchvpn_windows/tun_state_capture.py
- `failing_capture()` --calls--> `CaptureError`  [INFERRED]
  tests/test_tun_recovery.py → src/perchvpn_windows/tun_state_capture.py
- `fake_exchange()` --calls--> `FxaApiError`  [INFERRED]
  tests/test_fxa_antibot.py → src/perchvpn/exceptions.py
- `connect()` --calls--> `ProxyError`  [INFERRED]
  tests/test_candidate_failover.py → src/perchvpn/exceptions.py

## Import Cycles
- 3-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_frontend.py -> src/perchvpn_windows/__init__.py`
- 3-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_helper.py -> src/perchvpn_windows/__init__.py`
- 4-file cycle: `src/perchvpn_windows/__init__.py -> src/perchvpn_windows/app.py -> src/perchvpn_windows/tun_frontend.py -> src/perchvpn_windows/tun_helper.py -> src/perchvpn_windows/__init__.py`

## Communities (289 total, 147 thin omitted)

### Community 0 - "test_pool_churn_and_fallback.py"
Cohesion: 0.15
Nodes (14): _is_quic_timeout(), _affinity_with_hash_mod(), _bare_controller(), _controller_config(), _FakePool, test_close_storm_falls_back_to_http2_and_repoints_frontend(), on_pool_replaced(), test_fallback_failure_keeps_the_current_pool() (+6 more)

### Community 1 - "_get_urltest_raw_token"
Cohesion: 0.11
Nodes (10): _get_urltest_raw_token(), _remember_failure(), _pass_ttl_seconds(), _app_with_auth(), _reset_globals(), TestPassFetchNegativeCache, _fetch(), _fetch() (+2 more)

### Community 2 - "relayer.py"
Cohesion: 0.06
Nodes (22): build_relayer_url(), candidate_relayers(), configure(), current_state(), _direct_request(), match_category(), measure_relayer_rtt(), RelayerState (+14 more)

### Community 3 - "fxa.py"
Cohesion: 0.07
Nodes (30): verify_with_code(), FxaApiError, FxaUnblockCodeRequired, authorization_code_from_session(), CredentialStatus, _derive_auth_pw(), _derive_auth_pw_v2(), _derive_hawk_credentials() (+22 more)

### Community 5 - "H3ProxySession"
Cohesion: 0.05
Nodes (8): ProxyError, _format_authority(), _H3ClientProtocol, H3ProxySession, create_protocol(), H3Stream, _PinnedQuicConnect, _read_response_headers()

### Community 6 - "layout_check.py"
Cohesion: 0.09
Nodes (16): build_harness(), evaluate(), main(), run_size(), windows_path(), _run(), test_ascending_with_ties_and_unavailable_last(), test_missing_invalid_and_non_positive_are_unavailable() (+8 more)

### Community 7 - "_FakeWindll"
Cohesion: 0.17
Nodes (3): fake_windll(), _FakeCfunc, _FakeWindll

### Community 8 - "Dashboard"
Cohesion: 0.07
Nodes (12): _c(), Dashboard, DashboardData, demo(), _fmt_bytes(), _fmt_speed(), _fmt_uptime(), _pad() (+4 more)

### Community 9 - "TunRecoveryGate"
Cohesion: 0.09
Nodes (9): RecoveryRun, RecoveryUnverified, TunRecoveryGate, _without_transient_trial_adapter(), _identity(), executor(), failing_capture(), TestPreStartParallelStep (+1 more)

### Community 10 - "test_tun_graceful_shutdown.py"
Cohesion: 0.08
Nodes (28): _BlockingProcess, _ExitedProcess, _fake_frontend_ps(), _frontend(), _GracefulProcess, _identity(), _recovery_gate_and_run(), _no_sleep() (+20 more)

### Community 11 - "AdapterEvidence"
Cohesion: 0.13
Nodes (4): _default_probe(), AdapterEvidence, classify(), TestClassification

### Community 12 - "test_tun_recovery.py"
Cohesion: 0.11
Nodes (8): TestTunShutdownOwnership, _capture_of(), _FakeProcess, _frontend(), _sequence_capture(), TestBaselineRestoration, TestFrontendGate, failing_write()

### Community 13 - "SessionPool"
Cohesion: 0.15
Nodes (15): SessionPool, refuse(), test_born_dead_growth_dial_records_close_event(), test_dead_session_open_stream_records_close_and_retries(), test_four_edge_kills_trip_the_close_storm(), test_growth_dials_share_the_gate(), test_replacement_dials_are_rate_limited(), factory() (+7 more)

### Community 14 - "account_signin"
Cohesion: 0.08
Nodes (19): account_signin(), account_verify(), SigninRequest, VerifyRequest, reset_oauth_flow(), TestSessionTokenImport, fake_exchange(), fake_exchange() (+11 more)

### Community 15 - "pytest"
Cohesion: 0.04
Nodes (20): lifespan(), _shutdown(), TestAccountUiWiring, test_config_rejects_nonloopback_http_proxy_bind(), test_config_wildcard_http_proxy_bind_requires_auth(), _reset_signin_state(), _reset_flow(), TestFrontendWiring (+12 more)

### Community 16 - "test_runtime_fixes.py"
Cohesion: 0.09
Nodes (9): broadcast_log(), test_broadcast_log_handles_concurrent_set_changes(), test_broadcast_log_prunes_failed_clients(), test_lifespan_runs_startup_and_shutdown(), test_quota_monitor_calls_synchronous_fetch_user_info(), test_restart_refreshes_global_config(), test_shutdown_stops_tun_sidecar_before_controller(), test_startup_initializes_app_and_shutdown_cleans_up() (+1 more)

### Community 17 - "_read"
Cohesion: 0.26
Nodes (3): _read(), TestRenderingPerformance, TestTacticalRadar

### Community 18 - "oauth_complete"
Cohesion: 0.17
Nodes (12): oauth_complete(), OAuthCompleteRequest, cancel_oauth_flow(), get_flow(), start_oauth_flow(), _app_mock(), _callback_url(), TestCallbackSecurity (+4 more)

### Community 19 - "tun_state_capture.py"
Cohesion: 0.08
Nodes (23): capture_adapters(), capture_dns(), capture_interface_config(), capture_ip_addresses(), capture_routes(), capture_snapshot(), capture_snapshot_batched(), capture_snapshot_native() (+15 more)

### Community 20 - "Any"
Cohesion: 0.16
Nodes (29): as_list(), curl_get(), dns_packet(), dns_query_tcp(), dns_query_udp(), http_get(), https_get(), main() (+21 more)

### Community 21 - "http_client.py"
Cohesion: 0.08
Nodes (16): DoHTransport, _build_client(), control_plane_proxy_url(), _env_proxy_url(), get_async_client(), _local_addr_kwargs(), _normalize_proxy_url(), physical_interface_socket_options() (+8 more)

### Community 22 - "test_winconsole.py"
Cohesion: 0.10
Nodes (6): fake_win32(), _FakeKernel32, _reset_std_streams(), TestEnsureInteractiveConsole, TestRestoreStreams, TestWebviewReExports

### Community 23 - "_app"
Cohesion: 0.08
Nodes (8): _app(), FakeHelper, _ready_frontend(), TestApplyMode, start_helper(), TestBeginModeApply, TestLocalSocksPrerequisite, TestResolveTunExecutable

### Community 24 - "HttpProxyServer"
Cohesion: 0.23
Nodes (8): HttpProxyServer, test_api_rejects_nonloopback_http_proxy_bind(), test_http_proxy_binds_and_rejects_without_session(), test_http_proxy_stop_terminates_active_connect_tunnel(), test_loopback_bind_accepted(), test_nonloopback_bind_rejected(), test_wildcard_bind_accepted_with_local_proxy_auth(), test_wildcard_bind_rejected()

### Community 25 - "WindowsConfig"
Cohesion: 0.06
Nodes (11): InteractiveLoginRequired, WindowsConfig, TestEffectiveUseHttp3, TestParityDefaults, TestParityValidation, TestTlsFragmentParity, TestUpdateVersionCompare, TestWindowsConfigDefaults (+3 more)

### Community 26 - "_cached_countries"
Cohesion: 0.11
Nodes (7): CountryResponse, _filter_country_response(), get_countries(), _country(), _reset_globals(), TestCountriesCache, _fetch()

### Community 27 - "NetworkSnapshot"
Cohesion: 0.13
Nodes (6): compare_snapshots(), NetworkSnapshot, TestCompareSnapshotsValidation, TestPartitionDiffsTproxyOwnership, TestStateCapture, _snap()

### Community 28 - "_guardian_quota_fetch"
Cohesion: 0.12
Nodes (12): get_account_quota(), _guardian_quota_fetch(), _quota_error_response(), _quota_token_key(), QuotaResponse, _app_mock(), TestQuotaCaching, fake_user_info() (+4 more)

### Community 29 - "tun_recovery.py"
Cohesion: 0.07
Nodes (17): available(), established_remote_endpoints(), _accepts_require_up(), _boot_time(), _default_adapter_probe(), _default_creation_time(), _posix_creation_time(), _powershell_adapter_probe() (+9 more)

### Community 30 - "test_country_hot_swap.py"
Cohesion: 0.14
Nodes (10): _app(), _clean_instances(), FakeFrontend, FakeTunHelper, _patch_switch_deps(), _target(), TestHotSwap, TestHotSwapPinsBeforeDial (+2 more)

### Community 31 - "test_tun_helper.py"
Cohesion: 0.15
Nodes (10): _adapter(), _default_route(), _iface(), _ip(), _snapshot(), TestAdapterReusePlan, TestConflictDetection, TestPhysicalSelection (+2 more)

### Community 32 - "TestRunHelper"
Cohesion: 0.09
Nodes (18): _evidence(), TestActivationSafety, probe(), probe(), probe(), probe(), TestRunHelper, do_spawn() (+10 more)

### Community 33 - "webview.py"
Cohesion: 0.06
Nodes (5): TestRunAuthFlow, TestRunAuthOnly, TestSpawnAuthHelper, TestWaitForTokenReady, TestWebViewAuthFlow

### Community 34 - "H2ProxySession"
Cohesion: 0.07
Nodes (9): H2ProxySession, _probe(), _urltest_request_for(), _client_with_remote_max(), _FakeConn, _NullWriter, TestH2StreamSlot, TestH2StreamSlotConcurrency (+1 more)

### Community 35 - "_FakeClock"
Cohesion: 0.18
Nodes (6): _factory_ok(), _FakeClock, test_close_storm_fires_once_within_renotify_window(), on_storm(), test_scattered_closes_do_not_signal_storm(), test_storm_callback_failure_does_not_break_serving()

### Community 36 - "socket"
Cohesion: 0.06
Nodes (17): _dial_direct(), _flush_outgoing(), _format_authority(), H1ProxySession, H1Stream, _handshake_sync(), _tls_context(), fragment_bytes() (+9 more)

### Community 38 - "upstream_proxy.py"
Cohesion: 0.22
Nodes (8): _apply_physical_interface(), _apply_source_bind(), _connect_http(), _connect_socks5(), connect_through_upstream_proxy(), _proxy_connection_target(), _recv_exact(), UpstreamProxyError

### Community 40 - "_phase3_h1"
Cohesion: 0.15
Nodes (5): add_check(), _e2e_cert_paths(), _e2e_h1_tls_context(), _phase3_h1(), TlsConnectProxy

### Community 41 - "_read"
Cohesion: 0.11
Nodes (6): _read(), TestAllowanceGauge, TestLiveLogsUI, TestNoRegression, TestRadarMarkup, TestRadarStateLogic

### Community 42 - "detect_physical_ipv4"
Cohesion: 0.32
Nodes (4): detect_physical_ipv4(), _snapshot(), TestDetectPhysicalIpv4, boom()

### Community 43 - "RuntimeAuth"
Cohesion: 0.11
Nodes (15): AccessTokenExpiredError, refresh_runtime_auth(), RuntimeAuth, TestRefreshFailureClassification, _Clock, _controller(), TestControllerEnsureFresh, refresh() (+7 more)

### Community 44 - "oauth.py"
Cohesion: 0.09
Nodes (16): build_authorization_url(), _begin_flow(), _begin_guardian_flow(), _CallbackServer, _generate_pkce(), oauth_flow_status(), open_authorization_url(), _parse_query() (+8 more)

### Community 45 - "Socks5Server"
Cohesion: 0.05
Nodes (18): Socks5Server, _connect_rep(), _make_server(), _negotiate(), test_502_refusal_does_not_break_other_targets_on_same_port(), test_502_refusal_trips_per_target_breaker(), test_custom_upstream_disables_port_gating(), test_disconnect_cancels_in_flight_restart_task() (+10 more)

### Community 46 - "httpx"
Cohesion: 0.17
Nodes (11): _adapt_egress_for_sandbox(), _adapt_recovery_probe_for_sandbox(), patient(), ghost_present_count(), main(), transit_probe(), parse_cloudflare_trace(), route_snapshot() (+3 more)

### Community 47 - "test_physical_dns_doh.py"
Cohesion: 0.21
Nodes (25): query_doh_ipv4(), _fake_network(), _http(), _http_with(), _name(), _response(), _set_platform(), test_doh_endpoint_uses_canonical_sni_and_host() (+17 more)

### Community 49 - "test_candidate_failover.py"
Cohesion: 0.10
Nodes (16): alternate_candidates(), _candidate(), _controller(), _countries(), _fake_pass(), FakeSession, TestAlternateCandidates, TestControllerFailover (+8 more)

### Community 50 - "test_latency_probe.py"
Cohesion: 0.11
Nodes (13): get_latency(), _FakeWriter, test_latency_ipv4_validated(), test_latency_link_local_rejected(), test_latency_loopback_rejected(), test_latency_mixed_dns_answers_rejected(), test_latency_private_rejected(), test_latency_success_against_public_destination() (+5 more)

### Community 51 - "build_config"
Cohesion: 0.11
Nodes (6): build_config(), TestIpModeParity, TestKillSwitch, TestLocalNetworkBypass, TestLocalProxyAuth, TestUtlsParity

### Community 52 - ".from_dict"
Cohesion: 0.13
Nodes (5): teardown_trial(), TrialConfig, TrialRunner, _capture(), TestTrialRunnerTeardown

### Community 55 - "fastly.py"
Cohesion: 0.12
Nodes (16): FastlyChallengeError, _answer_challenge(), _base_origin(), _browser_session(), _client_metrics_answer(), _fetch_pat(), _install_challenge_cookies(), _NoChallengePage (+8 more)

### Community 56 - "test_win_process.py"
Cohesion: 0.14
Nodes (7): _FakeStartupInfo, test_popen_hidden_forwards_hidden_launch_parameters(), test_run_hidden_forwards_hidden_launch_parameters(), fake_run(), test_stale_wintun_removal_uses_hidden_pnputil(), test_terminate_pid_uses_hidden_taskkill(), windows_startupinfo()

### Community 57 - "exitcheck.py"
Cohesion: 0.19
Nodes (7): _extract_json_fields(), _extract_trace_fields(), _first_nonempty(), _json_string(), _parse_exit_probe_response(), _read_capped(), verify_exit_country()

### Community 58 - "_spec"
Cohesion: 0.11
Nodes (5): FakeClock, _spec(), TestSidecarCommand, TestTunHelperClient, launcher()

### Community 59 - "PhysicalDnsError"
Cohesion: 0.14
Nodes (18): PhysicalDnsError, resolve_ipv4(), _doh_result(), test_resolve_does_not_fall_back_after_later_authoritative_error(), doh(), query(), test_resolve_does_not_fall_back_on_dns_errors(), test_resolve_fails_closed_when_doh_also_fails() (+10 more)

### Community 60 - "test_api_mode_urlping.py"
Cohesion: 0.06
Nodes (14): _app_can_apply_mode(), ConnectionModeRequest, set_connection_mode(), url_ping(), UrlPingRequest, _FakeAsyncClient, _FakeResponse, _FakeStreamCtx (+6 more)

### Community 61 - "_record"
Cohesion: 0.07
Nodes (10): _drifted_snapshot_dict(), _gate(), _record(), _snapshot_dict(), TestGatePreStart, executor(), TestNetworkBaseline, probe() (+2 more)

### Community 62 - "test_physical_dns.py"
Cohesion: 0.32
Nodes (12): parse_response(), _a(), _name(), _response(), _rr(), test_build_query_encodes_recursive_a_record(), test_parse_follows_in_response_cname_chain(), test_parse_rejects_answer_for_another_name() (+4 more)

### Community 63 - "test_account_lifecycle.py"
Cohesion: 0.22
Nodes (14): test_account_logout_failure_does_not_report_success(), test_account_logout_success(), test_load_persisted_auth_disabled_during_logout(), test_load_persisted_auth_failed_credentials_not_installed(), test_load_persisted_auth_failed_then_retry_succeeds(), test_load_persisted_auth_rejects_invalid(), test_load_persisted_auth_serializes_concurrent_handoff(), test_load_persisted_auth_success() (+6 more)

### Community 64 - "physical_dns.py"
Cohesion: 0.10
Nodes (12): _bind_physical_interface(), build_query(), _decode_name(), _doh_fallback_reason(), _encode_name(), _query_doh_endpoint(), _read_doh_body(), _validated_ipv4_endpoints() (+4 more)

### Community 65 - "TunFrontend"
Cohesion: 0.06
Nodes (8): _check_tun_prerequisites(), TunFrontend, TestBuildCommand, TestBuildCommandBypass, TestCaptureLimits, TestIdempotencyAndMtu, TestResolveExecutable, TestAdaptiveReconcileCadence

### Community 66 - "test_fxa_antibot.py"
Cohesion: 0.18
Nodes (4): _FakeClient, _FakeResponse, TestMetricsFlow, TestUnblockCode

### Community 67 - "_dispatch"
Cohesion: 0.11
Nodes (6): acquire(), release(), _dispatch(), _helper_spec(), TestEntrypointDashboardDispatch, TestEntrypointDispatch

### Community 68 - "test_status_presentation.py"
Cohesion: 0.08
Nodes (13): _FakeMetrics, _get_status(), _make_app_pair(), TestCanonicalTunStatusContract, TestControllerReasonTranslation, TestStatusConnectedExitVerificationFailed, TestStatusConnectedExitVerificationNotApplicable, TestStatusConnectedExitVerificationPending (+5 more)

### Community 69 - "test_resolver_dns.py"
Cohesion: 0.13
Nodes (11): test_authorized_request_dials_only_the_verified_pin(), _dns_response(), FakeClient, FakeResponse, test_automatic_fails_closed_on_total_failure(), test_custom_resolver_requires_ip(), test_http_client_uses_certificate_verification(), __init__() (+3 more)

### Community 70 - "perchvpn/cli.py"
Cohesion: 0.13
Nodes (9): version_string(), _async_main(), build_parser(), _format_socks_authority(), _install_benign_future_exception_filter(), main(), _parse_listen(), _validate_args() (+1 more)

### Community 71 - "ipaddress"
Cohesion: 0.17
Nodes (10): available_mixed_port(), _custom_doh_endpoint(), dumps_config(), _exclude_addresses(), excluded_networks(), _normalize_cidr(), tunnel_dns_endpoint(), validate_config() (+2 more)

### Community 72 - "H2Stream"
Cohesion: 0.07
Nodes (8): _pump_client_to_upstream(), _pump_upstream_to_client(), relay_bidirectional(), H2Stream, FakeConn, _noop_read_loop(), _session(), TestOpenStreamTimeout

### Community 73 - "test_lifecycle.py"
Cohesion: 0.05
Nodes (12): _apply_mode_flags(), restart(), _make_app(), _set_app(), TestDisconnect, TestDnsCacheInitialization, TestInitializationFailure, TestInitializationMetricsWiring (+4 more)

### Community 74 - "MockUpstreamStream"
Cohesion: 0.10
Nodes (5): MockReader, MockUpstreamStream, MockWriter, TestFrontendLifecycle, TestRelayBidirectional

### Community 76 - "test_fxa_login_v2.py"
Cohesion: 0.08
Nodes (9): _normalize_verification_method(), _hkdf_auth_pw(), _Response, _RoutedClient, TestCredentialStatusSelection, TestEdgeBlockMessage, TestKeyStretching, TestResendEndpoint (+1 more)

### Community 77 - "get_urltest"
Cohesion: 0.17
Nodes (3): get_urltest(), TestUrlTestEndpoint, TestTwoStageUnifiedDelay

### Community 78 - "test_physical_egress.py"
Cohesion: 0.11
Nodes (9): _controller_config(), test_control_plane_bypass_ips_falls_back_to_cached_ip(), test_control_plane_bypass_ips_times_out_and_falls_back_to_os(), TestControllerWiring, slow_physical(), TestEdgeHostPins, TestH3SourceBind, TestStartupPhysicalPreflight (+1 more)

### Community 79 - "test_live_physical_preflight.py"
Cohesion: 0.08
Nodes (29): _adapter_bytes(), _bind_physical(), _bulk_download(), _burst(), _decode_unicast_if(), _discover_tunnel_adapter(), _discover_wifi_index(), _discover_wifi_ipv4() (+21 more)

### Community 80 - "Get-ForeignTunnelSnapshot"
Cohesion: 0.19
Nodes (14): Add-Check(), Compare-ForeignTunnelSnapshots(), Get-ForeignTunnelSnapshot(), Get-PhysicalLayout(), Invoke-Api(), Save-Report(), Test-GeneralConnectivity(), Get-DnsClientServerAddress() (+6 more)

### Community 81 - "doh_resolver.py"
Cohesion: 0.17
Nodes (14): _build_query(), _cache_key(), _cache_lookup(), _cache_store(), dns_cache_stats(), _local_addr_kwargs(), _parse_answers(), _parse_answers_with_ttl() (+6 more)

### Community 82 - "config.py"
Cohesion: 0.08
Nodes (26): _restart_worker(), set_network_config(), _config_path(), _CRYPT_INTEGER_BLOB, _cryptprotect(), _cryptunprotect(), _decrypt_password(), _encrypt_password() (+18 more)

### Community 83 - "_read"
Cohesion: 0.18
Nodes (5): _read(), TestAuthStateAfterSignIn, TestOnboardingPromptMarkup, TestOnboardingVisibilityLogic, TestSignedOutLatencyGating

### Community 84 - "test_iphelper_native.py"
Cohesion: 0.10
Nodes (14): _adapter_rows(), _sockaddr_v4(), socket_inet_pton(), socket_inet_pton6(), test_adapter_present_native_matches_guid_and_name(), test_dll_sentinel_initialised_at_module_level(), test_dns_servers_native_groups_by_family(), test_interface_entry_false_values_rejected() (+6 more)

### Community 85 - "proxystate.py"
Cohesion: 0.16
Nodes (9): _initial_dial_backoff(), available_country_codes(), _candidates_for_country(), _default_connect_protocol(), _parse_host_port(), _PersistedState, ProxyStateStore, resolve_proxy() (+1 more)

### Community 87 - "httpx"
Cohesion: 0.09
Nodes (3): _wait_for_api_ready(), TestWaitForApiReadyProxyOnly, TestWaitForApiReady

### Community 88 - "env"
Cohesion: 0.05
Nodes (36): defaults, runs-on, steps, timeout-minutes, run, env, GH_TOKEN, MANUFACTURER (+28 more)

### Community 89 - "_FakeSocket"
Cohesion: 0.11
Nodes (6): context(), factory(), _FakeContext, _FakeSocket, _FakeTLS, factory()

### Community 90 - "NetworkConfig"
Cohesion: 0.11
Nodes (6): NetworkConfig, TestTlsFragmentApiFields, test_network_config_accepts_lan_bind(), test_network_config_lan_bind_with_http_proxy(), test_network_config_relayer_pair_validation(), test_upstream_proxy_validation_requires_host_when_enabled()

### Community 93 - "_stub_build_status"
Cohesion: 0.06
Nodes (28): broadcast_status(), _build_status_response(), _ensure_status_monitor(), get_status(), notify_status_changed(), _push_now(), _push_status_frame(), _status_metrics_signature() (+20 more)

### Community 94 - "._dial"
Cohesion: 0.09
Nodes (3): FakeWriter, TestH2SourceBindDial, fake_open_connection()

### Community 95 - "test_fastly_solver.py"
Cohesion: 0.22
Nodes (5): _FakeSession, _pow_data(), _Resp, test_api_host_406_falls_through_and_cookies_are_installed(), test_captcha_challenge_raises_clear_error()

### Community 96 - "adapters_native"
Cohesion: 0.17
Nodes (6): adapter_present_native(), adapters_native(), unicast_native(), virtual_nat_subnets_native(), _wsl2_exclude_addresses(), _native_adapter_evidence()

### Community 98 - "TestEnforceAdapterMetric"
Cohesion: 0.27
Nodes (3): TestEnforceAdapterMetric, fake_write(), TestEnforceSplitRouteMetrics

### Community 99 - "_FakeProc"
Cohesion: 0.17
Nodes (3): _FakeProc, _StubbornProc, TestTerminateProcessEscalation

### Community 100 - "tun_trial_runner.py"
Cohesion: 0.07
Nodes (11): clear_journal(), compute_file_identity(), _journal_path(), JournalError, load_journal(), save_journal(), TrialPreparationError, abort_trial() (+3 more)

### Community 102 - "test_tun_state_capture.py"
Cohesion: 0.18
Nodes (5): _patch_captures(), test_capture_snapshot_native_skips_adapters_without_ip_interface(), test_capture_snapshot_preserves_capture_error_message(), test_capture_snapshot_runs_all_captures_and_assembles(), fake()

### Community 105 - "test_web_mode_perf.py"
Cohesion: 0.11
Nodes (5): _read(), TestClientPerfEndpoint, TestIdleRepaintGuards, TestModeUi, TestRadarPerformance

### Community 110 - "typing"
Cohesion: 0.09
Nodes (24): GuardianHTTPError, QuotaExceededError, TokenInvalidError, activate_guardian(), _coerce_optional_int(), _detect_proxy_pass_claim_time_offset(), Entitlement, fetch_proxy_pass() (+16 more)

### Community 111 - "test_tun_diagnostic_fixes.py"
Cohesion: 0.06
Nodes (9): TestBoundedDisconnect, TestCgnatExclusion, fake_pre_start(), TestDnsRefusalNamesCompetingIfIndex, TestPostPinEgressStallFastFail, fake_foreign(), TestPreStartGateUsesFastSnapshot, TestRouteCoverageVsExcludedSentinels (+1 more)

### Community 112 - "api.py"
Cohesion: 0.03
Nodes (68): account_login(), account_logout(), account_resend_verification(), account_send_unblock_code(), account_session_token(), account_verify_cancel(), AccountActionResponse, AccountResponse (+60 more)

### Community 113 - "iphelper.py"
Cohesion: 0.10
Nodes (19): _adapter_row(), best_route_interface(), _dll(), interface_entry_native(), _IpAddressPrefix, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW (+11 more)

### Community 114 - "obtain_auth"
Cohesion: 0.08
Nodes (18): complete_link_verification(), _from_single_session_token(), _is_permanent_refresh_rejection(), _login_interactively(), login_with_password(), login_with_session_token(), obtain_auth(), resend_verification_code() (+10 more)

### Community 115 - "ProxyCandidate"
Cohesion: 0.12
Nodes (5): ProxyCandidate, _app(), TestControlPlaneEndpointPinning, TestCountrySwitchPins, TestTunBypassIps

### Community 118 - "test_upstream_proxy_pin.py"
Cohesion: 0.27
Nodes (11): UpstreamProxyConfig, _controller(), test_interface_pin_sets_ip_unicast_if_before_connect(), test_literal_proxy_ip_needs_no_pin(), test_no_interface_pin_means_no_socket_option(), test_non_literal_pin_is_not_accepted_as_verified(), test_pinning_requirement_is_off_without_the_tunnel(), test_proxy_connection_dials_the_pin_and_keeps_the_target_name() (+3 more)

### Community 119 - "fetch_server_list"
Cohesion: 0.09
Nodes (15): _cache_path(), City, Country, fetch_server_list(), load_cached_server_list(), _parse_server_list(), print_server_list(), Protocol (+7 more)

### Community 120 - "TestRunPsWriteSemantics"
Cohesion: 0.15
Nodes (6): RollbackError, failing_executor(), not_found_executor(), TestRunPsWriteSemantics, executor(), executor()

### Community 121 - "StateDifference"
Cohesion: 0.10
Nodes (15): _adapter_indexes(), _difference_interface_index(), _is_virtual_adapter(), _dns_rollback_command(), generate_rollback_commands(), _is_tproxy_route(), partition_diffs(), _rollback_adapter() (+7 more)

### Community 122 - "threading"
Cohesion: 0.29
Nodes (7): _default_clock(), _serve(), test_http_proxy_connect(), test_http_proxy_rejects_non_2xx(), test_socks5_no_auth_connect(), handler(), test_socks5_userpass_connect()

### Community 127 - "probe_system_egress"
Cohesion: 0.11
Nodes (6): _default_egress(), _direct_tcp_probe(), probe_system_egress(), wait_for_system_egress(), TestEgressProbe, _FakeSocket

### Community 128 - "test_e2e_split_routes.py"
Cohesion: 0.26
Nodes (8): _load_support(), _route(), support(), test_decomposed_public_halves_satisfy_check(), test_literal_split_routes_satisfy_check(), test_other_adapter_routes_are_ignored(), test_private_and_onlink_routes_do_not_count(), test_single_half_is_not_enough()

### Community 129 - "tokens.py"
Cohesion: 0.11
Nodes (8): _refresh(), refresh_token(), delete_tokens(), load_tokens(), save_tokens(), SavedTokens, _token_path(), TestTokenPathOverride

### Community 132 - "h3_session.py"
Cohesion: 0.09
Nodes (10): _format_authority(), stream_id_for_stream(), certifi_cafile(), load_certifi_roots(), _FakeQuicConnectCM, test_certifi_cafile_points_at_existing_bundle(), test_h1_tls_context_is_strict_and_loads_certifi(), spy() (+2 more)

### Community 135 - "app.js"
Cohesion: 0.47
Nodes (9): apply(), boot(), init(), pause(), radianceFactor(), setRadiance(), setTransforms(), start() (+1 more)

### Community 136 - "TestControllerPassReuse"
Cohesion: 0.39
Nodes (3): TestControllerPassReuse, fake_acquire(), pool_start()

### Community 140 - "_rule"
Cohesion: 0.18
Nodes (5): _rule(), test_real_chromium_bounding_boxes(), TestAccountAlignment, TestPasswordToggle, TestScrollContainer

### Community 141 - "tun_helper.py"
Cohesion: 0.05
Nodes (41): _adapter_has_ipv4(), _adapter_present(), adapter_reuse_plan(), _atomic_write_json(), build_sidecar_command(), check_prerequisites(), cleanup_stale_wintun_adapters(), _default_spawn() (+33 more)

### Community 146 - "set_country"
Cohesion: 0.11
Nodes (5): no_metrics(), CountrySelection, TestCountrySwitch, _fake_frontend_ps(), _reset_ws_globals()

### Community 147 - "test_tun_perf.py"
Cohesion: 0.13
Nodes (7): _batched_payload(), _pins_app(), _run_batched_with(), TestBatchedSnapshotCapture, __call__(), TestParallelControlPlanePins, slow_physical()

### Community 148 - "_DyingSession"
Cohesion: 0.11
Nodes (9): SessionAtCapacity, _AtCapSession, _DyingSession, _HealthySession, _Session, factory(), factory(), factory() (+1 more)

### Community 149 - "test_fxa_identity.py"
Cohesion: 0.29
Nodes (5): _FakeResponse, _HeaderCapturingClient, _responder(), test_fxa_api_uses_product_ua_with_browser_headers(), test_hawk_requests_also_send_product_ua_and_never_reuse_signatures()

### Community 150 - "_Client"
Cohesion: 0.10
Nodes (8): _Client, _fxa_oauth(), _Resp, TestEmbeddedWindowRemoved, TestFxaDesktopIdentity, TestGuardianCallback, TestGuardianPkceUrl, TestGuardianTokenExchange

### Community 151 - "ProxyController"
Cohesion: 0.05
Nodes (7): ControllerConfig, _is_ip_literal(), ProxyController, _write(), ProxyPassInfo, test_controller_config_parity_defaults(), test_transport_property_maps_versions()

### Community 154 - "set_country"
Cohesion: 0.15
Nodes (6): _attach_status_notifier(), CountrySelection, _retain_failed_app(), set_country(), TestCountryEndpointHotPath, TestCountryHotPathAdapterIsolation

### Community 159 - ".test_unexpected_sidecar_exit_is_reported_as_failure"
Cohesion: 0.22
Nodes (4): TestEstablishedEndpointProtection, TestRunHelperP0, parent_alive(), boom()

### Community 162 - "_authorized_request"
Cohesion: 0.16
Nodes (9): _authorized_request(), rewrite_control_plane_url(), _FakeClient, _FakeResponse, patched(), test_challenge_error_propagates_and_stops_retrying(), test_challenge_then_success_solves_once_and_retries(), test_initial_success_makes_one_request_without_challenge() (+1 more)

### Community 168 - "probe_adapter"
Cohesion: 0.08
Nodes (17): _competing_tunnel_script(), detect_competing_tunnel(), detect_foreign_default_tunnel(), _direct_https_trace(), _foreign_default_route_script(), is_stable_reconcile_state(), _native_default_route_holders(), _parse_trace() (+9 more)

### Community 175 - "TestTunHelperNativeStubs"
Cohesion: 0.20
Nodes (3): TestTunHelperNativeStubs, TestWsl2CarveOut, boom()

### Community 177 - "FakeSession"
Cohesion: 0.22
Nodes (4): FakeSession, factory(), factory(), factory()

### Community 181 - "test_verify_exit_country_normalizes_socks5_to_socks5h"
Cohesion: 0.25
Nodes (3): test_verify_exit_country_normalizes_socks5_to_socks5h(), stream(), __aenter__()

### Community 186 - "_tls_context"
Cohesion: 0.33
Nodes (3): https_via_socks(), socks5_connect(), _tls_context()

### Community 189 - "DiagnosticsBuffer"
Cohesion: 0.25
Nodes (4): DiagnosticsBuffer, install_logger_handler(), LoggingDiagnosticsHandler, TestLoggingHandler

### Community 191 - "capture_adapter_dns"
Cohesion: 0.33
Nodes (3): _physical_dns_servers(), dns_servers_native(), capture_adapter_dns()

### Community 199 - "RelayerTestRequest"
Cohesion: 0.31
Nodes (3): RelayerTestRequest, test_relayer_latency(), TestRelayerTestEndpoint

### Community 204 - "TrialJournal"
Cohesion: 0.20
Nodes (3): load_journal(), TrialJournal, TestTrialJournalValidation

### Community 210 - "test_http_client_rebuild_race.py"
Cohesion: 0.21
Nodes (6): _isolate_shared_client(), _patch_mock_build(), fake_build(), test_rebuild_does_not_kill_in_flight_request(), test_rebuild_twice_keeps_each_in_flight_request_alive(), handler()

### Community 212 - "._wire"
Cohesion: 0.07
Nodes (9): launch_webview(), main(), _preflight_interactive_auth(), start_api_server(), _web_icon_path(), TestPreflightInteractiveAuth, FakeServer, FakeThread (+1 more)

### Community 215 - "get_token_path"
Cohesion: 0.07
Nodes (17): cli_obtain_auth(), _appdata_base(), discard_legacy_tokens(), ensure_config_dir(), get_config_dir(), get_legacy_config_dir(), get_legacy_migration_marker_path(), get_proxy_state_path() (+9 more)

### Community 220 - "test_physical_bootstrap.py"
Cohesion: 0.12
Nodes (12): _app(), _reset_http_client(), _reset_https_and_overrides(), test_activation_installs_the_proxy_pin_and_tightens_the_controller(), test_bootstrap_fails_closed_when_the_guardian_cannot_be_resolved(), test_bootstrap_fails_closed_without_a_physical_egress(), test_bootstrap_is_a_no_op_off_windows(), test_bootstrap_pins_both_endpoints_and_defers_binding_to_the_caller() (+4 more)

### Community 221 - "test_tun_frontend.py"
Cohesion: 0.07
Nodes (11): _disable_default_recovery_gate(), _sleep_proc_args(), TestDisabledByDefault, TestOptInAndElevation, TestOrderlyShutdown, TestOutputCaptureBounded, TestReconcileCaptureCadence, TestStartupEarlyExit (+3 more)

### Community 226 - "test_fxa_pkce.py"
Cohesion: 0.10
Nodes (7): _Response, TestOauthSuccessInterception, TestPkceUrlParity, TestStateReset, TestTokenUaSplit, fake_post(), fake_post()

### Community 240 - "app.py"
Cohesion: 0.04
Nodes (28): configure_logger(), _JsonFormatter, parse_log_format(), parse_log_level(), _rfc3339_timestamp(), _TextFormatter, auth_helper_command(), _is_singbox_name() (+20 more)

### Community 241 - ".test_permanent_rejection_falls_back_to_login"
Cohesion: 0.31
Nodes (7): _expired_token_file(), TestObtainAuthRefreshFallback, boom(), fake_login(), wrapper(), boom(), boom()

### Community 246 - "httpx"
Cohesion: 0.16
Nodes (7): exchange_code(), generate_pkce(), new_state(), _post_form(), refresh_access_token(), generate_pkce(), _clear_overrides()

### Community 263 - "PerchVPNApp"
Cohesion: 0.03
Nodes (32): _is_ip(), set_control_plane_address_overrides(), _startup(), _getaddrinfo_ipv4_addresses(), PerchVPNApp, _resolve_host(), _pin_host(), _add() (+24 more)

### Community 267 - "_FakeSocket"
Cohesion: 0.22
Nodes (4): query_a(), _FakeSocket, test_query_a_binds_source_and_sends_to_server_port_53(), test_query_a_rejects_a_reply_from_another_sender()

### Community 272 - "TokenResponse"
Cohesion: 0.13
Nodes (11): TokenResponse, install_login_token(), complete_oauth_flow(), complete_oauth_flow_async(), OAuthError, submit_oauth_code(), submit_oauth_code_async(), TestAuthTokenPathIntegration (+3 more)

### Community 292 - "buf"
Cohesion: 0.33
Nodes (3): buf(), _write_chain(), _write_string()

## Knowledge Gaps
- **1 isolated node(s):** `perchvpn-windows`
  These have ≤1 connection - possible missing edges. (Counts symbols only; 1866 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **147 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `TunFrontend` connect `TunFrontend` to `.test_recoverable_orphan_is_reconciled_then_spawned`, `FakeProcess`, `TestEnforceAdapterMetric`, `_FakeProc`, `PerchVPNApp`, `probe_adapter`, `TunRecoveryGate`, `.__init__`, `test_tun_graceful_shutdown.py`, `test_tun_recovery.py`, `test_tun_diagnostic_fixes.py`, `api.py`, `app.py`, `TestIdentitySettleAndRetry`, `Any`, `test_tun_frontend.py`, `tun_recovery.py`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Are the 45 inferred relationships involving `WindowsConfig` (e.g. with `test_load_persisted_auth_disabled_during_logout()` and `test_load_persisted_auth_failed_credentials_not_installed()`) actually correct?**
  _`WindowsConfig` has 45 INFERRED edges - model-reasoned connections that need verification._
- **What connects `perchvpn-windows` to the rest of the system?**
  _1 weakly-connected nodes found - possible missing edges._
- **Should `test_pool_churn_and_fallback.py` be split into smaller, more focused modules?**
  _Cohesion score 0.14814814814814814 - nodes in this community are weakly interconnected._
- **Why does `WindowsConfig` connect `WindowsConfig` to `_get_urltest_raw_token`, `asyncio`, `PerchVPNApp`, `test_tun_recovery.py`, `account_signin`, `pytest`, `test_runtime_fixes.py`, `oauth_complete`, `_app`, `HttpProxyServer`, `_cached_countries`, `set_country`, `_guardian_quota_fetch`, `test_country_hot_swap.py`, `test_status_reports_connecting_while_background_init_running`, `test_api_mode_urlping.py`, `test_account_lifecycle.py`, `TunFrontend`, `test_status_presentation.py`, `test_lifecycle.py`, `get_urltest`, `._app`, `config.py`, `get_token_path`, `_stub_build_status`, `TestExitVerificationStateTransitions`, `api.py`, `app.py`, `ProxyCandidate`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 37 inferred relationships involving `PerchVPNApp` (e.g. with `test_load_persisted_auth_disabled_during_logout()` and `test_load_persisted_auth_failed_credentials_not_installed()`) actually correct?**
  _`PerchVPNApp` has 37 INFERRED edges - model-reasoned connections that need verification._
- **Should `_get_urltest_raw_token` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._