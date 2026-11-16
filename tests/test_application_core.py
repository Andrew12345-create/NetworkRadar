import unittest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta

import networkradar as app


class DeviceIdentityDerivationTests(unittest.TestCase):
    def test_locally_administered_mac_uses_ip_fallback(self):
        device = {"ip": "192.168.43.22", "mac": "02:11:22:33:44:55"}
        _, key, basis = app.derive_identity(device)
        self.assertEqual(key, "ip:192.168.43.22")
        self.assertTrue(basis.startswith("IP fallback"))

    def test_globally_administered_mac_remains_identity_anchor(self):
        device = {"ip": "192.168.43.22", "mac": "00:11:22:33:44:55"}
        _, key, basis = app.derive_identity(device)
        self.assertEqual(key, "mac:00:11:22:33:44:55")
        self.assertEqual(basis, "MAC")


class DeviceDisplayNameTests(unittest.TestCase):
    def test_successfully_classified_device_replaces_generic_database_label(self):
        device = {
            "ip": "192.168.100.1",
            "device_name": "Unidentified device",
            "_is_gateway": True,
        }
        app.advanced_device_recognition(device)
        self.assertEqual(device["device_type"], "Router / firewall")
        self.assertEqual(device["device_name"], "Router / firewall at 192.168.100.1")

    def test_generic_unclassified_label_is_replaced_case_insensitively(self):
        device = {
            "ip": "192.168.100.1",
            "device_name": "UNIDENTIFIED DEVICE",
            "_is_gateway": True,
        }
        app.advanced_device_recognition(device)
        self.assertEqual(device["device_name"], "Router / firewall at 192.168.100.1")


class ApplicationIdentityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def evidence(self, source, kind, value, strength=1.0, observed_at=None):
        return {
            "source": source,
            "kind": kind,
            "value": value,
            "strength": strength,
            "independence_group": source,
            "observed_at": observed_at or self.now,
        }

    def test_application_uses_confirmed_modular_identity_scorer(self):
        rows = [
            self.evidence("dhcp", "hostname", "workstation-1"),
            self.evidence("nmap", "os", "Windows"),
            self.evidence("mdns", "service", "_workstation._tcp"),
        ]
        outcome, score, explanation = app.phantom_score(rows)
        self.assertEqual(outcome, "CONFIRMED_MATCH")
        self.assertGreaterEqual(score, 0.85)
        self.assertTrue(explanation["auto_merge_allowed"])

    def test_application_flags_conflicting_strong_hostnames(self):
        rows = [
            self.evidence("source-a", "hostname", "alpha"),
            self.evidence("source-b", "hostname", "beta"),
        ]
        outcome, _, explanation = app.phantom_score(rows)
        self.assertEqual(outcome, "CONFLICTING_IDENTITY")
        self.assertFalse(explanation["auto_merge_allowed"])

    def test_local_mac_alone_cannot_auto_merge(self):
        rows = [
            self.evidence("oui_local", "oui_local", "randomised-mac")
        ]
        outcome, _, explanation = app.phantom_score(rows)
        self.assertFalse(explanation["auto_merge_allowed"])
        self.assertTrue(explanation["local_mac_present"])
        self.assertNotEqual(outcome, "CONFIRMED_MATCH")


class EndpointManagementAuthorizationTests(unittest.TestCase):
    def test_enrolment_and_commands_blocked_on_unauthorised_network(self):
        original = app.is_authorized
        app.is_authorized = lambda: False
        try:
            with self.assertRaisesRegex(RuntimeError, "not authorised"):
                app.create_agent_enrollment_token()
            with self.assertRaisesRegex(ValueError, "not authorised"):
                app.queue_agent_command(
                    "nr-" + "a" * 20, "refresh_inventory"
                )
        finally:
            app.is_authorized = original


class EndpointAgentCapabilityTests(unittest.TestCase):
    def test_inventory_only_client_cannot_receive_remote_control_capabilities(self):
        self.assertEqual(app._normalise_agent_capabilities(["inventory-report"]), ["inventory-report"])
        self.assertFalse(app._agent_supports_action(["inventory-report"], "list_processes"))
        self.assertFalse(app._agent_supports_action(["inventory-report"], "restart_computer"))
        self.assertFalse(app._agent_supports_action(["inventory-report"], "refresh_inventory"))

    def test_requested_capabilities_are_allowlisted(self):
        self.assertEqual(
            app._normalise_agent_capabilities(["inventory-report", "power-control", "unknown"]),
            ["inventory-report", "power-control"],
        )
        self.assertEqual(app._normalise_agent_capabilities([]), ["inventory-report"])

    def test_legacy_agents_without_capability_field_keep_compatibility(self):
        capabilities = app._normalise_agent_capabilities(None)
        self.assertIn("inventory", capabilities)
        self.assertIn("processes", capabilities)
        self.assertIn("power-control", capabilities)
        self.assertTrue(app._agent_supports_action(capabilities, "restart_computer"))

    def test_unsupported_or_unknown_actions_fail_closed(self):
        self.assertFalse(app._agent_supports_action(["inventory", "power-control"], "arbitrary_shell"))
        self.assertFalse(app._agent_supports_action(["inventory"], "restart_service"))


class EndpointInventoryAssociationTests(unittest.TestCase):
    def test_exact_observed_ip_can_associate_inventory(self):
        self.assertEqual(
            app._endpoint_inventory_association_basis(
                "192.168.1.20", "00:11:22:33:44:55", "192.168.1.20", {}
            ),
            "OBSERVED_SOURCE_IP",
        )

    def test_matching_adapter_mac_can_follow_a_dhcp_ip_change(self):
        inventory = {"network_adapters": [{"mac": "AA-BB-CC-DD-EE-FF"}]}
        self.assertEqual(
            app._endpoint_inventory_association_basis(
                "192.168.1.20", "aa:bb:cc:dd:ee:ff", "192.168.1.99", inventory
            ),
            "MATCHED_ADAPTER_MAC",
        )

    def test_hostname_is_never_used_as_an_association_key(self):
        self.assertEqual(
            app._endpoint_inventory_association_basis(
                "192.168.1.20", "00:11:22:33:44:55", "192.168.1.99",
                {"hostname": "same-name", "network_adapters": []},
            ),
            "",
        )

    def test_conflicting_adapter_mac_blocks_ip_only_join(self):
        inventory = {"network_adapters": [{"mac": "AA:BB:CC:DD:EE:FF"}]}
        self.assertEqual(
            app._endpoint_inventory_association_basis(
                "192.168.1.20", "00:11:22:33:44:55", "192.168.1.20", inventory
            ),
            "",
        )

    def test_ip_match_with_no_adapter_mac_remains_usable(self):
        self.assertEqual(
            app._endpoint_inventory_association_basis(
                "192.168.1.20", "00:11:22:33:44:55", "192.168.1.20",
                {"network_adapters": []},
            ),
            "OBSERVED_SOURCE_IP",
        )


class TSharkInterfaceSelectionTests(unittest.TestCase):
    def test_active_adapter_guid_beats_first_wifi_interface(self):
        interfaces = [
            ("1", r"\Device\NPF_{11111111-1111-1111-1111-111111111111} (Wi-Fi)"),
            ("2", r"\Device\NPF_{22222222-2222-2222-2222-222222222222} (Ethernet)"),
        ]
        selected = app._select_tshark_interface(
            interfaces,
            primary_guid="{22222222-2222-2222-2222-222222222222}",
            primary_name="Ethernet",
        )
        self.assertEqual(selected, "2")

    def test_invalid_guid_falls_back_to_active_adapter_name(self):
        interfaces = [("1", "Wi-Fi"), ("2", "Ethernet")]
        self.assertEqual(
            app._select_tshark_interface(
                interfaces, primary_guid="N/A", primary_name="Ethernet"
            ),
            "2",
        )

    def test_preferred_interface_overrides_active_adapter(self):
        interfaces = [("1", "Wi-Fi"), ("2", "Ethernet")]
        self.assertEqual(
            app._select_tshark_interface(
                interfaces, preferred="1", primary_name="Ethernet"
            ),
            "1",
        )

    def test_missing_active_adapter_does_not_silently_choose_another(self):
        with self.assertRaisesRegex(RuntimeError, "will not silently capture"):
            app._select_tshark_interface(
                [("1", "Wi-Fi")], primary_name="Ethernet 2"
            )

    def test_manual_network_override_can_use_safe_interface_fallback(self):
        self.assertEqual(
            app._select_tshark_interface(
                [("1", "Wi-Fi")], primary_name="Manual override"
            ),
            "1",
        )


class InterfaceIPv4SelectionTests(unittest.TestCase):
    def test_preferred_routable_address_beats_apipa_and_deprecated(self):
        rows = [
            {"InterfaceIndex": 7, "IPAddress": "169.254.12.8",
             "PrefixLength": 16, "AddressState": "Preferred",
             "SkipAsSource": False},
            {"InterfaceIndex": 7, "IPAddress": "192.168.43.22",
             "PrefixLength": 24, "AddressState": "Preferred",
             "SkipAsSource": False},
            {"InterfaceIndex": 7, "IPAddress": "192.168.43.23",
             "PrefixLength": 24, "AddressState": "Deprecated",
             "SkipAsSource": False},
            {"InterfaceIndex": 8, "IPAddress": "127.0.0.1",
             "PrefixLength": 8, "AddressState": "Preferred",
             "SkipAsSource": False},
        ]
        selected = app._select_ipv4_interface_rows(rows)
        self.assertEqual(selected[7]["IPAddress"], "192.168.43.22")
        self.assertNotIn(8, selected)

    def test_invalid_and_non_ipv4_addresses_are_ignored(self):
        rows = [
            {"InterfaceIndex": 1, "IPAddress": "not-an-ip",
             "PrefixLength": 24},
            {"InterfaceIndex": 2, "IPAddress": "2001:db8::1",
             "PrefixLength": 64},
        ]
        self.assertEqual(app._select_ipv4_interface_rows(rows), {})


class NetworkAdapterSelectionTests(unittest.TestCase):
    def test_lowest_effective_default_route_metric_wins(self):
        adapters = [
            {"idx": 4, "status": "Up", "ip": "192.168.1.20"},
            {"idx": 9, "status": "Up", "ip": "10.0.0.20"},
        ]
        routes = {
            4: {"_metric": 80},
            9: {"_metric": 15},
        }
        selected = app._select_primary_adapter(adapters, routes)
        self.assertEqual(selected["idx"], 9)

    def test_up_adapter_is_fallback_when_no_default_route_exists(self):
        adapters = [
            {"idx": 4, "status": "Up", "ip": "192.168.1.20"},
            {"idx": 9, "status": "Up", "ip": "10.0.0.20"},
        ]
        self.assertEqual(app._select_primary_adapter(adapters, {})["idx"], 4)
        self.assertIsNone(app._select_primary_adapter([], {}))


class NetworkApprovalFreshnessTests(unittest.TestCase):
    def test_recent_approval_is_fresh(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        profile = {"last_authorized": "2025-12-15 12:00:00"}
        self.assertTrue(app._profile_authorization_fresh(profile, now)[0])

    def test_routine_last_seen_does_not_refresh_old_approval(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        profile = {
            "last_seen": "2026-01-01 11:59:00",
            "last_authorized": "2025-09-01 12:00:00",
        }
        fresh, reason = app._profile_authorization_fresh(profile, now)
        self.assertFalse(fresh)
        self.assertIn("expired", reason.lower())

    def test_missing_or_invalid_approval_timestamp_fails_closed(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        for profile in ({}, {"last_authorized": "not-a-date"}):
            with self.subTest(profile=profile):
                self.assertFalse(app._profile_authorization_fresh(profile, now)[0])

    def test_future_approval_timestamp_fails_closed(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        profile = {"last_authorized": "2026-01-01 12:10:00"}
        self.assertFalse(app._profile_authorization_fresh(profile, now)[0])


class GatewayNeighbourRefreshTests(unittest.TestCase):
    @patch.object(app.subprocess, "run")
    @patch.object(app, "_ps")
    def test_gateway_ping_primes_cache_then_retries_selected_interface(self, ps, run):
        ps.side_effect = [
            [],
            [{
                "IPAddress": "192.168.1.1",
                "InterfaceIndex": 7,
                "LinkLayerAddress": "aa-bb-cc-dd-ee-ff",
                "State": "Reachable",
            }],
        ]
        result = app._gateway_mac_via_neighbor("192.168.1.1", 7)
        self.assertEqual(result, "AA:BB:CC:DD:EE:FF")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],
                         ["ping", "-n", "1", "-w", "900", "192.168.1.1"])
        self.assertIn("-InterfaceIndex 7", ps.call_args_list[0].args[0])
        self.assertIn("-InterfaceIndex 7", ps.call_args_list[1].args[0])
        # Get-NetNeighbor does not support -IPAddress; exact IP matching
        # is performed against the selected interface rows in Python.
        self.assertNotIn("-IPAddress", ps.call_args_list[0].args[0])
        self.assertNotIn("-IPAddress", ps.call_args_list[1].args[0])

    @patch.object(app.subprocess, "run")
    @patch.object(app, "_ps")
    def test_invalid_gateway_is_not_probed(self, ps, run):
        self.assertIsNone(app._gateway_mac_via_neighbor("not-an-ip", 7))
        ps.assert_not_called()
        run.assert_not_called()

    @patch.object(app.subprocess, "run")
    @patch.object(app, "_ps")
    def test_neighbour_from_another_interface_is_rejected(self, ps, run):
        ps.side_effect = [
            [{
                "IPAddress": "192.168.1.1",
                "InterfaceIndex": 8,
                "LinkLayerAddress": "aa-bb-cc-dd-ee-ff",
                "State": "Reachable",
            }],
            [],
        ]
        self.assertIsNone(app._gateway_mac_via_neighbor("192.168.1.1", 7))
        run.assert_called_once()


class NetworkFingerprintDiagnosticsTests(unittest.TestCase):
    def test_manual_override_is_explicitly_non_authorising(self):
        with patch.object(app, "NETWORK_OVERRIDE", "192.168.100.0/24"):
            detected = app.detect_network()
        self.assertEqual(detected["fingerprint"], "")
        self.assertEqual(detected["fingerprint_status"], "MANUAL_OVERRIDE")
        self.assertIn("not proof", detected["fingerprint_diagnostics"]["reason"])

    @patch.object(app, "_wifi_details", return_value=("Andrew", "B0:19:21:4A:14:6F"))
    @patch.object(app, "_gateway_mac_via_neighbor", return_value="F4:A4:D6:17:32:72")
    @patch.object(app, "_ps")
    def test_windows_adapter_evidence_produces_fingerprint(self, ps, gateway_mac, wifi):
        ps.return_value = [{
            "adapters": [{"Name": "Wi-Fi", "InterfaceIndex": 8,
                          "InterfaceDescription": "Intel(R) Wireless-AC 9560 160MHz",
                          "InterfaceGuid": "{4a54e23f-455a-4e34-b9f2-4ab74d8cf34f}",
                          "MacAddress": "96-03-C3-D8-6E-A8", "Status": "Up",
                          "MediaType": "Native 802.11"}],
            "addresses": [{"InterfaceIndex": 8, "IPAddress": "192.168.100.82",
                           "PrefixLength": 24, "AddressState": "Preferred",
                           "SkipAsSource": False}],
            "routes": [{"InterfaceIndex": 8, "NextHop": "192.168.100.1",
                        "RouteMetric": 25, "InterfaceMetric": 10}],
            "dns": [{"InterfaceIndex": 8, "ServerAddresses": ["192.168.100.1"]}],
            "dhcp": [{"InterfaceIndex": 8, "Dhcp": "Enabled"}],
        }]
        with patch.object(app, "NETWORK_OVERRIDE", ""):
            detected = app.detect_network()
        self.assertTrue(detected["fingerprint"])
        self.assertEqual(detected["confidence"], 100)
        self.assertEqual(detected["fingerprint_status"], "READY")
        self.assertEqual(detected["gateway_mac"], "F4:A4:D6:17:32:72")
        self.assertEqual(detected["bssid"], "B0:19:21:4A:14:6F")
        self.assertEqual(detected["fingerprint_diagnostics"]["strong_anchors"],
                         ["gateway_mac", "bssid"])
        self.assertTrue(app.has_strong_network_anchor(detected))
        ps.assert_called_once()

    def test_authorise_error_explains_manual_override(self):
        original = dict(app.NET_CTX)
        try:
            app.NET_CTX.update({
                "fingerprint": "", "mode": "MANUAL",
                "fingerprint_diagnostics": {
                    "status": "MANUAL_OVERRIDE",
                    "reason": "Manual scope only."
                }
            })
            with patch.object(app, "refresh_network_context"):
                with self.assertRaisesRegex(RuntimeError, "NETWORKRADAR_NETWORK"):
                    app.authorize_current()
        finally:
            app.NET_CTX.clear()
            app.NET_CTX.update(original)


class PowerShellDiagnosticTests(unittest.TestCase):
    @patch.object(app.subprocess, "run")
    def test_wlan_command_failure_is_included_in_fingerprint_diagnostics(self, run):
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "WLAN AutoConfig service is not running."
        app._PS_DIAGNOSTICS.records = []
        self.assertEqual(app._wifi_details("Wi-Fi"), ("", ""))
        record = app._PS_DIAGNOSTICS.records[0]
        self.assertEqual(record["operation"], "netsh wlan show interfaces")
        self.assertEqual(record["state"], "ERROR")
        self.assertIn("AutoConfig", record["detail"])

    @patch.object(app.subprocess, "run")
    def test_empty_query_result_is_reported(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = ""
        run.return_value.stderr = ""
        app._PS_DIAGNOSTICS.records = []
        self.assertEqual(app._ps("Get-NetAdapter", label="Get-NetAdapter"), [])
        self.assertEqual(app._PS_DIAGNOSTICS.records[0]["state"], "EMPTY")
        self.assertEqual(app._PS_DIAGNOSTICS.records[0]["operation"], "Get-NetAdapter")


    @patch.object(app.subprocess, "run")
    def test_helper_does_not_bypass_host_execution_policy(self, run):
        run.return_value.returncode = 0
        run.return_value.stdout = "[]"
        run.return_value.stderr = ""
        app._PS_DIAGNOSTICS.records = []
        self.assertEqual(app._ps("Get-NetAdapter", label="Get-NetAdapter"), [])
        args = run.call_args.args[0]
        self.assertNotIn("-ExecutionPolicy", args)
        self.assertNotIn("Bypass", args)

    @patch.object(app.subprocess, "run")
    def test_powershell_failure_is_reported_without_raw_command(self, run):
        run.return_value.returncode = 1
        run.return_value.stdout = ""
        run.return_value.stderr = "Access is denied."
        app._PS_DIAGNOSTICS.records = []
        self.assertEqual(app._ps("Get-NetAdapter", label="Get-NetAdapter"), [])
        record = app._PS_DIAGNOSTICS.records[0]
        self.assertEqual(record["state"], "ERROR")
        self.assertEqual(record["detail"], "Access is denied.")
        self.assertNotIn("Get-NetAdapter", record["detail"])


if __name__ == "__main__":
    unittest.main()


class WebStartupErrorHandlingTests(unittest.TestCase):
    def test_start_web_propagates_binding_error_for_orderly_cleanup(self):
        with patch.dict(app.os.environ, {"NETWORKRADAR_PORT": "8766"}), patch.object(
            app, "bind_local_server",
            side_effect=app.StartupError("127.0.0.1:8766 is reserved"),
        ), patch.object(app.sys, "argv", []):
            with self.assertRaisesRegex(app.StartupError, "web console startup failed"):
                app.start_web()


class JobProgressHistoryTests(unittest.TestCase):
    def test_update_job_records_bounded_human_readable_history(self):
        import threading
        initial = {
            "state": "IDLE", "phase": "Waiting", "percent": 0,
            "started_at": "", "updated_at": "", "message": "Initialising.",
            "scan_number": 0, "last_error": "", "history": [],
        }
        with patch.object(app, "JOB_STATE", initial), patch.object(app, "JOB_LOCK", threading.Lock()):
            for number in range(15):
                app.update_job(
                    state="RUNNING",
                    phase=f"Stage {number}",
                    percent=number * 5,
                    message=f"Working on stage {number}.",
                )
            self.assertEqual(len(app.JOB_STATE["history"]), 12)
            self.assertEqual(app.JOB_STATE["history"][-1]["phase"], "Stage 14")
            self.assertEqual(app.JOB_STATE["history"][-1]["percent"], 70)
            self.assertIn("Working on stage 14", app.JOB_STATE["history"][-1]["message"])
