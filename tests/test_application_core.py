import unittest
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



class StrongNetworkAnchorAuthorizationTests(unittest.TestCase):
    def _detected(self, **extra):
        detected = {
            "fingerprint": "test-fingerprint",
            "confidence": 90,
            "gateway_mac": "",
            "bssid": "",
            "_classification": {"fingerprint": app.Conf.CONFIRMED},
        }
        detected.update(extra)
        return detected

    def _approved_profile(self):
        return {
            "id": "test-network",
            "fingerprint": "test-fingerprint",
            "approved": True,
            "last_authorized": datetime.now().isoformat(),
        }

    def test_missing_gateway_mac_and_bssid_blocks_active_discovery(self):
        allowed, decision, reasons, _ = app._authz_decision(
            self._detected(), [self._approved_profile()]
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "INDETERMINATE")
        self.assertIn("No strong network anchor", " ".join(reasons))

    def test_valid_gateway_mac_is_a_strong_anchor(self):
        allowed, decision, _, _ = app._authz_decision(
            self._detected(gateway_mac="00:11:22:33:44:55"),
            [self._approved_profile()],
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "AUTHORISED")

    def test_valid_interface_bssid_is_a_strong_anchor(self):
        allowed, decision, _, _ = app._authz_decision(
            self._detected(bssid="AA:BB:CC:DD:EE:FF"),
            [self._approved_profile()],
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "AUTHORISED")

    def test_invalid_or_multicast_anchor_does_not_authorise(self):
        for value in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "bad-mac"):
            with self.subTest(value=value):
                allowed, _, reasons, _ = app._authz_decision(
                    self._detected(gateway_mac=value),
                    [self._approved_profile()],
                )
                self.assertFalse(allowed)
                self.assertIn("No strong network anchor", " ".join(reasons))


class WifiInterfaceParsingTests(unittest.TestCase):
    def test_uses_bssid_from_exact_connected_interface(self):
        output = """Name                   : Wi-Fi
Description            : Adapter A
State                  : connected
SSID                   : Home Network
BSSID                  : aa:bb:cc:dd:ee:01

Name                   : Wi-Fi 2
Description            : Adapter B
State                  : connected
SSID                   : Guest Network
BSSID                  : aa:bb:cc:dd:ee:02
"""
        self.assertEqual(
            app._parse_wifi_interface_blocks(output, "Wi-Fi 2"),
            ("Guest Network", "AA:BB:CC:DD:EE:02"),
        )

    def test_does_not_use_bssid_from_another_interface(self):
        output = """Name : Wi-Fi
State : connected
SSID : Home
BSSID : aa:bb:cc:dd:ee:01
"""
        self.assertEqual(app._parse_wifi_interface_blocks(output, "Ethernet"), ("", ""))

    def test_disconnected_interface_has_no_anchor(self):
        output = """Name : Wi-Fi
State : disconnected
SSID : Home
BSSID : aa:bb:cc:dd:ee:01
"""
        self.assertEqual(app._parse_wifi_interface_blocks(output, "Wi-Fi"), ("", ""))


if __name__ == "__main__":
    unittest.main()
