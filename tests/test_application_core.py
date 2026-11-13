import unittest
from datetime import datetime, timezone, timedelta

import networkradar as app


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
            ("1", r"\\Device\\NPF_{11111111-1111-1111-1111-111111111111} (Wi-Fi)"),
            ("2", r"\\Device\\NPF_{22222222-2222-2222-2222-222222222222} (Ethernet)"),
        ]
        selected = app._select_tshark_interface(
            interfaces,
            primary_guid="{22222222-2222-2222-2222-222222222222}",
            primary_name="Ethernet",
        )
        self.assertEqual(selected, "2")

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


if __name__ == "__main__":
    unittest.main()
