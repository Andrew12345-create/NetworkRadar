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
