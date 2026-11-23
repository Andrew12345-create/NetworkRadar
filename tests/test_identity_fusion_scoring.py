from datetime import datetime, timedelta, timezone
import math
import unittest

from networkradar_modules.identity.fusion import freshness, score_evidence


class IdentityFusionScoringTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)

    def test_stale_hostname_does_not_create_a_current_identity_conflict(self):
        candidate = [
            {
                "kind": "hostname", "value": "old-laptop",
                "strength": 1.0, "independence_group": "hostname",
                "observed_at": self.now - timedelta(days=180),
            },
            {
                "kind": "hostname", "value": "current-laptop",
                "strength": 1.0, "independence_group": "hostname",
                "observed_at": self.now,
            },
            {
                "kind": "client_id", "value": "client-123",
                "strength": 1.0, "independence_group": "client_id",
                "observed_at": self.now,
            },
        ]
        outcome, score, explanation = score_evidence(candidate, now=self.now)
        self.assertEqual(outcome, "CONFIRMED_MATCH")
        self.assertGreaterEqual(score, 0.85)
        self.assertEqual(explanation["conflicts"], [])

    def test_fresh_conflicting_hostname_evidence_still_requires_review(self):
        candidate = [
            {
                "kind": "hostname", "value": "laptop-a",
                "strength": 0.95, "independence_group": "hostname",
                "observed_at": self.now,
            },
            {
                "kind": "hostname", "value": "laptop-b",
                "strength": 0.95, "independence_group": "hostname",
                "observed_at": self.now,
            },
        ]
        outcome, _score, explanation = score_evidence(candidate, now=self.now)
        self.assertEqual(outcome, "CONFLICTING_IDENTITY")
        self.assertEqual(explanation["conflicts"][0]["kind"], "hostname")

    def test_malformed_nan_and_infinite_strengths_are_ignored(self):
        candidate = [
            {"kind": "vendor", "strength": "not-a-number",
             "independence_group": "vendor", "observed_at": self.now},
            {"kind": "model", "strength": math.nan,
             "independence_group": "model", "observed_at": self.now},
            {"kind": "serial", "strength": math.inf,
             "independence_group": "serial", "observed_at": self.now},
        ]
        outcome, score, explanation = score_evidence(candidate, now=self.now)
        self.assertEqual(outcome, "NEW_IDENTITY")
        self.assertEqual(score, 0.0)
        self.assertEqual(explanation["total"], 0.0)

    def test_local_mac_is_capped_at_five_points_and_zero_strength_is_ignored(self):
        fresh = [{
            "kind": "oui_local", "value": "locally-administered",
            "strength": 1.0, "independence_group": "oui_local",
            "observed_at": self.now,
        }]
        outcome, score, explanation = score_evidence(fresh, now=self.now)
        self.assertEqual(outcome, "NEW_IDENTITY")
        self.assertEqual(score, 0.05)
        self.assertTrue(explanation["local_mac_present"])

        zero = [{
            "kind": "oui_local", "value": "locally-administered",
            "strength": 0.0, "independence_group": "oui_local",
            "observed_at": self.now,
        }]
        _outcome, zero_score, zero_explanation = score_evidence(zero, now=self.now)
        self.assertEqual(zero_score, 0.0)
        self.assertFalse(zero_explanation["local_mac_present"])

    def test_materially_future_dated_evidence_cannot_create_a_conflict(self):
        candidate = [
            {
                "kind": "hostname", "value": "future-a",
                "strength": 1.0, "independence_group": "hostname",
                "observed_at": self.now + timedelta(hours=1),
            },
            {
                "kind": "hostname", "value": "future-b",
                "strength": 1.0, "independence_group": "hostname",
                "observed_at": self.now + timedelta(hours=1),
            },
        ]
        outcome, score, explanation = score_evidence(candidate, now=self.now)
        self.assertEqual(outcome, "NEW_IDENTITY")
        self.assertEqual(score, 0.0)
        self.assertEqual(explanation["conflicts"], [])

    def test_invalid_numeric_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            score_evidence([], now=self.now, group_cap=math.nan)
        with self.assertRaises(ValueError):
            freshness(self.now, self.now, half_life_days=math.inf)


if __name__ == "__main__":
    unittest.main()
