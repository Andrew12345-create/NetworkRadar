import unittest

from networkradar_modules.discovery.adaptive_fingerprint import build_fingerprint_plan


class AdaptiveFingerprintPlanTests(unittest.TestCase):
    def test_new_devices_are_prioritised_and_target_budget_is_enforced(self):
        devices = [{"ip": f"192.168.10.{n}", "identification_confidence": 95}
                   for n in range(1, 12)]
        plan = build_fingerprint_plan(devices, {}, now=1_000_000,
                                      max_targets=5, max_udp_targets=2)
        self.assertEqual(len(plan["targets"]), 5)
        self.assertEqual(plan["candidate_count"], 11)
        self.assertEqual(len(plan["udp_targets"]), 2)
        self.assertEqual(plan["targets"], [
            "192.168.10.1", "192.168.10.10", "192.168.10.11",
            "192.168.10.2", "192.168.10.3",
        ])

    def test_recent_unknown_is_cooled_down_but_stale_unknown_is_selected(self):
        now = 2_000_000
        devices = [
            {"ip": "192.168.10.2", "identification_confidence": 15},
            {"ip": "192.168.10.3", "identification_confidence": 20},
        ]
        history = {
            "192.168.10.2": now - 120,
            "192.168.10.3": now - 1800,
        }
        plan = build_fingerprint_plan(devices, history, now=now)
        self.assertEqual(plan["targets"], ["192.168.10.3"])
        self.assertIn("cooldown", next(
            row["reason"] for row in plan["deferred"]
            if row["ip"] == "192.168.10.2"
        ))

    def test_medium_and_high_confidence_use_different_refresh_intervals(self):
        now = 3_000_000
        devices = [
            {"ip": "192.168.10.4", "identification_confidence": 70},
            {"ip": "192.168.10.5", "identification_confidence": 95},
        ]
        history = {
            "192.168.10.4": now - 7 * 60 * 60,
            "192.168.10.5": now - 7 * 60 * 60,
        }
        plan = build_fingerprint_plan(devices, history, now=now)
        self.assertEqual(plan["targets"], ["192.168.10.4"])

    def test_stale_high_confidence_device_is_eventually_refingerprinted(self):
        now = 4_000_000
        plan = build_fingerprint_plan(
            [{"ip": "192.168.10.6", "identification_confidence": 92}],
            {"192.168.10.6": now - 25 * 60 * 60},
            now=now,
        )
        self.assertEqual(plan["targets"], ["192.168.10.6"])

    def test_non_private_invalid_ipv6_and_duplicate_targets_are_excluded(self):
        devices = [
            {"ip": "192.168.10.7"},
            {"ip": "192.168.10.7"},
            {"ip": "8.8.8.8"},
            {"ip": "2001:db8::1"},
            {"ip": "not-an-ip"},
            {"ip": "224.0.0.1"},
        ]
        plan = build_fingerprint_plan(devices, {}, now=5_000_000)
        self.assertEqual(plan["targets"], ["192.168.10.7"])

    def test_targets_must_belong_to_the_authorised_subnet(self):
        devices = [
            {"ip": "192.168.100.20", "identification_confidence": 0},
            {"ip": "192.168.101.20", "identification_confidence": 0},
        ]
        plan = build_fingerprint_plan(
            devices, {}, now=7_000_000, allowed_network="192.168.100.0/24"
        )
        self.assertEqual(plan["targets"], ["192.168.100.20"])
        self.assertEqual(plan["scope"], "192.168.100.0/24")

    def test_invalid_authorised_subnet_fails_closed(self):
        plan = build_fingerprint_plan(
            [{"ip": "192.168.100.20", "identification_confidence": 0}],
            {}, now=8_000_000, allowed_network="not-a-subnet",
        )
        self.assertEqual(plan["targets"], [])
        self.assertEqual(plan["udp_targets"], [])
        self.assertIn("fails closed", plan["deferred"][0]["reason"])

    def test_plan_never_exceeds_hard_clamped_limits(self):
        devices = [{"ip": f"10.0.0.{n}", "identification_confidence": 0}
                   for n in range(1, 40)]
        plan = build_fingerprint_plan(devices, {}, now=6_000_000,
                                      max_targets=500, max_udp_targets=500)
        self.assertEqual(plan["max_targets"], 32)
        self.assertEqual(len(plan["targets"]), 32)
        self.assertEqual(len(plan["udp_targets"]), 8)


if __name__ == "__main__":
    unittest.main()
