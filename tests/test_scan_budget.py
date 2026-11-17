import unittest

from networkradar_modules.discovery.scan_budget import deep_scan_profile


class DeepScanBudgetTests(unittest.TestCase):
    def test_small_target_set_uses_bounded_tcp_and_udp_budgets(self):
        plan = deep_scan_profile(4)
        self.assertEqual(plan["tcp_top_ports"], 50)
        self.assertEqual(plan["tcp_timeout"], 45)
        self.assertEqual(plan["tcp_host_timeout"], 15)
        self.assertEqual(plan["udp_timeout"], 12)
        self.assertEqual(plan["udp_host_timeout"], 6)

    def test_adaptive_target_batch_keeps_tcp_timeout_bounded(self):
        plan = deep_scan_profile(8)
        self.assertEqual(plan["tcp_top_ports"], 50)
        self.assertEqual(plan["tcp_timeout"], 50)
        self.assertEqual(plan["tcp_host_timeout"], 15)
        self.assertEqual(plan["tcp_fallback_top_ports"], 25)
        self.assertLessEqual(plan["tcp_fallback_timeout"], plan["tcp_timeout"])

    def test_larger_inventories_reduce_probe_volume_and_wall_clock_budgets(self):
        small = deep_scan_profile(8)
        medium = deep_scan_profile(24)
        large = deep_scan_profile(80)
        self.assertLess(medium["tcp_top_ports"], small["tcp_top_ports"])
        self.assertLess(large["tcp_top_ports"], medium["tcp_top_ports"])
        self.assertLess(medium["tcp_timeout"], small["tcp_timeout"])
        self.assertLess(large["udp_timeout"], medium["udp_timeout"])

    def test_configured_port_limit_is_respected(self):
        plan = deep_scan_profile(4, configured_top_ports=20)
        self.assertEqual(plan["tcp_top_ports"], 20)
        self.assertEqual(plan["tcp_fallback_top_ports"], 20)

    def test_invalid_counts_are_safely_clamped(self):
        self.assertEqual(deep_scan_profile(-5)["tcp_top_ports"], 50)
        self.assertEqual(deep_scan_profile(100, 0)["tcp_top_ports"], 1)

    def test_every_budget_is_positive_and_fallback_is_no_larger(self):
        for count in (0, 1, 4, 8, 16, 32, 128, 512):
            with self.subTest(count=count):
                plan = deep_scan_profile(count)
                self.assertTrue(all(value > 0 for value in plan.values()))
                self.assertLessEqual(plan["tcp_fallback_timeout"], plan["tcp_timeout"])
                self.assertLessEqual(plan["tcp_fallback_top_ports"], plan["tcp_top_ports"])


if __name__ == "__main__":
    unittest.main()
