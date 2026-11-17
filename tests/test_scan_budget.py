import unittest

from networkradar_modules.discovery.scan_budget import deep_scan_profile


class DeepScanBudgetTests(unittest.TestCase):
    def test_small_inventory_keeps_full_tcp_coverage(self):
        plan = deep_scan_profile(5)
        self.assertEqual(plan["tcp_top_ports"], 100)
        self.assertEqual(plan["tcp_timeout"], 75)
        self.assertEqual(plan["udp_timeout"], 30)

    def test_typical_home_inventory_uses_bounded_balanced_profile(self):
        plan = deep_scan_profile(17)
        self.assertEqual(plan["tcp_top_ports"], 75)
        self.assertEqual(plan["tcp_timeout"], 70)
        self.assertEqual(plan["tcp_host_timeout"], 20)
        self.assertEqual(plan["tcp_fallback_top_ports"], 35)
        self.assertLessEqual(plan["tcp_fallback_timeout"], plan["tcp_timeout"])

    def test_larger_inventory_scales_down_probe_volume_and_budget(self):
        small = deep_scan_profile(17)
        large = deep_scan_profile(80)
        self.assertLess(large["tcp_top_ports"], small["tcp_top_ports"])
        self.assertLess(large["tcp_timeout"], small["tcp_timeout"])
        self.assertLess(large["udp_timeout"], small["udp_timeout"])

    def test_configured_port_limit_is_respected(self):
        plan = deep_scan_profile(4, configured_top_ports=40)
        self.assertEqual(plan["tcp_top_ports"], 40)
        self.assertEqual(plan["tcp_fallback_top_ports"], 40)

    def test_invalid_counts_are_safely_clamped(self):
        self.assertEqual(deep_scan_profile(-5)["tcp_top_ports"], 100)
        self.assertEqual(deep_scan_profile(100, 0)["tcp_top_ports"], 1)


if __name__ == "__main__":
    unittest.main()
