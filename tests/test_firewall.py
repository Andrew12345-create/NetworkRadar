import unittest
from networkradar_modules.security.firewall import default_device_decision


class FirewallDefaultPolicyTests(unittest.TestCase):
    def test_new_device_is_allowed_by_default(self):
        result = default_device_decision({"ip": "192.168.100.55"})
        self.assertEqual(result["decision"], "ALLOW")

    def test_only_explicit_denial_blocks(self):
        result = default_device_decision(
            {"ip": "192.168.100.55"},
            explicit_denials={"192.168.100.55"},
        )
        self.assertEqual(result["decision"], "BLOCK")

    def test_empty_device_is_still_allowed(self):
        self.assertEqual(default_device_decision({})["decision"], "ALLOW")

    def test_default_allow_reason_is_explicit(self):
        result = default_device_decision({"ip": "192.168.100.77"})
        self.assertIn("Default policy", result["reason"])


if __name__ == "__main__":
    unittest.main()
