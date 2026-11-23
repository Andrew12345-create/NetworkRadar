import json
import subprocess
import unittest
from unittest.mock import patch

from networkradar_modules.security import firewall
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


class FirewallSnapshotTests(unittest.TestCase):
    def setUp(self):
        firewall._FIREWALL_CACHE_DATA = None
        firewall._FIREWALL_CACHE_AT = 0.0

    @patch.object(firewall.platform, "system", return_value="Windows")
    @patch.object(firewall, "_run_powershell")
    def test_snapshot_batches_profile_and_rule_queries(self, run, _system):
        payload = {
            "profiles": [
                {"Name": "Domain", "Enabled": True,
                 "DefaultInboundAction": "Block",
                 "DefaultOutboundAction": "Allow", "NotifyOnListen": True}
            ],
            "rule_counts": {
                "total": 400, "enabled": 250, "inbound": 120,
                "outbound": 130, "block": 40, "allow": 210,
            },
        }
        run.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"], returncode=0,
            stdout=json.dumps(payload), stderr=""
        )
        result = firewall.get_firewall_snapshot()
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        self.assertEqual(result["status"], "ONLINE")
        self.assertEqual(result["profiles"][0]["name"], "Domain")
        self.assertEqual(result["rule_counts"]["enabled"], 250)
        self.assertIn("single PowerShell process", result["collected_by"])

    @patch.object(firewall.platform, "system", return_value="Windows")
    @patch.object(firewall, "_run_powershell")
    def test_recent_snapshot_is_cached_and_force_refresh_bypasses_cache(self, run, _system):
        payload = {
            "profiles": [{"Name": "Private", "Enabled": True,
                          "DefaultInboundAction": "Block",
                          "DefaultOutboundAction": "Allow"}],
            "rule_counts": {"total": 10, "enabled": 8, "inbound": 4,
                            "outbound": 4, "block": 2, "allow": 6},
        }
        run.return_value = subprocess.CompletedProcess(
            args=["powershell.exe"], returncode=0,
            stdout=json.dumps(payload), stderr=""
        )
        first = firewall.get_firewall_snapshot()
        cached = firewall.get_firewall_snapshot()
        forced = firewall.get_firewall_snapshot(force=True)

        self.assertFalse(first["cached"])
        self.assertTrue(cached["cached"])
        self.assertFalse(forced["cached"])
        self.assertEqual(run.call_count, 2)

    @patch.object(firewall.platform, "system", return_value="Windows")
    @patch.object(firewall, "_run_powershell",
                  side_effect=subprocess.TimeoutExpired("powershell.exe", 20))
    def test_timeout_returns_degraded_snapshot_without_raising(self, run, _system):
        result = firewall.get_firewall_snapshot()
        self.assertEqual(result["status"], "DEGRADED")
        self.assertIn("timed out", result["message"])
        run.assert_called_once_with(unittest.mock.ANY, timeout=20)


if __name__ == "__main__":
    unittest.main()
