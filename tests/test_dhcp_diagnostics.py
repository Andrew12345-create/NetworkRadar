import unittest
from unittest.mock import patch

import networkradar as app


class DHCPCaptureDiagnosticsTests(unittest.TestCase):
    def test_zero_frames_explains_passive_capture_limits_and_interface(self):
        with patch.dict(app.DHCP_STATE, {
            "status": "ONLINE", "messages": 0, "interface": "Wi-Fi 2"
        }, clear=True):
            result = app.DHCPEngine().diagnostic_classification()
        self.assertEqual(result["state"], "TRAFFIC_NOT_OBSERVED")
        self.assertEqual(result["interface"], "Wi-Fi 2")
        self.assertEqual(result["capture_filter"], "udp port 67 or udp port 68")
        self.assertIn("client isolation", result["reason"])
        self.assertIn("Wi-Fi 2", result["reason"])

    def test_observed_frames_report_the_interface(self):
        with patch.dict(app.DHCP_STATE, {
            "status": "ONLINE", "messages": 4, "interface": "Ethernet"
        }, clear=True):
            result = app.DHCPEngine().diagnostic_classification()
        self.assertEqual(result["state"], "OBSERVING")
        self.assertEqual(result["messages"], 4)
        self.assertIn("Ethernet", result["reason"])


if __name__ == "__main__":
    unittest.main()
