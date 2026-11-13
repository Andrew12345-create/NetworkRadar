import unittest

from networkradar_modules.discovery.classification import infer_type


class DeviceClassificationTests(unittest.TestCase):
    def test_gateway_role_is_confirmed_from_network_context(self):
        device = {"ip": "192.168.1.1", "hostname": "unknown"}
        self.assertEqual(
            infer_type(device, gateway_ip="192.168.1.1"),
            "Router / network gateway (role-confirmed)",
        )

    def test_printer_classification_uses_observed_device_text(self):
        device = {"hostname": "HP-LaserJet-Office"}
        self.assertEqual(infer_type(device), "Printer (probable)")

    def test_camera_classification_uses_reported_service_evidence(self):
        device = {"service_summary": "RTSP video stream"}
        self.assertEqual(infer_type(device), "IP camera / video (probable)")

    def test_open_port_only_is_labelled_unconfirmed(self):
        device = {"port_numbers": [9100]}
        self.assertEqual(
            infer_type(device),
            "Device exposing printing service (type unconfirmed)",
        )

    def test_unknown_device_remains_unclassified(self):
        self.assertEqual(
            infer_type({"ip": "192.168.1.40"}),
            "Unclassified network device",
        )

    def test_explicit_gateway_flag_does_not_require_gateway_ip(self):
        self.assertEqual(
            infer_type({"_is_gateway": True}),
            "Router / network gateway (role-confirmed)",
        )


if __name__ == "__main__":
    unittest.main()
