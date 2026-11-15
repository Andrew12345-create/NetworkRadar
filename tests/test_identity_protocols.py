import unittest

from networkradar_modules.identity.protocols import (
    analyse_mdns_services,
    parse_ssdp_message,
)


class SSDPParserTests(unittest.TestCase):
    def test_parses_notify_headers_without_fetching_location(self):
        result = parse_ssdp_message(
            "NOTIFY * HTTP/1.1\r\n"
            "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            "USN: uuid:device-123::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            "SERVER: Linux/5.10 UPnP/1.0 Example/2.0\r\n"
            "LOCATION: http://192.168.100.25:8000/device.xml\r\n\r\n"
        )
        self.assertEqual(result["message_type"], "NOTIFY")
        self.assertEqual(result["uuid"], "device-123")
        self.assertEqual(result["server"], "Linux/5.10 UPnP/1.0 Example/2.0")
        self.assertEqual(result["location"], "http://192.168.100.25:8000/device.xml")
        self.assertTrue(any("never fetches" in x for x in result["limitations"]))

    def test_limits_message_and_header_sizes(self):
        result = parse_ssdp_message("HTTP/1.1 200 OK\r\nX-Test: " + ("x" * 20000))
        self.assertLessEqual(len(result["headers"].get("x-test", "")), 1024)


class MDNSIdentityTests(unittest.TestCase):
    def test_classifies_service_capabilities_not_hardware_models(self):
        result = analyse_mdns_services([
            {"name": "_airplay._tcp.local", "target": "living-room.local", "port": "7000"},
            {"name": "_ipp._tcp.local", "target": "printer.local", "port": 631},
        ])
        self.assertEqual(result["record_count"], 2)
        self.assertTrue(any("AirPlay" in h["category"] for h in result["hints"]))
        self.assertTrue(any("printer" in h["category"] for h in result["hints"]))
        self.assertNotIn("model", result["services"][0])

    def test_ignores_duplicate_and_invalid_records(self):
        result = analyse_mdns_services([
            {"name": "_ipp._tcp.local", "target": "p.local", "port": 631},
            {"name": "_ipp._tcp.local", "target": "p.local", "port": 631},
            None,
            {"name": "_bad._tcp.local", "port": 70000},
        ])
        self.assertEqual(result["record_count"], 2)
        self.assertIsNone(result["services"][1]["port"])


if __name__ == "__main__":
    unittest.main()
