import unittest
from unittest.mock import patch
from networkradar_modules.control import router_discovery
from networkradar_modules.control.router_discovery import identify_router, _private_target, _extract_title


class RouterDiscoveryTests(unittest.TestCase):
    def test_only_authorised_private_gateway_is_accepted(self):
        self.assertEqual(_private_target("192.168.1.1", "192.168.1.0/24"), "192.168.1.1")
        for host, scope in (("8.8.8.8", "192.168.1.0/24"),
                            ("192.168.2.1", "192.168.1.0/24"),
                            ("127.0.0.1", "127.0.0.0/8")):
            with self.subTest(host=host), self.assertRaises(ValueError):
                _private_target(host, scope)

    def test_html_title_is_extracted_without_markup(self):
        self.assertEqual(_extract_title("<html><title>ASUS Router</title></html>"), "ASUS Router")

    def test_discovery_never_claims_control_ready_without_adapter_session(self):
        # Mock all network probes: unit tests must never contact a real gateway.
        empty = {"port": 80, "evidence": [], "headers": {}, "body": "", "certificate_subject": ""}
        with patch.object(router_discovery, "_probe_http", return_value=empty):
            result = identify_router("192.168.1.254", "192.168.1.0/24")
        self.assertFalse(result["control_ready"])
        self.assertFalse(result["credentials_sent"])
        self.assertFalse(result["configuration_changed"])


if __name__ == "__main__":
    unittest.main()
