import unittest
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
        # A closed local port is a valid unknown-device outcome, not a crash.
        result = identify_router("192.168.1.254", "192.168.1.0/24")
        self.assertFalse(result["control_ready"])
        self.assertFalse(result["credentials_sent"])
        self.assertFalse(result["configuration_changed"])


if __test__:
    unittest.main()
