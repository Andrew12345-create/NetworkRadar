import unittest
from unittest.mock import patch

from networkradar_modules.network.load_test import (
    MAX_TOTAL_BYTES, NetworkLoadTestManager, validate_test_config,
)


class LoadTestValidationTests(unittest.TestCase):
    def public_resolver(self, host, port, type=None):
        return [(None, None, None, None, ("93.184.216.34", port))]

    def test_accepts_authorised_https_endpoint(self):
        result = validate_test_config("https://test.example/download.bin", resolver=self.public_resolver)
        self.assertEqual(result["host"], "test.example")
        self.assertEqual(result["streams"], 2)

    def test_rejects_non_https_and_nonstandard_ports(self):
        for endpoint in ("http://test.example/file", "https://test.example:8443/file", "ftp://test.example/file"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_test_config(endpoint, resolver=self.public_resolver)

    def test_rejects_private_or_reserved_destinations(self):
        for address in ("127.0.0.1", "192.168.1.1", "10.0.0.2", "169.254.1.1", "224.0.0.1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_test_config(f"https://{address}/file")

    def test_rejects_hostname_resolving_to_private_address(self):
        def private_resolver(host, port, type=None):
            return [(None, None, None, None, ("192.168.1.20", port))]
        with self.assertRaisesRegex(ValueError, "public internet"):
            validate_test_config("https://test.example/file", resolver=private_resolver)

    def test_enforces_duration_rate_stream_and_url_caps(self):
        for kwargs in (
            {"duration_seconds": 4}, {"duration_seconds": 121},
            {"aggregate_mbps": 0.1}, {"aggregate_mbps": 20.1},
            {"streams": 0}, {"streams": 5},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate_test_config("https://test.example/file", resolver=self.public_resolver, **kwargs)
        with self.assertRaises(ValueError):
            validate_test_config("https://user:pass@test.example/file", resolver=self.public_resolver)

    def test_manager_does_not_require_iperf3(self):
        manager = NetworkLoadTestManager(resolver=self.public_resolver)
        self.assertTrue(manager.status()["available"])
        self.assertEqual(manager.status()["state"], "IDLE")


if __name__ == "__main__":
    unittest.main()
