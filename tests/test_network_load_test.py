import unittest

from networkradar_modules.network.load_test import (
    MAX_TOTAL_BYTES, MAX_TOTAL_MB, NetworkLoadTestManager, validate_test_config,
)


class LoadTestValidationTests(unittest.TestCase):
    def public_resolver(self, host, port, type=None):
        return [(None, None, None, None, ("93.184.216.34", port))]

    def test_accepts_authorised_https_endpoint(self):
        result = validate_test_config("https://test.example/download.bin", resolver=self.public_resolver)
        self.assertEqual(result["host"], "test.example")
        self.assertEqual(result["streams"], 2)
        self.assertEqual(result["max_total_mb"], 256)

    def test_accepts_extreme_profile_with_explicit_bounds(self):
        result = validate_test_config(
            "https://test.example/large-test-payload.bin",
            duration_seconds=180, aggregate_mbps=75, streams=8,
            max_total_mb=1024, profile="Extreme",
            resolver=self.public_resolver,
        )
        self.assertEqual(result["streams"], 8)
        self.assertEqual(result["max_total_bytes"], 1024 * 1024 * 1024)
        self.assertEqual(result["profile"], "Extreme")

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

    def test_enforces_duration_rate_stream_data_and_url_caps(self):
        for kwargs in (
            {"duration_seconds": 4}, {"duration_seconds": 181},
            {"aggregate_mbps": 0.1}, {"aggregate_mbps": 100.1},
            {"streams": 0}, {"streams": 9},
            {"max_total_mb": 15}, {"max_total_mb": 1025},
            {"profile": "Unbounded"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate_test_config("https://test.example/file", resolver=self.public_resolver, **kwargs)
        with self.assertRaises(ValueError):
            validate_test_config("https://user:pass@test.example/file", resolver=self.public_resolver)

    def test_global_data_cap_matches_one_gibibyte(self):
        self.assertEqual(MAX_TOTAL_MB, 1024)
        self.assertEqual(MAX_TOTAL_BYTES, 1024 * 1024 * 1024)

    def test_manager_does_not_require_iperf3(self):
        manager = NetworkLoadTestManager(resolver=self.public_resolver)
        self.assertTrue(manager.status()["available"])
        self.assertEqual(manager.status()["state"], "IDLE")


if __name__ == "__main__":
    unittest.main()
