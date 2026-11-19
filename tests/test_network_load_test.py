import unittest
from unittest.mock import patch

from networkradar_modules.network.load_test import (
    NetworkLoadTestManager, validate_test_config,
)


class LoadTestValidationTests(unittest.TestCase):
    def test_accepts_bounded_private_or_public_ipv4_literal(self):
        self.assertEqual(validate_test_config("192.168.1.20")["target"], "192.168.1.20")
        self.assertEqual(validate_test_config("203.0.113.10", 60, 50, 4)["streams"], 4)

    def test_rejects_hostnames_ipv6_and_special_addresses(self):
        for target in ("example.com", "::1", "127.0.0.1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_test_config(target)

    def test_enforces_duration_rate_and_stream_caps(self):
        for kwargs in (
            {"duration_seconds": 4}, {"duration_seconds": 61},
            {"aggregate_mbps": 0.1}, {"aggregate_mbps": 50.1},
            {"streams": 0}, {"streams": 5},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                validate_test_config("192.168.1.2", **kwargs)

    def test_requires_iperf3_before_start(self):
        manager = NetworkLoadTestManager(which=lambda _: None)
        with self.assertRaisesRegex(RuntimeError, "iperf3 was not found"):
            manager.start("192.168.1.20")

    def test_rejects_second_concurrent_job(self):
        class DummyThread:
            def __init__(self, *args, **kwargs): pass
            def start(self): pass
        manager = NetworkLoadTestManager(which=lambda _: "iperf3")
        with patch("networkradar_modules.network.load_test.threading.Thread", DummyThread):
            manager.start("192.168.1.20")
            with self.assertRaisesRegex(RuntimeError, "already running"):
                manager.start("192.168.1.21")


if __name__ == "__main__":
    unittest.main()
