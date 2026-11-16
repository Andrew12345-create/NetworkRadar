import unittest

from networkradar_modules.discovery.tcp_sweep import sweep_tcp_hosts


class FakeSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class TcpSweepTests(unittest.TestCase):
    def test_discovers_only_hosts_that_accept_a_selected_port(self):
        sockets = []

        def connector(address, timeout):
            ip, port = address
            if ip == "192.168.50.2" and port == 80:
                sock = FakeSocket()
                sockets.append(sock)
                return sock
            raise OSError("connection refused")

        result = sweep_tcp_hosts(
            "192.168.50.0/30",
            ports=(80, 443),
            connector=connector,
            max_workers=4,
        )
        self.assertEqual(result["targets"], 2)
        self.assertEqual(result["probes"], 4)
        self.assertEqual(result["responders"], 1)
        self.assertEqual(result["devices"][0]["ip"], "192.168.50.2")
        self.assertEqual(result["devices"][0]["port_numbers"], [80])
        self.assertEqual(result["devices"][0]["identification_confidence"], 0)
        self.assertTrue(sockets[0].closed)

    def test_rejects_public_ipv4_and_ipv6_scopes(self):
        for scope in ("8.8.8.0/24", "2001:db8::/64"):
            with self.subTest(scope=scope):
                with self.assertRaises(ValueError):
                    sweep_tcp_hosts(scope)

    def test_rejects_invalid_scope_and_oversized_network(self):
        with self.assertRaises(ValueError):
            sweep_tcp_hosts("not-a-network")
        with self.assertRaisesRegex(ValueError, "limited to"):
            sweep_tcp_hosts("10.0.0.0/16", max_hosts=512)

    def test_timeout_and_port_validation(self):
        with self.assertRaises(ValueError):
            sweep_tcp_hosts("192.168.1.0/24", timeout=5)
        with self.assertRaises(ValueError):
            sweep_tcp_hosts("192.168.1.0/24", ports=(0, 70000, "80"))

    def test_progress_reports_bounded_probe_completion(self):
        progress = []

        def connector(address, timeout):
            raise OSError("closed")

        result = sweep_tcp_hosts(
            "192.168.60.0/30",
            ports=(80,),
            connector=connector,
            progress=lambda done, total, responders: progress.append((done, total, responders)),
        )
        self.assertEqual(result["probes"], 2)
        self.assertEqual(progress[-1], (2, 2, 0))


if __name__ == "__main__":
    unittest.main()
