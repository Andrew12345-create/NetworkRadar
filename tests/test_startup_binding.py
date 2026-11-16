"""Regression tests for local HTTP port binding and Windows port diagnostics."""
import unittest
from unittest.mock import patch

from networkradar_modules.core import startup


class FakeServer:
    failures = {}
    instances = []

    def __init__(self, address, handler, bind_and_activate=False):
        self.server_address = address
        self.closed = False
        self.activated = False
        type(self).instances.append(self)

    def server_bind(self):
        error = type(self).failures.get(self.server_address[1])
        if error is not None:
            raise error

    def server_activate(self):
        self.activated = True

    def server_close(self):
        self.closed = True


class BindLocalServerTests(unittest.TestCase):
    def setUp(self):
        FakeServer.failures = {}
        FakeServer.instances = []

    def bind(self, port, **kwargs):
        return startup.bind_local_server(
            object, "127.0.0.1", port, server_class=FakeServer, **kwargs
        )

    def test_requested_port_is_bound_without_probe_socket(self):
        server, port = self.bind(8766)
        self.assertEqual(port, 8766)
        self.assertTrue(server.activated)
        self.assertFalse(server.closed)

    def test_port_conflict_does_not_silently_change_port(self):
        FakeServer.failures[8766] = OSError(98, "address already in use")
        with self.assertRaises(startup.StartupError) as caught:
            self.bind(8766)
        self.assertIn("127.0.0.1:8766", str(caught.exception))
        self.assertIn("NETWORKRADAR_PORT", str(caught.exception))
        self.assertEqual(len(FakeServer.instances), 1)
        self.assertTrue(FakeServer.instances[0].closed)

    def test_alternate_port_is_used_only_when_explicitly_enabled(self):
        FakeServer.failures[8766] = OSError(98, "address already in use")
        server, port = self.bind(8766, allow_alternate=True, search_span=3)
        self.assertEqual(port, 8767)
        self.assertTrue(server.activated)
        self.assertTrue(FakeServer.instances[0].closed)

    def test_alternate_search_stops_at_requested_span(self):
        FakeServer.failures = {
            8766: OSError(98, "busy"),
            8767: OSError(98, "busy"),
            8768: OSError(98, "busy"),
        }
        with self.assertRaises(startup.StartupError) as caught:
            self.bind(8766, allow_alternate=True, search_span=2)
        self.assertIn("Tried 2 alternative port(s)", str(caught.exception))
        self.assertEqual(
            [item.server_address[1] for item in FakeServer.instances],
            [8766, 8767, 8768],
        )
        self.assertTrue(all(item.closed for item in FakeServer.instances))

    def test_activation_failure_closes_partial_server(self):
        class ActivationFailureServer(FakeServer):
            def server_activate(self):
                raise OSError("activation failed")

        with self.assertRaises(startup.StartupError):
            startup.bind_local_server(
                object, "127.0.0.1", 8766, server_class=ActivationFailureServer
            )
        self.assertTrue(ActivationFailureServer.instances[-1].closed)

    def test_invalid_port_and_search_span_are_rejected(self):
        for value in (0, -1, 65536, "not-a-port"):
            with self.subTest(value=value):
                with self.assertRaises(startup.StartupError):
                    self.bind(value)
        with self.assertRaises(startup.StartupError):
            self.bind(8766, allow_alternate=True, search_span=-1)
        with self.assertRaises(startup.StartupError):
            self.bind(8766, allow_alternate=True, search_span=1025)

    def test_windows_excluded_port_error_is_explained(self):
        denied = OSError("access denied")
        denied.winerror = 10013
        FakeServer.failures[8766] = denied
        with patch.object(startup.os, "name", "nt"), patch.object(
            startup, "_windows_excluded_tcp_ports",
            return_value=[("ipv4", 8700, 8799, True)],
        ):
            with self.assertRaises(startup.StartupError) as caught:
                self.bind(8766)
        message = str(caught.exception)
        self.assertIn("WSAEACCES", message)
        self.assertIn("ipv4 8700-8799", message)
        self.assertIn("no listening process", message)

    def test_excluded_port_parser_reads_netsh_ranges_for_both_families(self):
        class Result:
            returncode = 0
            stdout = (
                "Start Port    End Port\n"
                "----------    --------\n"
                "      8700        8799     *\n"
            )

        with patch.object(startup.os, "name", "nt"), patch.object(
            startup.subprocess, "run", return_value=Result()
        ) as run:
            ranges = startup._windows_excluded_tcp_ports(8766)
        self.assertEqual(
            ranges,
            [("ipv4", 8700, 8799, True), ("ipv6", 8700, 8799, True)],
        )
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
