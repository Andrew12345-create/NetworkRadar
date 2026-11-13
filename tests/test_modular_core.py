import socket
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from networkradar_modules.core.startup import (
    StartupError, acquire_instance_lock, release_instance_lock, bind_local_server
)
from networkradar_modules.identity.fusion import score_evidence
from networkradar_modules.diagnostics.status import engine_record


class StartupTests(unittest.TestCase):
    def tearDown(self):
        release_instance_lock()

    def test_lock_acquire_release(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "db" / ".lock"
            acquire_instance_lock(path)
            self.assertTrue(path.exists())
            release_instance_lock()
            acquire_instance_lock(path)

    def test_port_conflict_is_explicit(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        try:
            with self.assertRaises(StartupError):
                bind_local_server(lambda *a, **k: None, "127.0.0.1", port)
            server, alternate = bind_local_server(
                lambda *a, **k: None, "127.0.0.1", port,
                allow_alternate=True, search_span=10
            )
            self.assertNotEqual(port, alternate)
            server.server_close()
        finally:
            sock.close()


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)

    def evidence(self, group, kind, value, strength=1.0, days=0):
        return {"source": group, "kind": kind, "value": value,
                "strength": strength, "independence_group": group,
                "observed_at": self.now - timedelta(days=days)}

    def test_independent_evidence_can_confirm(self):
        rows = [
            self.evidence("dhcp", "hostname", "workstation-1"),
            self.evidence("nmap", "os", "Windows"),
            self.evidence("mdns", "service", "_workstation._tcp"),
        ]
        outcome, score, explanation = score_evidence(rows, now=self.now)
        self.assertEqual(outcome, "CONFIRMED_MATCH")
        self.assertTrue(explanation["auto_merge_allowed"])

    def test_same_source_group_is_capped(self):
        rows = [self.evidence("dhcp", "hostname", f"host-{i}") for i in range(20)]
        outcome, score, explanation = score_evidence(rows, now=self.now)
        self.assertLessEqual(score, 0.45)
        self.assertFalse(explanation["auto_merge_allowed"])

    def test_conflicting_strong_hostname_is_flagged(self):
        rows = [
            self.evidence("host-a", "hostname", "alpha"),
            self.evidence("host-b", "hostname", "beta"),
        ]
        outcome, _, _ = score_evidence(rows, now=self.now)
        self.assertEqual(outcome, "CONFLICTING_IDENTITY")

    def test_local_mac_is_not_an_auto_merge_anchor(self):
        rows = [self.evidence("oui_local", "oui_local", "randomised",
                              strength=1.0)]
        outcome, _, explanation = score_evidence(rows, now=self.now)
        self.assertFalse(explanation["auto_merge_allowed"])
        self.assertTrue(explanation["local_mac_present"])

    def test_empty_evidence_is_unknown(self):
        self.assertEqual(score_evidence([], now=self.now)[0], "UNKNOWN")


class DiagnosticsTests(unittest.TestCase):
    def test_unknown_is_not_reported_online(self):
        self.assertEqual(engine_record("x", "UNKNOWN")["status"], "UNKNOWN")

    def test_error_degrades_running_engine(self):
        self.assertEqual(engine_record("x", "RUNNING", last_error="timeout")["status"],
                         "DEGRADED")


if __name__ == "__main__":
    unittest.main()
