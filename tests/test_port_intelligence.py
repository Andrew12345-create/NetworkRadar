import unittest
import subprocess

from networkradar_modules.discovery.port_intelligence import (
    validate_target, parse_full_tcp_xml, run_full_tcp_scan,
)


XML = """<nmaprun><host><status state="up"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"/></port>
<port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
</ports></host></nmaprun>"""


class FullPortIntelligenceTests(unittest.TestCase):
    def test_scope_validation_requires_private_ipv4_membership(self):
        self.assertEqual(validate_target("192.168.1.9", "192.168.1.0/24"), "192.168.1.9")
        for target, scope in [
            ("8.8.8.8", "0.0.0.0/0"),
            ("192.168.2.9", "192.168.1.0/24"),
            ("2001:db8::1", "192.168.1.0/24"),
            ("127.0.0.1", "127.0.0.0/8"),
        ]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target, scope)

    def test_parser_keeps_only_open_tcp_ports_and_service_metadata(self):
        result = parse_full_tcp_xml(XML)
        self.assertTrue(result["completed"])
        self.assertEqual(result["open_ports"], [22])
        self.assertEqual(result["services"][0]["product"], "OpenSSH")

    def test_scan_uses_full_tcp_range_and_one_target(self):
        class Result:
            returncode = 0
            stdout = XML
            stderr = ""
        captured = {}
        def runner(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            return Result()
        result = run_full_tcp_scan("192.168.1.9", "192.168.1.0/24", "nmap", runner=runner)
        self.assertIn("-p-", captured["command"])
        self.assertEqual(captured["command"][-1], "192.168.1.9")
        self.assertEqual(result["ports_tested"], 65535)
        self.assertEqual(captured["kwargs"]["timeout"], 190)

    def test_timeout_is_reported_as_incomplete(self):
        def runner(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        with self.assertRaises(TimeoutError):
            run_full_tcp_scan("192.168.1.9", "192.168.1.0/24", "nmap", runner=runner)


if __name__ == "__main__":
    unittest.main()
