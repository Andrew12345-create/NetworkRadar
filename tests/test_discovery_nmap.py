import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from networkradar_modules.discovery.nmap import (
    best_os_match,
    parse_nmap_xml,
    run_nmap_discovery,
)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Vendor"/>
    <hostnames><hostname name="workstation.local" type="PTR"/></hostnames>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="2001:db8::10" addrtype="ipv6"/>
  </host>
</nmaprun>
"""


class NmapXMLParserTests(unittest.TestCase):
    def test_parses_only_up_hosts_with_ipv4_addresses(self):
        devices = parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(devices), 1)
        device = devices[0]
        self.assertEqual(device["ip"], "192.168.1.10")
        self.assertEqual(device["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(device["vendor"], "Example Vendor")
        self.assertEqual(device["hostname"], "workstation.local")
        self.assertEqual(device["device_name"], "workstation.local")
        self.assertEqual(device["device_type"], "Unclassified device")

    def test_missing_mac_and_hostname_keep_established_defaults(self):
        xml = (
            '<nmaprun><host><status state="up"/>'
            '<address addr="192.168.1.20" addrtype="ipv4"/>'
            '</host></nmaprun>'
        )
        device = parse_nmap_xml(xml)[0]
        self.assertEqual(device["mac"], "Unavailable")
        self.assertEqual(device["vendor"], "Unknown")
        self.assertEqual(device["hostname"], "-")
        self.assertEqual(device["device_name"], "")

    def test_malformed_xml_is_rejected(self):
        with self.assertRaises(Exception):
            parse_nmap_xml("<nmaprun><host>")


    def test_best_os_match_preserves_classes_and_marks_accuracy_semantics(self):
        import xml.etree.ElementTree as ET
        host = ET.fromstring("""<host><os>
          <osmatch name="Linux 5.x" accuracy="96">
            <osclass vendor="Linux" osfamily="Linux" osgen="5.X"
                     type="general purpose" accuracy="96">
              <cpe>cpe:/o:linux:linux_kernel:5</cpe>
            </osclass>
          </osmatch>
          <osmatch name="Linux 4.x" accuracy="80"/>
        </os></host>""")
        result = best_os_match(host)
        self.assertEqual(result["name"], "Linux 5.x")
        self.assertEqual(result["accuracy"], 96)
        self.assertEqual(result["classes"][0]["vendor"], "Linux")
        self.assertEqual(result["classes"][0]["cpe"][0], "cpe:/o:linux:linux_kernel:5")
        self.assertIn("not a probability", result["interpretation"])

    def test_best_os_match_handles_missing_and_malformed_accuracy(self):
        import xml.etree.ElementTree as ET
        self.assertEqual(best_os_match(ET.fromstring("<host/>")), {})
        host = ET.fromstring('<host><os><osmatch name="Unknown" accuracy="bad"/></os></host>')
        self.assertEqual(best_os_match(host)["accuracy"], 0)


class NmapExecutionTests(unittest.TestCase):
    def test_empty_network_does_not_execute_scanner(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("Nmap must not run without a network scope")

        self.assertEqual(
            run_nmap_discovery("", "nmap", "unused.log", runner=forbidden),
            ([], 0.0),
        )

    def test_successful_scan_writes_diagnostics_and_returns_devices(self):
        calls = []

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout=NMAP_XML, stderr="scan ok")

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "nmap.log"
            devices, duration = run_nmap_discovery(
                "192.168.1.0/24", "nmap.exe", log, runner=fake_runner
            )
            self.assertEqual(len(devices), 1)
            self.assertGreaterEqual(duration, 0)
            self.assertEqual(
                calls[0][0],
                ["nmap.exe", "-sn", "-R", "-oX", "-", "192.168.1.0/24"],
            )
            self.assertEqual(calls[0][1]["timeout"], 150)
            self.assertIn("scan ok", log.read_text(encoding="utf-8"))

    def test_nonzero_exit_raises_with_stderr_context(self):
        def fake_runner(command, **kwargs):
            return SimpleNamespace(
                returncode=2, stdout="", stderr="permission denied"
            )

        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "nmap.log"
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                run_nmap_discovery("192.168.1.0/24", "nmap", log,
                                   runner=fake_runner)


if __name__ == "__main__":
    unittest.main()
