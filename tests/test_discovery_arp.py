import unittest
from types import SimpleNamespace

from networkradar_modules.discovery.arp import (
    parse_arp_output,
    read_arp_cache,
)


class ArpOutputTests(unittest.TestCase):
    def test_parses_windows_arp_rows_and_normalises_mac(self):
        output = """Interface: 192.168.1.25 --- 0x8
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
        self.assertEqual(parse_arp_output(output), {
            "192.168.1.1": "AA:BB:CC:DD:EE:FF",
            "192.168.1.255": "FF:FF:FF:FF:FF:FF",
        })

    def test_ignores_unrelated_and_malformed_rows(self):
        output = """? (192.168.1.1) at aa:bb:cc:dd:ee:ff
192.168.1.2 not-a-mac dynamic
192.168.1.3 aa-bb-cc-dd-ee dynamic
"""
        self.assertEqual(parse_arp_output(output), {})

    def test_later_observation_for_same_ip_replaces_earlier_row(self):
        output = (
            "192.168.1.5 aa-bb-cc-dd-ee-01 dynamic\n"
            "192.168.1.5 aa-bb-cc-dd-ee-02 dynamic"
        )
        self.assertEqual(
            parse_arp_output(output)["192.168.1.5"],
            "AA:BB:CC:DD:EE:02",
        )


class ArpCollectionTests(unittest.TestCase):
    def test_reads_local_arp_cache(self):
        calls = []

        def fake_runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(
                stdout="192.168.0.1 aa-bb-cc-dd-ee-ff dynamic"
            )

        self.assertEqual(
            read_arp_cache(runner=fake_runner),
            {"192.168.0.1": "AA:BB:CC:DD:EE:FF"},
        )
        self.assertEqual(calls[0][0], ["arp", "-a"])
        self.assertEqual(calls[0][1]["timeout"], 8)

    def test_command_failure_is_nonfatal(self):
        def failing_runner(*args, **kwargs):
            raise OSError("arp command unavailable")

        self.assertEqual(read_arp_cache(runner=failing_runner), {})


if __name__ == "__main__":
    unittest.main()
