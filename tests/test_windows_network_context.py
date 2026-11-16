import unittest

from networkradar_modules.network.windows_context import (
    build_network_context_script,
    parse_ipconfig_all,
)


SAMPLE = r"""
Windows IP Configuration

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.100.25(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.1
   DNS Servers . . . . . . . . . . . : 192.168.100.1
                                       1.1.1.1

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Physical Address. . . . . . . . . : 11-22-33-44-55-66

Ethernet adapter vEthernet (Default Switch):

   Physical Address. . . . . . . . . : 00-15-5D-41-E0-83
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 172.20.63.138(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . :
"""


class WindowsContextParserTests(unittest.TestCase):
    def test_batched_script_collects_all_five_sources_in_one_process(self):
        script = build_network_context_script()
        self.assertEqual(script.count("Get-NetAdapter"), 1)
        self.assertEqual(script.count("Get-NetIPAddress"), 1)
        self.assertEqual(script.count("Get-NetRoute"), 1)
        self.assertEqual(script.count("Get-DnsClientServerAddress"), 1)
        self.assertEqual(script.count("Get-NetIPInterface"), 1)
        self.assertIn("ConvertTo-Json -Depth 6 -Compress", script)

    def test_ipconfig_fallback_parses_ipv4_gateway_dns_and_dhcp(self):
        result = parse_ipconfig_all(SAMPLE)
        self.assertEqual(len(result["adapters"]), 2)
        wifi = result["adapters"][0]
        self.assertEqual(wifi["Name"], "Wi-Fi")
        self.assertEqual(wifi["MacAddress"], "AA:BB:CC:DD:EE:FF")
        self.assertTrue(wifi["_native_fallback"])
        self.assertEqual(result["addresses"][0]["IPAddress"], "192.168.100.25")
        self.assertEqual(result["addresses"][0]["PrefixLength"], 24)
        self.assertEqual(result["routes"][0]["NextHop"], "192.168.100.1")
        self.assertEqual(result["dns"][0]["ServerAddresses"],
                         ["192.168.100.1", "1.1.1.1"])
        self.assertEqual(result["dhcp"][0]["Dhcp"], "Enabled")

    def test_native_fallback_does_not_invent_gateway(self):
        result = parse_ipconfig_all(SAMPLE)
        virtual = result["adapters"][1]
        self.assertEqual(virtual["Name"], "vEthernet (Default Switch)")
        self.assertEqual(
            [r for r in result["routes"] if r["InterfaceIndex"] == virtual["InterfaceIndex"]],
            [],
        )

    def test_localised_or_unusable_output_fails_empty(self):
        result = parse_ipconfig_all("Configuración IP de Windows\nAdaptador Wi-Fi:")
        self.assertEqual(result["adapters"], [])
        self.assertEqual(result["routes"], [])


if __name__ == "__main__":
    unittest.main()
