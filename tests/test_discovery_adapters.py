import unittest

from networkradar_modules.discovery.adapters import (
    _norm_mac,
    _is_real_mac,
    _select_primary_adapter,
    _select_ipv4_interface_rows,
    _select_tshark_interface,
)


class MacAddressHelpersTests(unittest.TestCase):
    def test_normalises_common_mac_formats(self):
        self.assertEqual(_norm_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(_norm_mac("aabb.ccdd.eeff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(_norm_mac("invalid"), "")

    def test_real_mac_rejects_empty_and_all_zero_or_broadcast(self):
        self.assertFalse(_is_real_mac(""))
        self.assertFalse(_is_real_mac("00:00:00:00:00:00"))
        self.assertFalse(_is_real_mac("FF:FF:FF:FF:FF:FF"))
        self.assertTrue(_is_real_mac("02:11:22:33:44:55"))


class AdapterSelectionTests(unittest.TestCase):
    def test_lowest_route_metric_wins(self):
        adapters = [{"idx": 1}, {"idx": 2}]
        routes = {1: {"_metric": 90}, 2: {"_metric": 10}}
        self.assertEqual(_select_primary_adapter(adapters, routes)["idx"], 2)

    def test_first_adapter_is_fallback_without_default_route(self):
        adapters = [{"idx": 1}, {"idx": 2}]
        self.assertEqual(_select_primary_adapter(adapters, {})["idx"], 1)
        self.assertIsNone(_select_primary_adapter([], {}))

    def test_ipv4_selection_skips_loopback_link_local_and_deprecated(self):
        rows = [
            {"InterfaceIndex": 1, "IPAddress": "127.0.0.1",
             "AddressState": "Preferred"},
            {"InterfaceIndex": 2, "IPAddress": "169.254.1.1",
             "AddressState": "Preferred"},
            {"InterfaceIndex": 3, "IPAddress": "192.168.1.10",
             "AddressState": "Deprecated"},
            {"InterfaceIndex": 3, "IPAddress": "192.168.1.11",
             "AddressState": "Preferred"},
        ]
        result = _select_ipv4_interface_rows(rows)
        self.assertEqual(set(result), {3})
        self.assertEqual(result[3]["IPAddress"], "192.168.1.11")

    def test_tshark_prefers_matching_adapter_guid(self):
        interfaces = [
            ("1", r"\Device\NPF_{11111111-1111-1111-1111-111111111111} (Wi-Fi)"),
            ("2", r"\Device\NPF_{22222222-2222-2222-2222-222222222222} (Ethernet)"),
        ]
        self.assertEqual(
            _select_tshark_interface(
                interfaces,
                primary_guid="{22222222-2222-2222-2222-222222222222}",
                primary_name="Ethernet",
            ),
            "2",
        )

    def test_tshark_does_not_silently_switch_adapters(self):
        with self.assertRaisesRegex(RuntimeError, "will not silently capture"):
            _select_tshark_interface(
                [("1", "Wi-Fi")], primary_name="Ethernet 2"
            )


if __name__ == "__main__":
    unittest.main()
