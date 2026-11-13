import unittest

from networkradar_modules.identity.dhcp import (
    analyse_dhcp_identity, parse_parameter_request_list,
)


class DhcpFingerprintTests(unittest.TestCase):
    def test_parse_parameter_request_list(self):
        self.assertEqual(parse_parameter_request_list("1, 3,6,15,119,252"),
                         [1, 3, 6, 15, 119, 252])
        self.assertEqual(parse_parameter_request_list("1;3; 6"), [1, 3, 6])
        self.assertEqual(parse_parameter_request_list(""), [])
        self.assertEqual(parse_parameter_request_list("999,abc,-1,255"), [])

    def test_android_vendor_class_is_explained(self):
        result = analyse_dhcp_identity("android-dhcp-13", "phone", "1,3,6,15")
        self.assertEqual(result["hints"][0]["category"], "Android mobile client")
        self.assertEqual(result["hints"][0]["confidence"], 78)
        self.assertIn("client-supplied", result["limitations"][0])

    def test_busybox_and_dhcpcd_are_not_exact_os_claims(self):
        busybox = analyse_dhcp_identity("udhcp 1.36.1")
        dhcpcd = analyse_dhcp_identity("dhcpcd-10.0.6")
        self.assertEqual(busybox["hints"][0]["category"], "Embedded Linux DHCP client")
        self.assertEqual(dhcpcd["hints"][0]["category"], "dhcpcd-based client")

    def test_pxe_is_a_role_not_a_device_model(self):
        result = analyse_dhcp_identity("PXEClient:Arch:00007")
        self.assertEqual(result["hints"][0]["attribute"], "network_role")
        self.assertEqual(result["hints"][0]["category"], "PXE network-boot client")

    def test_prl_is_preserved_without_os_guess(self):
        result = analyse_dhcp_identity("", "", "1,3,6,15,119,121,252")
        self.assertEqual(result["hints"], [])
        self.assertIn("classless_static_routes option requested", result["features"])
        self.assertEqual(result["fingerprint"]["parameter_request_list_names"][0], "subnet_mask")

    def test_hostname_hints_are_low_confidence(self):
        result = analyse_dhcp_identity("", "Office-Printer-01")
        self.assertEqual(result["hints"][0]["category"], "Printer candidate")
        self.assertEqual(result["hints"][0]["confidence"], 62)

    def test_empty_input_is_safe(self):
        result = analyse_dhcp_identity()
        self.assertEqual(result["hints"], [])
        self.assertEqual(result["fingerprint"]["parameter_request_list"], [])


if __name__ == "__main__":
    unittest.main()
