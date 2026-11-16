import unittest

from networkradar_modules.identity.engine import analyse_device_profile


class AdvancedDeviceProfileTests(unittest.TestCase):
    def test_android_dhcp_fingerprint_identifies_mobile_family(self):
        result = analyse_device_profile({
            "ip": "192.168.100.120",
            "mac": "5E:11:22:33:44:55",
            "dhcp_identity": [{"vendor_class": "android-dhcp-13",
                               "hostname": "", "user_class": "", "client_fqdn": ""}],
        })
        self.assertEqual(result["selected_category"], "Android mobile device")
        self.assertGreaterEqual(result["confidence"], 58)
        self.assertIn("dhcp", result["source_families"])

    def test_oui_and_randomized_mac_never_classify_phone_or_model(self):
        result = analyse_device_profile({
            "ip": "192.168.100.120",
            "mac": "5E:11:22:33:44:55",
            "vendor": "Samsung Electronics",
            "oui_assignment": {"organization": "Samsung Electronics"},
        })
        self.assertEqual(result["selected_category"], "Unclassified network device")
        self.assertEqual(result["model"], "")
        self.assertEqual(result["manufacturer"], "")
        self.assertEqual(result["nic_manufacturer"], "Samsung Electronics")

    def test_amazon_oui_does_not_mean_fire_tv_or_echo(self):
        result = analyse_device_profile({
            "ip": "192.168.100.71",
            "mac": "00:11:22:33:44:55",
            "vendor": "Amazon Technologies Inc.",
        })
        self.assertEqual(result["selected_category"], "Unclassified network device")

    def test_android_hostname_is_only_a_probable_name_signal(self):
        result = analyse_device_profile({
            "ip": "192.168.100.120",
            "hostname": "android-8f31a9",
        })
        self.assertEqual(result["category"], "Android mobile device")
        self.assertLess(result["confidence"], 58)
        self.assertEqual(result["selected_category"], "Unclassified network device")

    def test_dns_sd_google_cast_means_cast_capability_not_android_phone(self):
        result = analyse_device_profile({
            "ip": "192.168.100.30",
            "mdns_records": "_googlecast._tcp.local",
        })
        self.assertEqual(result["selected_category"], "Smart TV / media streamer")
        self.assertNotEqual(result["selected_category"], "Android mobile device")

    def test_printer_requires_service_or_device_report_evidence(self):
        result = analyse_device_profile({
            "ip": "192.168.100.40",
            "mdns_records": "_ipp._tcp.local",
            "nmap_service_intel": [{"port": 631, "name": "ipp", "product": "CUPS"}],
        })
        self.assertEqual(result["selected_category"], "Printer")
        self.assertGreaterEqual(result["confidence"], 58)

    def test_open_ports_alone_never_assert_a_printer(self):
        result = analyse_device_profile({
            "ip": "192.168.100.40",
            "port_numbers": [631, 9100],
        })
        self.assertEqual(result["selected_category"], "Unclassified network device")
        self.assertTrue(result["port_clues"])

    def test_service_combination_parser_handles_port_prefixed_strings(self):
        result = analyse_device_profile({
            "ip": "192.168.100.40",
            "services_found": ["631/ipp CUPS", "80/http Apache"],
        })
        self.assertEqual(result["selected_category"], "Printer")

    def test_upnp_reported_model_and_manufacturer_are_separate_from_oui(self):
        result = analyse_device_profile({
            "ip": "192.168.100.50",
            "vendor": "LG Innotek",
            "ssdp_intel": {"manufacturer": "Samsung Electronics",
                           "modelname": "Smart TV", "modelnumber": "UE55"},
        })
        self.assertEqual(result["manufacturer"], "Samsung Electronics")
        self.assertEqual(result["model"], "Smart TV UE55")
        self.assertEqual(result["nic_manufacturer"], "LG Innotek")

    def test_same_family_does_not_stack_repeated_hostname_fields(self):
        result = analyse_device_profile({
            "ip": "192.168.100.120",
            "hostname": "Samsung Galaxy S24",
            "friendly_name": "Samsung Galaxy S24",
            "device_name": "Samsung Galaxy S24",
        })
        self.assertLess(result["confidence"], 80)
        self.assertEqual(result["source_families"].count("reported_name"), 1)

    def test_nmap_os_and_smb_host_script_are_independent_evidence(self):
        result = analyse_device_profile({
            "ip": "192.168.100.82",
            "os_guess": "Microsoft Windows 11",
            "nmap_script_intel": [{"id": "smb-os-discovery",
                                   "output": "OS: Windows 11 Pro\nComputer name: ANDREWSTHINKPAD"}],
        })
        self.assertEqual(result["selected_category"], "Windows computer")
        self.assertGreaterEqual(result["confidence"], 80)
        self.assertEqual(result["operating_system"]["family"], "Windows")

    def test_model_is_not_inferred_from_service_banner(self):
        result = analyse_device_profile({
            "ip": "192.168.100.20",
            "service_intel": [{"port": 80, "server": "LG webOS/4.0",
                               "http_title": "LG OLED55 TV"}],
        })
        self.assertEqual(result["model"], "")

    def test_gateway_role_is_explicit_and_high_confidence(self):
        result = analyse_device_profile({"ip": "192.168.100.1", "_is_gateway": True})
        self.assertEqual(result["selected_category"], "Router / firewall")
        self.assertEqual(result["confidence"], 98)


if __name__ == "__main__":
    unittest.main()
