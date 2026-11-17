import unittest

from networkradar_modules.identity.investigation import build_identity_next_steps


class IdentityInvestigationTests(unittest.TestCase):
    def test_unauthorised_device_gets_passive_guidance_only(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.20", "device_type": "Unclassified network device"},
            [],
            authorised=False,
        )
        self.assertFalse(result["authorised_active_discovery"])
        self.assertTrue(any("passive" in item["action"].lower()
                            for item in result["next_actions"]))
        self.assertFalse(any("Run a bounded authorised TCP" in item["action"]
                             for item in result["next_actions"]))

    def test_exact_model_is_not_invented(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.21", "model": "", "identification_confidence": 20},
            ["MAC OUI"],
            authorised=True,
        )
        self.assertEqual(result["model"], "Not established")
        self.assertEqual(result["model_status"], "NOT_ESTABLISHED")
        self.assertTrue(any("exact hardware model" in item["action"].lower()
                            for item in result["next_actions"]))

    def test_existing_evidence_suppresses_duplicate_collection_actions(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.22", "device_type": "Printer", "model": "Reported model",
             "identification_confidence": 80},
            ["DHCP", "mDNS/DNS-SD", "SSDP/UPnP", "Nmap service", "SNMPv3",
             "LLDP/CDP", "Enrolled endpoint inventory"],
            dhcp_observed=True,
            authorised=True,
        )
        actions = " ".join(item["action"] for item in result["next_actions"])
        self.assertNotIn("Run the bounded, authorised mDNS", actions)
        self.assertNotIn("Run the existing rate-limited SSDP", actions)
        self.assertNotIn("Run a bounded authorised TCP", actions)
        self.assertEqual(result["identity_status"], "HIGH_CONFIDENCE")
        self.assertEqual(result["model_status"], "DEVICE_REPORTED")


    def test_printer_gets_protocol_specific_guidance_without_model_claim(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.30", "device_type": "Printer", "identification_confidence": 54},
            ["MAC OUI"],
            authorised=False,
        )
        self.assertIn("IPP", result["next_actions"][0]["action"])
        self.assertIn("exact model", result["next_actions"][0]["reason"].lower())
        self.assertEqual(result["model"], "Not established")

    def test_windows_endpoint_gets_passive_host_identity_guidance(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.31", "device_type": "Windows computer"},
            [],
            authorised=False,
        )
        self.assertIn("NetBIOS", result["next_actions"][0]["action"])
        self.assertIn("exact hardware model", result["next_actions"][0]["reason"].lower())

    def test_media_device_guidance_keeps_advertised_model_unverified(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.32", "device_type": "Smart TV / media streamer"},
            [],
            authorised=False,
        )
        self.assertIn("unverified claims", result["next_actions"][0]["action"])

    def test_vxworks_fingerprint_is_not_treated_as_device_model(self):
        result = build_identity_next_steps(
            {"ip": "192.168.1.33", "device_type": "Unclassified device",
             "os_guess": "VxWorks (97% Nmap match accuracy)"},
            ["Nmap OS fingerprint"],
            authorised=False,
        )
        self.assertIn("OS-family hypothesis", result["next_actions"][0]["action"])
        self.assertEqual(result["model_status"], "NOT_ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
