"""Regression tests for evidence-coverage reporting."""
import unittest

from networkradar_modules.identity.quality import assess_identity_quality


class IdentityQualityTests(unittest.TestCase):
    def test_empty_device_reports_zero_coverage(self):
        result = assess_identity_quality({})
        self.assertEqual(result["coverage_score"], 0)
        self.assertEqual(result["evidence_count"], 0)
        self.assertEqual(result["independent_families"], 0)

    def test_domain_coverage_is_bounded_and_explainable(self):
        result = assess_identity_quality({
            "ip": "192.168.1.20",
            "mac": "00:11:22:33:44:55",
            "hostname": "workstation",
            "os_guess": "Windows",
            "open_ports": "80,443",
            "service_summary": "https",
            "reported_manufacturer": "Example",
            "model": "Model X",
        }, facts=[
            {"family": "upnp", "value": "Model X"},
            {"family": "os", "value": "Windows"},
        ], recognition={"category": "Computer", "matches": [{"category": "Computer"}]})
        self.assertGreater(result["coverage_score"], 0)
        self.assertLessEqual(result["coverage_score"], 100)
        self.assertEqual(result["independent_families"], 2)
        self.assertEqual(
            {x["key"] for x in result["domains"]},
            {"hardware", "operating_system", "network", "services", "classification", "evidence"},
        )

    def test_oui_alone_does_not_create_device_classification(self):
        result = assess_identity_quality(
            {"oui_assignment": {"organization": "NIC Assignee"}},
            recognition={"category": "Unclassified network device", "matches": []},
        )
        domains = {x["key"]: x for x in result["domains"]}
        self.assertEqual(domains["classification"]["score"], 0)
        self.assertEqual(domains["hardware"]["score"], 25)

    def test_generated_device_name_placeholder_does_not_inflate_network_coverage(self):
        result = assess_identity_quality({
            "device_name": "Unidentified device",
            "friendly_name": "Unknown device at 192.168.1.20",
        })
        domains = {item["key"]: item for item in result["domains"]}
        self.assertEqual(domains["network"]["observed"], 0)
        self.assertEqual(domains["network"]["score"], 0)

    def test_coverage_is_not_reported_as_probability(self):
        result = assess_identity_quality({"ip": "192.168.1.1"})
        self.assertTrue(any("not identity probability" in x for x in result["limitations"]))


if __name__ == "__main__":
    unittest.main()
