"""Tests for evidence-family restrictions in device recognition."""
import unittest

from networkradar_modules.identity.recognition import recognition_family_compatible


class RecognitionFamilyTests(unittest.TestCase):
    def test_ieee_registrant_cannot_satisfy_device_category_signatures(self):
        for rule in ("product", "service", "reported", "os", "dhcp", "any"):
            with self.subTest(rule=rule):
                self.assertFalse(recognition_family_compatible(rule, "oui"))

    def test_os_rules_accept_os_and_passive_tcp_evidence_only(self):
        self.assertTrue(recognition_family_compatible("os", "os"))
        self.assertTrue(recognition_family_compatible("os", "tcpip"))
        self.assertFalse(recognition_family_compatible("os", "reported"))

    def test_product_rules_do_not_use_manufacturer_or_service_text(self):
        self.assertTrue(recognition_family_compatible("product", "product"))
        self.assertFalse(recognition_family_compatible("product", "reported"))
        self.assertFalse(recognition_family_compatible("product", "service"))

    def test_service_rules_accept_discovery_service_evidence(self):
        for family in ("service", "mdns", "upnp", "snmp"):
            with self.subTest(family=family):
                self.assertTrue(recognition_family_compatible("service", family))

    def test_reported_rules_accept_device_reported_names(self):
        self.assertTrue(recognition_family_compatible("reported", "reported"))
        self.assertTrue(recognition_family_compatible("reported", "upnp"))
        self.assertFalse(recognition_family_compatible("reported", "oui"))

    def test_unknown_rule_families_fail_closed(self):
        self.assertFalse(recognition_family_compatible("unknown", "reported"))
        self.assertFalse(recognition_family_compatible("", "reported"))


if __name__ == "__main__":
    unittest.main()
