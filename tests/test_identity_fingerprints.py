"""Regression tests for pure identity and fingerprint primitives."""
import unittest

from networkradar_modules.identity.fingerprints import (
    derive_identity, dhcp_fingerprint, mac_properties, normalise_mac,
)


class IdentityFingerprintTests(unittest.TestCase):
    def test_mac_normalisation_accepts_colon_and_hyphen_forms(self):
        expected = "A0:B1:C2:D3:E4:F5"
        self.assertEqual(normalise_mac("a0:b1:c2:d3:e4:f5"), expected)
        self.assertEqual(normalise_mac("a0-b1-c2-d3-e4-f5"), expected)

    def test_invalid_mac_is_rejected(self):
        for value in ("", "Unknown", "00:11:22:33:44", "GG:11:22:33:44:55",
                      "0011.2233.4455"):
            self.assertEqual(normalise_mac(value), "")
        self.assertEqual(normalise_mac("01:00:00:00:00:00"), "01:00:00:00:00:00")

    def test_mac_properties_distinguish_global_local_and_multicast(self):
        self.assertTrue(mac_properties("00:11:22:33:44:55")["unicast"])
        self.assertFalse(mac_properties("00:11:22:33:44:55")["locally_administered"])
        self.assertTrue(mac_properties("02:11:22:33:44:55")["locally_administered"])
        self.assertTrue(mac_properties("01:11:22:33:44:55")["multicast"])
        self.assertFalse(mac_properties("bad")["valid"])

    def test_global_mac_derives_stable_cross_ip_identity(self):
        first = derive_identity({"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"})
        second = derive_identity({"ip": "192.168.1.99", "mac": "00-11-22-33-44-55"})
        self.assertEqual(first, second)
        self.assertEqual(first[1], "mac:00:11:22:33:44:55")
        self.assertEqual(first[2], "MAC")

    def test_locally_administered_mac_is_scoped_to_ip(self):
        first = derive_identity({"ip": "192.168.1.10", "mac": "02:11:22:33:44:55"})
        other_ip = derive_identity({"ip": "192.168.1.11", "mac": "02:11:22:33:44:55"})
        self.assertNotEqual(first[0], other_ip[0])
        self.assertEqual(first[1], "ip:192.168.1.10")
        self.assertIn("ignored", first[2])

    def test_missing_or_invalid_mac_uses_ip_fallback(self):
        a = derive_identity({"ip": "10.0.0.5", "mac": "Unavailable"})
        b = derive_identity({"ip": "10.0.0.5", "mac": ""})
        self.assertEqual(a, b)
        self.assertEqual(a[1], "ip:10.0.0.5")

    def test_identity_requires_ip(self):
        with self.assertRaises(ValueError):
            derive_identity({"mac": "00:11:22:33:44:55"})

    def test_dhcp_fingerprint_is_normalised_and_deterministic(self):
        a = dhcp_fingerprint("  WINDOWS   11 ", "1, 3,6,15")
        b = dhcp_fingerprint("windows 11", "1,3,6,15")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 24)
        self.assertNotEqual(a, dhcp_fingerprint("linux", "1,3,6,15"))


if __name__ == "__main__":
    unittest.main()
