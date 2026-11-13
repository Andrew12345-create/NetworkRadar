"""Tests for IEEE MA-L, MA-M and MA-S registry parsing and matching."""
import unittest

from networkradar_modules.identity.oui import (
    lookup_ieee_assignment,
    normalise_mac_hex,
    parse_ieee_registry,
)


class IEEERegistryTests(unittest.TestCase):
    def test_normalise_mac_hex_rejects_bad_values(self):
        self.assertEqual(normalise_mac_hex("00:11:22:33:44:55"), "001122334455")
        self.assertEqual(normalise_mac_hex("00-11-22-33-44-55"), "001122334455")
        self.assertEqual(normalise_mac_hex("02:11:22:33:44:5Z"), "")
        self.assertEqual(normalise_mac_hex("not-a-mac"), "")

    def test_parse_legacy_text_for_all_three_block_sizes(self):
        fixtures = {
            "MA-L": "00-11-22 (hex) Large Example Ltd\n",
            "MA-M": "00-11-22-3 (hex) Medium Example Ltd\n",
            "MA-S": "00-11-22-3A-4 (hex) Small Example Ltd\n",
        }
        for registry, raw in fixtures.items():
            with self.subTest(registry=registry):
                parsed = parse_ieee_registry(raw, registry)
                self.assertEqual(len(parsed), 1)
                entry = next(iter(parsed.values()))
                self.assertEqual(entry["registry"], registry)
                self.assertIn("Example Ltd", entry["organization"])

    def test_parse_csv_listing(self):
        raw = (
            "Registry,Assignment,Organization Name,Organization Address\n"
            "MA-M,0011223,Medium Example Ltd,Somewhere\n"
        )
        parsed = parse_ieee_registry(raw, "MA-M")
        self.assertEqual(parsed["0011223"]["organization"], "Medium Example Ltd")

    def test_longest_assignment_wins(self):
        assignments = {
            "001122": {"organization": "Large Example", "registry": "MA-L"},
            "0011223": {"organization": "Medium Example", "registry": "MA-M"},
            "0011223A4": {"organization": "Small Example", "registry": "MA-S", "updated_at": "2026-11-13 10:00:00"},
        }
        result = lookup_ieee_assignment("00:11:22:3A:4B:5C", assignments)
        self.assertEqual(result["organization"], "Small Example")
        self.assertEqual(result["registry"], "MA-S")
        self.assertEqual(result["prefix_bits"], 36)
        self.assertEqual(result["updated_at"], "2026-11-13 10:00:00")
        self.assertIn("not proof", result["interpretation"])

    def test_ma_m_and_ma_s_are_not_mislabelled_as_oui(self):
        assignments = {
            "0011223": {"organization": "Medium Example", "registry": "MA-M"},
        }
        result = lookup_ieee_assignment("00:11:22:3A:4B:5C", assignments)
        self.assertEqual(result["assignment_type"], "medium MAC address block")
        self.assertNotIn("OUI)", result["assignment_type"])

    def test_local_and_multicast_addresses_are_not_attributed(self):
        assignments = {
            "001122": {"organization": "Example", "registry": "MA-L"},
        }
        self.assertEqual(lookup_ieee_assignment("02:11:22:33:44:55", assignments), {})
        self.assertEqual(lookup_ieee_assignment("01:11:22:33:44:55", assignments), {})
        self.assertEqual(lookup_ieee_assignment("bad", assignments), {})

    def test_unknown_registry_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ieee_registry("", "CID")


if __name__ == "__main__":
    unittest.main()
