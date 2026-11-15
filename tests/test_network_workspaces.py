import sqlite3
import unittest
from networkradar_modules.network.workspaces import (
    classify_interface_type, ensure_workspace, parse_netsh_wlan_interfaces,
    record_interface_observation, has_strong_network_anchor,
)

class NetworkWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("""
            CREATE TABLE network_workspaces(network_id TEXT PRIMARY KEY, display_name TEXT, network_type TEXT, created_at TEXT, last_seen TEXT, current_fingerprint TEXT, status TEXT);
            CREATE TABLE network_workspace_authorizations(network_id TEXT NOT NULL, fingerprint TEXT NOT NULL, approved INTEGER DEFAULT 0, last_authorized TEXT DEFAULT '', approved_by TEXT DEFAULT '', updated_at TEXT NOT NULL, PRIMARY KEY(network_id,fingerprint));
            CREATE TABLE network_fingerprint_history(fingerprint TEXT PRIMARY KEY, network_id TEXT, first_seen TEXT, last_seen TEXT, network TEXT, gateway TEXT, gateway_mac TEXT, dns_servers TEXT, ssid TEXT, bssid TEXT, interface_name TEXT, interface_guid TEXT, confidence INTEGER, fingerprint_raw TEXT);
            CREATE TABLE network_interface_observations(id INTEGER PRIMARY KEY, network_id TEXT, timestamp TEXT, interface_index INTEGER, interface_name TEXT, interface_guid TEXT, interface_description TEXT, interface_type TEXT, status TEXT, ip TEXT, prefix INTEGER, network TEXT, gateway TEXT, gateway_mac TEXT, dns_servers TEXT, dhcp TEXT, ssid TEXT, bssid TEXT, route_metric INTEGER, adapter_mac TEXT, is_primary INTEGER);
        """)
    def tearDown(self):
        self.db.close()
    def test_same_subnet_different_fingerprints_get_distinct_workspaces(self):
        a = {"fingerprint": "fp-home", "network": "192.168.1.0/24", "ssid": "Home"}
        b = {"fingerprint": "fp-office", "network": "192.168.1.0/24", "ssid": "Office"}
        self.assertNotEqual(ensure_workspace(self.db, a, "t1"), ensure_workspace(self.db, b, "t2"))
    def test_legacy_profile_does_not_transfer_approval_between_fingerprints(self):
        from networkradar_modules.network.workspaces import upsert_legacy_network_profile
        self.db.execute("""CREATE TABLE network_profiles(
            network TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
            interface TEXT DEFAULT '', gateway TEXT DEFAULT '', ssid TEXT DEFAULT '',
            approved INTEGER DEFAULT 0, profile_name TEXT DEFAULT '', notes TEXT DEFAULT '',
            fingerprint TEXT DEFAULT '', gateway_mac TEXT DEFAULT '', adapter_mac TEXT DEFAULT '',
            dns_servers TEXT DEFAULT '', bssid TEXT DEFAULT '', last_authorized TEXT DEFAULT '',
            confidence INTEGER DEFAULT 0)""")
        upsert_legacy_network_profile(self.db, {"network":"192.168.1.0/24","fingerprint":"home-fp"}, "t1")
        self.db.execute("UPDATE network_profiles SET approved=1,last_authorized='approved-at'")
        upsert_legacy_network_profile(self.db, {"network":"192.168.1.0/24","fingerprint":"office-fp"}, "t2")
        row = self.db.execute("SELECT approved,last_authorized,fingerprint FROM network_profiles").fetchone()
        self.assertEqual(row, (0, "", "office-fp"))

    def test_authorisation_requires_a_strong_network_anchor(self):
        self.assertFalse(has_strong_network_anchor({
            "fingerprint_raw": {"subnet":"192.168.1.0/24","gateway":"192.168.1.1","dns":["1.1.1.1"]}
        }))
        self.assertTrue(has_strong_network_anchor({
            "fingerprint_raw": {"gateway_mac":"00:11:22:33:44:55"}
        }))
        self.assertTrue(has_strong_network_anchor({
            "fingerprint_raw": '{"bssid":"aa:bb:cc:dd:ee:ff"}'
        }))
        for invalid in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF",
                        "01:11:22:33:44:55", "not-a-mac"):
            with self.subTest(invalid=invalid):
                self.assertFalse(has_strong_network_anchor({
                    "fingerprint_raw": {"gateway_mac": invalid}
                }))

    def test_same_subnet_workspaces_have_isolated_authorisations(self):
        home = ensure_workspace(self.db, {"fingerprint":"home-fp","network":"192.168.1.0/24"}, "t1")
        office = ensure_workspace(self.db, {"fingerprint":"office-fp","network":"192.168.1.0/24"}, "t2")
        self.db.execute("UPDATE network_workspace_authorizations SET approved=1,last_authorized='approved' WHERE network_id=?", (home,))
        states = dict(self.db.execute("SELECT network_id,approved FROM network_workspace_authorizations"))
        self.assertEqual(states[home], 1)
        self.assertEqual(states[office], 0)

    def test_same_fingerprint_reuses_workspace(self):
        a = {"fingerprint": "fp-a", "network": "10.0.0.0/24"}
        self.assertEqual(ensure_workspace(self.db, a, "t1"), ensure_workspace(self.db, a, "t2"))
    def test_missing_fingerprint_does_not_create_workspace(self):
        self.assertEqual(ensure_workspace(self.db, {"network": "10.0.0.0/24"}, "t"), "")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM network_workspaces").fetchone()[0], 0)
    def test_wifi_parser_keeps_interfaces_separate(self):
        rows = parse_netsh_wlan_interfaces("Name : Wi-Fi\nState : connected\nSSID : Home\nBSSID : aa:bb:cc:dd:ee:01\n\nName : Wi-Fi 2\nState : connected\nSSID : Guest\nAP BSSID : aa:bb:cc:dd:ee:02")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["ssid"], "Guest")
        self.assertEqual(rows[1]["bssid"], "AA:BB:CC:DD:EE:02")

    def test_parser_accepts_actual_windows_ap_bssid_label(self):
        output = """There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wireless-AC 9560 160MHz
    GUID                   : 4a54e23f-455a-4e34-b9f2-4ab74d8cf34f
    Physical address       : 96:03:c3:d8:6e:a8
    State                  : connected
    SSID                   : Andrew
    AP BSSID               : b0:19:21:4a:14:6f
    Band                   : 2.4 GHz
"""
        rows = parse_netsh_wlan_interfaces(output)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Wi-Fi")
        self.assertEqual(rows[0]["ssid"], "Andrew")
        self.assertEqual(rows[0]["bssid"], "B0:19:21:4A:14:6F")
        self.assertTrue(has_strong_network_anchor({
            "fingerprint_raw": {"bssid": rows[0]["bssid"]}
        }))
    def test_disconnected_wifi_interface_does_not_supply_a_bssid(self):
        rows = parse_netsh_wlan_interfaces(
            "Name : Wi-Fi\nState : disconnected\nSSID : Home\n"
            "BSSID : aa:bb:cc:dd:ee:01"
        )
        self.assertEqual(rows[0]["bssid"], "")
        self.assertEqual(rows[0]["ssid"], "")

    def test_invalid_bssid_is_not_retained_as_network_anchor(self):
        rows = parse_netsh_wlan_interfaces(
            "Name : Wi-Fi\nState : connected\nSSID : Home\n"
            "BSSID : ff:ff:ff:ff:ff:ff"
        )
        self.assertEqual(rows[0]["bssid"], "")

    def test_interface_type_classification(self):
        self.assertEqual(classify_interface_type("Wi-Fi"), "WIFI")
        self.assertEqual(classify_interface_type("Ethernet 2"), "ETHERNET")
        self.assertEqual(classify_interface_type("WireGuard Tunnel"), "VPN")
        self.assertEqual(classify_interface_type("vEthernet (Default Switch)"), "VIRTUAL")
    def test_interface_observation_is_network_scoped(self):
        record_interface_observation(self.db, "workspace-a", {"idx": 7, "interface": "Wi-Fi", "interface_type": "WIFI", "ip": "192.168.1.20", "prefix": 24}, "t1", True)
        row = self.db.execute("SELECT network_id,interface_name,is_primary FROM network_interface_observations").fetchone()
        self.assertEqual(row, ("workspace-a", "Wi-Fi", 1))

if __name__ == "__main__":
    unittest.main()
