import unittest
from unittest.mock import patch

import networkradar as app


class Cursor:
    def __init__(self, rows=None, one=None, rowcount=1):
        self.rows = rows or []
        self.one = one
        self.rowcount = rowcount

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.one


class FakeConnection:
    def __init__(self):
        self.statements = []

    def execute(self, sql, args=()):
        self.statements.append((sql, args))
        if "SELECT ip, status FROM devices" in sql:
            return Cursor(rows=[
                ("192.168.100.1", "ONLINE"),
                ("192.168.100.20", "ONLINE"),
            ])
        if "SELECT COALESCE(offline_misses,0)" in sql:
            return Cursor(one=(0,))
        return Cursor(rowcount=1)


class ActiveDiscoveryAuthorisationTests(unittest.TestCase):
    @patch.object(app, "update_job")
    @patch.object(app, "merge_reachable_neighbors", return_value=[])
    @patch.object(app, "collect_windows_neighbor_cache",
                  return_value={"status": "OK", "records": []})
    @patch.object(app, "sweep_tcp_hosts")
    @patch.object(app, "run_nmap_discovery")
    @patch.object(app, "is_authorized", return_value=False)
    @patch.object(app, "current_network", return_value="192.168.100.0/24")
    def test_unauthorised_discovery_uses_only_local_neighbour_observations(
            self, _network, _auth, nmap, tcp, neighbours, _merge, _progress):
        devices, duration, complete = app.discover_devices()
        self.assertEqual(devices, [])
        self.assertFalse(complete)
        nmap.assert_not_called()
        tcp.assert_not_called()
        neighbours.assert_called_once()

    @patch.object(app, "update_job")
    @patch.object(app, "merge_reachable_neighbors", side_effect=lambda devices, _rows: devices)
    @patch.object(app, "collect_windows_neighbor_cache",
                  return_value={"status": "OK", "records": []})
    @patch.object(app, "sweep_tcp_hosts", return_value={
        "status": "OK", "responders": 0, "devices": [], "duration_seconds": 0
    })
    @patch.object(app, "run_nmap_discovery", return_value=([{
        "ip": "192.168.100.20", "mac": "00:11:22:33:44:55",
        "vendor": "Example", "hostname": "-"
    }], 1.25))
    @patch.object(app, "is_authorized", return_value=True)
    @patch.object(app, "current_network", return_value="192.168.100.0/24")
    def test_authorised_discovery_runs_nmap_and_marks_scope_complete(
            self, _network, _auth, nmap, tcp, neighbours, _merge, _progress):
        devices, duration, complete = app.discover_devices()
        self.assertTrue(complete)
        self.assertEqual(devices[0]["ip"], "192.168.100.20")
        self.assertEqual(duration, 1.25)
        nmap.assert_called_once()
        tcp.assert_called_once()
        neighbours.assert_called_once()

    @patch.object(app.DB_MANAGER, "write")
    def test_partial_inventory_does_not_advance_offline_misses(self, write):
        conn = FakeConnection()
        write.side_effect = lambda callback: callback(conn)
        app.update_inventory([{
            "ip": "192.168.100.20", "mac": "00:11:22:33:44:55",
            "vendor": "Example", "hostname": "-"
        }], complete_scope=False)
        sql = "\n".join(statement for statement, _args in conn.statements)
        self.assertNotIn("offline_misses=", sql)
        self.assertNotIn("status='OFFLINE'", sql)

    @patch.object(app.DB_MANAGER, "write")
    def test_complete_inventory_can_advance_offline_misses(self, write):
        conn = FakeConnection()
        write.side_effect = lambda callback: callback(conn)
        app.update_inventory([{
            "ip": "192.168.100.20", "mac": "00:11:22:33:44:55",
            "vendor": "Example", "hostname": "-"
        }], complete_scope=True)
        sql = "\n".join(statement for statement, _args in conn.statements)
        self.assertIn("offline_misses=", sql)

    @patch.object(app, "_ssdp_scan")
    @patch.object(app, "is_authorized", return_value=False)
    def test_ssdp_msearch_is_blocked_without_authorisation(self, auth, scan):
        self.assertEqual(app.ssdp_scan(), {})
        scan.assert_not_called()

    @patch.object(app.socket, "create_connection")
    @patch.object(app, "is_authorized", return_value=False)
    def test_tls_handshake_is_blocked_without_authorisation(self, auth, connect):
        self.assertEqual(app.tls_certificate_intelligence(
            "192.168.100.20", [443]
        ), [])
        connect.assert_not_called()

    @patch.object(app.shutil, "which")
    @patch.object(app, "is_authorized", return_value=False)
    def test_snmp_is_blocked_without_authorisation(self, auth, which):
        self.assertEqual(app.snmpv3_intelligence("192.168.100.20"), {})
        which.assert_not_called()

    @patch.object(app.urllib.request, "build_opener")
    @patch.object(app, "is_authorized", return_value=False)
    def test_service_banner_probe_is_blocked_without_authorisation(self, auth, opener):
        self.assertEqual(app.service_banner_intelligence(
            "192.168.100.20", [80, 22]
        ), [])
        opener.assert_not_called()

    @patch.object(app, "netbios_name")
    @patch.object(app, "reverse_dns")
    @patch.object(app, "is_authorized", return_value=False)
    def test_name_lookups_are_skipped_without_authorisation(self, auth, reverse, netbios):
        device = {
            "ip": "192.168.100.20", "mac": "Unavailable", "vendor": "Unknown",
            "hostname": "-", "device_name": "", "port_numbers": [],
            "services_found": [], "os_guess": "Unknown"
        }
        app.identify_device(device, ssdp={}, deep=False)
        reverse.assert_not_called()
        netbios.assert_not_called()


if __name__ == "__main__":
    unittest.main()
