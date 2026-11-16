"""Regression tests for scan quality and identity coverage reporting."""
import sqlite3
import unittest
from unittest.mock import patch

import networkradar as app


class ScanQualityReportTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("""CREATE TABLE scans(
            id INTEGER PRIMARY KEY, timestamp TEXT, network TEXT,
            hosts_up INTEGER, duration REAL
        )""")
        self.conn.execute("""CREATE TABLE devices(
            ip TEXT PRIMARY KEY, device_type TEXT,
            identification_confidence INTEGER
        )""")
        self.net = {
            "network": "192.168.100.0/24", "ip": "192.168.100.139",
            "gateway": "192.168.100.1", "authorized": True,
        }
        self.dns = {"status": "ONLINE", "queries": 20, "responses": 18}
        self.dhcp = {"status": "ONLINE", "messages": 12}
        self.arp = {"status": "ONLINE", "observations": 50}

    def tearDown(self):
        self.conn.close()

    def run_report(self):
        with patch.dict(app.NET_CTX, self.net, clear=True), \
             patch.dict(app.DNS_STATE, self.dns, clear=True), \
             patch.dict(app.DHCP_STATE, self.dhcp, clear=True), \
             patch.dict(app.ARP_STATE, self.arp, clear=True):
            return app.scan_quality_report(self.conn)

    def test_score_has_exactly_one_hundred_available_points(self):
        self.conn.execute(
            "INSERT INTO scans(timestamp,network,hosts_up,duration) VALUES(?,?,?,?)",
            ("2026-11-16 07:00:00", "192.168.100.0/24", 14, 2.5),
        )
        result = self.run_report()
        self.assertEqual(result["score"], 100)
        self.assertEqual(sum(item["maximum"] for item in result["components"]), 100)
        self.assertEqual(sum(item["score"] for item in result["components"]), 100)

    def test_default_and_ambiguous_device_labels_are_not_classified(self):
        self.conn.executemany(
            "INSERT INTO devices(ip,device_type,identification_confidence) VALUES(?,?,?)",
            [
                ("192.168.100.2", "Unclassified device", 80),
                ("192.168.100.3", "Unidentified device", 75),
                ("192.168.100.4", "Unknown", 60),
                ("192.168.100.5", "Ambiguous: Laptop / computer / Android phone", 48),
                ("192.168.100.6", "Laptop / computer", 68),
            ],
        )
        result = self.run_report()
        coverage = result["identity_coverage"]
        self.assertEqual(coverage["total"], 5)
        self.assertEqual(coverage["classified"], 1)
        self.assertEqual(coverage["unclassified"], 4)
        self.assertEqual(coverage["coverage_percent"], 20)
        self.assertEqual(coverage["average_confidence"], 68.0)

    def test_no_scan_and_no_devices_return_zero_without_crashing(self):
        result = self.run_report()
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["identity_coverage"]["total"], 0)
        self.assertEqual(result["identity_coverage"]["coverage_percent"], 0)


if __name__ == "__main__":
    unittest.main()
