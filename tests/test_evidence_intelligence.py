import unittest
from datetime import datetime, timezone, timedelta

from networkradar_modules.identity.evidence_intelligence import (
    evidence_freshness, rank_evidence, reconcile_identity_assessment,
    plan_investigation_methods,
)


class EvidenceIntelligenceTests(unittest.TestCase):
    def test_missing_timestamp_is_not_treated_as_fresh(self):
        result = evidence_freshness("")
        self.assertEqual(result["state"], "UNDATED")
        self.assertEqual(result["factor"], 0.0)

    def test_expired_evidence_does_not_contribute(self):
        now = datetime(2026, 11, 17, tzinfo=timezone.utc)
        result = evidence_freshness(now - timedelta(days=100), now=now)
        self.assertEqual(result["state"], "EXPIRED")
        self.assertEqual(result["factor"], 0.0)

    def test_duplicate_source_family_is_capped(self):
        now = datetime(2026, 11, 17, tzinfo=timezone.utc)
        rows = [
            {"source": "Nmap", "attribute": "device category", "value": "Windows computer",
             "confidence": 90, "evidence_class": "OBSERVED", "last_seen": now.isoformat()},
            {"source": "Nmap OS", "attribute": "device category", "value": "Windows computer",
             "confidence": 95, "evidence_class": "OBSERVED", "last_seen": now.isoformat()},
        ]
        result = rank_evidence(rows, now=now)
        item = result["attributes"]["device category"]
        self.assertEqual(item["independent_sources"], 1)
        self.assertEqual(len(item["sources"]), 1)

    def test_independent_sources_support_same_candidate(self):
        now = datetime(2026, 11, 17, tzinfo=timezone.utc)
        rows = [
            {"source": "Nmap", "attribute": "os", "value": "Windows 11",
             "confidence": 85, "evidence_class": "OBSERVED", "last_seen": now.isoformat()},
            {"source": "DHCP", "attribute": "os", "value": "Windows 11",
             "confidence": 70, "evidence_class": "INFERRED", "last_seen": now.isoformat()},
        ]
        result = rank_evidence(rows, now=now)
        self.assertEqual(result["attributes"]["os"]["independent_sources"], 2)

    def test_absence_of_current_evidence_retains_historical_identity(self):
        result = reconcile_identity_assessment(
            {"device_type": "Unclassified network device", "confidence": 0},
            {"device_type": "Windows computer", "identification_confidence": 84},
        )
        self.assertEqual(result["accepted"]["device_type"], "Windows computer")
        self.assertEqual(result["action"], "RETAINED_NO_NEW_EVIDENCE")

    def test_weak_conflicting_identity_cannot_replace_stronger_identity(self):
        result = reconcile_identity_assessment(
            {"device_type": "Linux / Unix computer", "confidence": 67},
            {"device_type": "Windows computer", "identification_confidence": 84},
        )
        self.assertEqual(result["accepted"]["device_type"], "Windows computer")
        self.assertEqual(result["action"], "RETAINED_CONFLICTING_IDENTITY")

    def test_stronger_new_identity_can_replace_retained_identity(self):
        result = reconcile_identity_assessment(
            {"device_type": "Printer", "confidence": 94},
            {"device_type": "Windows computer", "identification_confidence": 84},
        )
        self.assertEqual(result["accepted"]["device_type"], "Printer")
        self.assertEqual(result["action"], "REPLACED_WITH_STRONGER_EVIDENCE")

    def test_dhcp_is_not_recommended_when_capture_is_unavailable(self):
        result = plan_investigation_methods(
            {"ip": "192.168.1.22", "status": "ONLINE",
             "dhcp_capture_status": "UNAVAILABLE"},
            [], {}, authorised=True,
        )
        self.assertNotIn("dhcp", [row["method"] for row in result["planned"]])
        self.assertIn("COLLECTOR_UNAVAILABLE",
                      [row["state"] for row in result["deferred"]])

    def test_offline_device_waits_without_consuming_probe_plan(self):
        result = plan_investigation_methods(
            {"ip": "192.168.1.22", "status": "OFFLINE"}, [], {}, authorised=True,
        )
        self.assertEqual(result["planned"], [])
        self.assertTrue(all(row["state"] == "WAITING_FOR_ONLINE"
                            for row in result["deferred"]))

    def test_active_methods_require_authorisation(self):
        result = plan_investigation_methods(
            {"ip": "192.168.1.22", "status": "ONLINE"}, [], {}, authorised=False,
        )
        self.assertNotIn("nmap", [row["method"] for row in result["planned"]])
        self.assertIn("AUTHORIZATION_REQUIRED",
                      [row["state"] for row in result["deferred"]])


if __name__ == "__main__":
    unittest.main()
