import unittest

from networkradar_modules.identity.subscan import IdentitySubscanCoordinator


class IdentitySubscanCoordinatorTests(unittest.TestCase):
    def device(self, ip="192.168.100.20", **overrides):
        value = {
            "ip": ip, "mac": "AA:BB:CC:DD:EE:20",
            "hostname": "", "device_name": "Unidentified device",
            "device_type": "Unclassified network device",
            "identification_confidence": 0, "open_ports": "",
        }
        value.update(overrides)
        return value

    def test_observation_deduplicates_same_device(self):
        queue = IdentitySubscanCoordinator()
        self.assertEqual(queue.observe([self.device()], now=100), 1)
        self.assertEqual(queue.observe([self.device()], now=110), 0)
        self.assertEqual(queue.snapshot(now=110)["total_targets"], 1)

    def test_claims_only_one_target_and_applies_backoff(self):
        queue = IdentitySubscanCoordinator(max_attempts=3, base_backoff=10)
        queue.observe([self.device()], now=100)
        first = queue.claim_due(now=100)
        self.assertIsNotNone(first)
        self.assertIsNone(queue.claim_due(now=100))
        result = queue.complete(first["key"], recognised=False, now=100)
        self.assertEqual(result["state"], "QUEUED")
        self.assertEqual(result["next_attempt_at"], 110)
        self.assertIsNone(queue.claim_due(now=109))
        self.assertIsNotNone(queue.claim_due(now=110))

    def test_retry_limit_exhausts_unresponsive_device(self):
        queue = IdentitySubscanCoordinator(max_attempts=2, base_backoff=1)
        queue.observe([self.device()], now=100)
        first = queue.claim_due(now=100)
        queue.complete(first["key"], recognised=False, now=100)
        second = queue.claim_due(now=101)
        result = queue.complete(second["key"], recognised=False, error="timeout", now=101)
        self.assertEqual(result["state"], "EXHAUSTED")
        self.assertIsNone(queue.claim_due(now=100000))

    def test_recognised_device_resolves_and_fresh_evidence_reopens(self):
        queue = IdentitySubscanCoordinator(max_attempts=1)
        original = self.device()
        queue.observe([original], now=100)
        claimed = queue.claim_due(now=100)
        queue.complete(claimed["key"], recognised=True, now=101)
        self.assertEqual(queue.snapshot()["counts"]["resolved"], 1)
        changed = self.device(hostname="new-hostname")
        self.assertEqual(queue.observe([changed], now=102), 1)
        self.assertEqual(queue.snapshot(now=102)["counts"]["queued"], 1)

    def test_progress_is_separate_and_queue_completion_is_reported(self):
        queue = IdentitySubscanCoordinator(max_attempts=2, base_backoff=1)
        queue.observe([self.device()], now=100)
        task = queue.claim_due(now=100)
        queue.update_progress(task["key"], "Nmap TCP/OS fingerprint", 45,
                              "Nmap is running.", now=101)
        snapshot = queue.snapshot(now=101)
        self.assertEqual(snapshot["progress"]["ip"], "192.168.100.20")
        self.assertEqual(snapshot["progress"]["phase"], "Nmap TCP/OS fingerprint")
        self.assertEqual(snapshot["progress"]["percent"], 45)
        self.assertEqual(snapshot["queue_progress_percent"], 0)
        queue.complete(task["key"], recognised=True, now=102)
        snapshot = queue.snapshot(now=102)
        self.assertEqual(snapshot["progress"]["state"], "COMPLETED")
        self.assertEqual(snapshot["progress"]["percent"], 100)
        self.assertEqual(snapshot["processed_targets"], 1)
        self.assertEqual(snapshot["queue_progress_percent"], 100)

    def test_pause_blocks_claiming(self):
        queue = IdentitySubscanCoordinator()
        queue.observe([self.device()], now=100)
        queue.pause()
        self.assertIsNone(queue.claim_due(now=100))
        queue.resume()
        self.assertIsNotNone(queue.claim_due(now=100))

    def test_rejects_non_private_targets(self):
        queue = IdentitySubscanCoordinator()
        self.assertEqual(queue.observe([self.device("8.8.8.8")]), 0)
        self.assertEqual(queue.snapshot()["total_targets"], 0)


if __name__ == "__main__":
    unittest.main()
