import unittest

from networkradar_modules.identity.domain_intelligence import (
    build_domain_activity, classify_domain,
)


class DomainIntelligenceTests(unittest.TestCase):
    def test_search_engine_domain_is_classified_not_search_phrase(self):
        self.assertEqual(classify_domain("www.google.com")["provider"], "Google")
        self.assertEqual(classify_domain("www.google.com")["category"], "SEARCH")

    def test_unknown_and_internal_domains_remain_conservative(self):
        self.assertEqual(classify_domain("printer.local")["category"], "IGNORED")
        self.assertEqual(classify_domain("example.net")["category"], "OTHER")

    def test_aggregates_per_device_without_claiming_query_text(self):
        result = build_domain_activity([
            ("2026-11-17 10:00:00", "192.168.1.10", "www.google.com", "A", 3),
            ("2026-11-17 10:01:00", "192.168.1.10", "youtube.com", "AAAA", 2),
            ("2026-11-17 10:02:00", "8.8.8.8", "google.com", "A", 9),
        ])
        self.assertEqual(result["observed_query_count"], 5)
        self.assertEqual(result["unique_device_domain_pairs"], 2)
        self.assertEqual(result["search_providers"][0]["provider"], "Google")
        self.assertTrue(any("HTTPS search phrases" in item for item in result["limitations"]))


if __name__ == "__main__":
    unittest.main()
