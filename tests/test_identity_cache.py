import unittest

from networkradar_modules.identity.cache import IdentityLookupCache


class IdentityLookupCacheTests(unittest.TestCase):
    def test_positive_results_are_reused(self):
        now = [100.0]
        cache = IdentityLookupCache(positive_ttl=30, clock=lambda: now[0])
        calls = []
        loader = lambda: calls.append(1) or "workstation.local"
        self.assertEqual(cache.get("ptr", "192.168.1.2", "192.168.1.0/24", loader), "workstation.local")
        self.assertEqual(cache.get("ptr", "192.168.1.2", "192.168.1.0/24", loader), "workstation.local")
        self.assertEqual(len(calls), 1)

    def test_negative_results_have_shorter_lifetime(self):
        now = [100.0]
        cache = IdentityLookupCache(positive_ttl=60, negative_ttl=5, clock=lambda: now[0])
        calls = []
        loader = lambda: calls.append(1) or ""
        cache.get("netbios", "192.168.1.3", "192.168.1.0/24", loader)
        now[0] += 6
        cache.get("netbios", "192.168.1.3", "192.168.1.0/24", loader)
        self.assertEqual(len(calls), 2)

    def test_network_change_is_a_distinct_cache_scope(self):
        cache = IdentityLookupCache()
        calls = []
        loader = lambda: calls.append(1) or "device"
        cache.get("ptr", "192.168.1.4", "192.168.1.0/24", loader)
        cache.get("ptr", "192.168.1.4", "10.0.0.0/24", loader)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
