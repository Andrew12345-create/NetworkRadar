import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import networkradar as app


class NetworkContextSnapshotTests(unittest.TestCase):
    def test_fresh_cached_context_is_returned_without_live_discovery(self):
        original = dict(app.NET_CTX)
        try:
            app.NET_CTX.clear()
            app.NET_CTX.update({
                "network": "192.168.100.0/24",
                "gateway": "192.168.100.1",
                "authorized": True,
                "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            with patch.object(app, "detect_network", side_effect=AssertionError(
                    "read endpoint must not trigger PowerShell discovery")):
                snapshot = app.network_context_snapshot()
            self.assertTrue(snapshot["_context_fresh"])
            self.assertEqual(snapshot["gateway"], "192.168.100.1")
            self.assertTrue(snapshot["authorized"])
        finally:
            app.NET_CTX.clear()
            app.NET_CTX.update(original)

    def test_stale_context_is_marked_stale_without_refreshing_it(self):
        original = dict(app.NET_CTX)
        try:
            app.NET_CTX.clear()
            app.NET_CTX.update({
                "network": "192.168.100.0/24",
                "last_checked": (datetime.now() - timedelta(minutes=5)).strftime(
                    "%Y-%m-%d %H:%M:%S"),
            })
            with patch.object(app, "detect_network", side_effect=AssertionError(
                    "snapshot must not trigger live discovery")):
                snapshot = app.network_context_snapshot(max_age_seconds=120)
            self.assertFalse(snapshot["_context_fresh"])
            self.assertGreater(snapshot["_context_age_seconds"], 120)
        finally:
            app.NET_CTX.clear()
            app.NET_CTX.update(original)

    def test_missing_or_invalid_timestamp_fails_closed(self):
        original = dict(app.NET_CTX)
        try:
            for timestamp in ("", "not-a-date"):
                app.NET_CTX.clear()
                app.NET_CTX.update({"last_checked": timestamp})
                snapshot = app.network_context_snapshot()
                self.assertFalse(snapshot["_context_fresh"])
                self.assertIsNone(snapshot["_context_age_seconds"])
        finally:
            app.NET_CTX.clear()
            app.NET_CTX.update(original)


if __name__ == "__main__":
    unittest.main()
