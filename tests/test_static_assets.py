"""Static asset packaging regression tests."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DashboardAssetTests(unittest.TestCase):
    def test_stylesheet_is_a_real_nonempty_asset(self):
        css = ROOT / "networkradar.css"
        self.assertTrue(css.is_file())
        content = css.read_text(encoding="utf-8")
        self.assertGreater(len(content), 1000)
        self.assertEqual(content.count("{"), content.count("}"))
        self.assertIn("#sideNavigation", content)
        self.assertIn(".terminal-output", content)

    def test_dashboard_javascript_is_a_real_nonempty_asset(self):
        js = ROOT / "dashboard.js"
        self.assertTrue(js.is_file())
        self.assertGreater(js.stat().st_size, 10000)

    def test_html_references_both_external_assets(self):
        source = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn(
            'href="/assets/networkradar.css?v={APP_VERSION}"', source
        )
        self.assertIn(
            'src="/assets/dashboard.js?v={APP_VERSION}" defer', source
        )
        self.assertNotIn("DASHBOARD_JS_BUNDLED", source)

    def test_server_has_routes_for_both_assets(self):
        source = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn('p.path == "/assets/networkradar.css"', source)
        self.assertIn('p.path == "/assets/dashboard.js"', source)


if __name__ == "__main__":
    unittest.main()
