"""Static asset packaging regression tests."""
from pathlib import Path
import re
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
        self.assertIn("NETWORKRADAR 13.7.0", content)
        self.assertIn(":focus-visible", content)
        self.assertIn("prefers-reduced-motion:reduce", content)
        # Six dashboard KPIs and five workspace tabs must match their desktop grids.
        self.assertRegex(content, r"\.nightwatch-metrics\s*\{[^}]*grid-template-columns:\s*repeat\(6,minmax\(0,1fr\)\)")
        self.assertRegex(content, r"\.nr-workspace-switcher\s*\{[^}]*grid-template-columns:\s*repeat\(5,minmax\(0,1fr\)\)")
        self.assertRegex(content, r"\.fw-metrics\s*\{[^}]*grid-template-columns:\s*repeat\(6,minmax\(0,1fr\)\)")

    def test_dashboard_javascript_is_a_real_nonempty_asset(self):
        js = ROOT / "dashboard.js"
        self.assertTrue(js.is_file())
        self.assertGreater(js.stat().st_size, 10000)
        content = js.read_text(encoding="utf-8")
        self.assertIn('Device API unavailable. Check server log and /api/devices.</td></tr>', content)
        self.assertIn('colspan="8">Device API unavailable.', content)
        self.assertIn("SECONDARY_REFRESH_INTERVAL_MS=15000", content)
        self.assertIn("refreshAll(true)", (ROOT / "index.html").read_text(encoding="utf-8"))

    def test_html_references_both_external_assets(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        source = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        # A harmless asset-specific cache-busting suffix may follow the app version.
        self.assertIn(
            'href="/assets/networkradar.css?v={APP_VERSION}', html
        )
        self.assertIn(
            'src="/assets/dashboard.js?v={APP_VERSION}" defer', html
        )
        self.assertNotIn("<style", html.lower())
        self.assertNotRegex(html, r"\sstyle=")
        self.assertNotRegex(html, r"""["']/\s+[A-Za-z-]+=""")
        ids = re.findall(r"""\bid=["']([^"']+)["']""", html)
        self.assertEqual(len(ids), len(set(ids)), "Dashboard HTML contains duplicate IDs")
        script_tags = re.findall(r"<script\b[^>]*>", html, flags=re.IGNORECASE)
        self.assertTrue(script_tags)
        self.assertTrue(all(re.search(r"\bsrc=", tag, flags=re.IGNORECASE) for tag in script_tags))
        self.assertNotIn("WEB_PAGE", source)
        self.assertNotIn("DASHBOARD_JS_BUNDLED", source)
        self.assertIn('(ROOT / "index.html").read_text(encoding="utf-8")', source)

    def test_unknown_device_metrics_and_filter_share_one_confidence_threshold(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn("const UNKNOWN_IDENTITY_CONFIDENCE_THRESHOLD=35;", js)
        self.assertEqual(js.count("UNKNOWN_IDENTITY_CONFIDENCE_THRESHOLD"), 3)
        self.assertNotIn("identification_confidence||0)<25", js)

    def test_workspace_groups_include_identity_and_network_intelligence_panels(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        self.assertIn("'identitySubscan'", js)
        self.assertIn("'domainIntelligence'", js)
        self.assertIn("'fullPortIntelligence'", js)

    def test_authorisation_and_agent_management_require_fresh_network_scope(self):
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        auth_start = server.index("def is_authorized():")
        auth_end = server.index("\ndef ", auth_start + 5)
        auth_body = server[auth_start:auth_end]
        self.assertIn("network_context_snapshot(max_age_seconds=120)", auth_body)
        self.assertIn('context.get("_context_fresh")', auth_body)
        self.assertIn("def _agent_ip_in_scope(client_ip, bind_ip=None):", server)
        self.assertIn("_agent_ip_in_scope(self.client_address[0], self.server.server_address[0])", server)
        self.assertIn("SELECT status,capabilities_json,last_ip FROM remote_agents", server)
        phantom_start = server.index("def _phantom_validate_target(")
        phantom_end = server.index("\ndef ", phantom_start + 5)
        self.assertIn("_is_authorized_device_target(str(addr))", server[phantom_start:phantom_end])

    def test_deep_fingerprint_requires_fresh_authorised_subnet_scope(self):
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        start = server.index("def deep_fingerprint(")
        end = server.index("\ndef ", start + 5)
        body = server[start:end]
        self.assertIn('network_context_snapshot(max_age_seconds=120)', body)
        self.assertIn('not context.get("_context_fresh")', body)
        self.assertIn('not context.get("authorized")', body)
        self.assertIn('allowed_network=allowed_network', body)

    def test_identity_probes_require_fresh_authorised_subnet_targets(self):
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn("def _is_authorized_device_target(ip):", server)
        for name in ("reverse_dns", "netbios_name", "tls_certificate_intelligence",
                     "snmpv3_intelligence", "service_banner_intelligence"):
            start = server.index("def " + name + "(")
            end = server.find("\ndef ", start + 5)
            body = server[start:end if end >= 0 else len(server)]
            self.assertIn("_is_authorized_device_target(ip)", body, name)

    def test_active_multicast_scope_uses_an_atomic_authorisation_snapshot(self):
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        start = server.index("def _selected_discovery_scope():")
        end = server.index("def discover_devices(", start)
        scope = server[start:end]
        self.assertIn('if not context.get("_context_fresh") or not context.get("authorized"):', scope)
        self.assertNotIn("if not is_authorized():", scope)

    def test_slow_firewall_refresh_does_not_block_primary_dashboard_poll(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        start = js.index("async function refreshAll(")
        end = js.index("loadHuntTemplates();refreshAll();", start)
        refresh = js[start:end]
        self.assertNotIn('["firewall",', refresh)
        self.assertIn("void loadFirewallSnapshot(forceSecondary);", refresh)
        self.assertIn("firewallRefreshInFlight", js)
        self.assertIn("firewallRefreshQueued", js)

    def test_firewall_poll_uses_cache_and_manual_refresh_forces_collection(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn('force?"/api/firewall?refresh=1":"/api/firewall"', js)
        self.assertIn("void loadFirewallSnapshot(forceSecondary);", js)
        self.assertIn('force_refresh = "refresh=1" in p.query.split("&")', server)

    def test_manual_refresh_is_queued_when_refresh_is_in_flight(self):
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("let forceRefreshQueued=false;", js)
        self.assertIn("if(forceSecondary){forceRefreshQueued=true;", js)
        self.assertIn("if(forceRefreshQueued){", js)
        self.assertIn("void refreshAll(true);", js)
        self.assertIn('onclick="refreshAll(true)"', html)

    def test_dashboard_html_is_a_real_nonempty_asset(self):
        html = ROOT / "index.html"
        self.assertTrue(html.is_file())
        self.assertGreater(html.stat().st_size, 10000)

    def test_dashboard_javascript_static_element_references_exist(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "dashboard.js").read_text(encoding="utf-8")
        html_ids = set(re.findall(r"""\bid=["']([^"']+)["']""", html))
        referenced_ids = set(re.findall(r"""\$\(["']([^"']+)["']\)""", js))
        self.assertFalse(
            referenced_ids - html_ids,
            "Dashboard JavaScript references missing static HTML IDs",
        )

    def test_blank_networkradar_port_environment_uses_default_port(self):
        server = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn('os.environ.get("NETWORKRADAR_PORT", "").strip() or str(WEB_PORT)', server)

    def test_server_has_routes_for_both_assets(self):
        source = (ROOT / "networkradar.py").read_text(encoding="utf-8-sig")
        self.assertIn('p.path == "/assets/networkradar.css"', source)
        self.assertIn('p.path == "/assets/dashboard.js"', source)


if __name__ == "__main__":
    unittest.main()
