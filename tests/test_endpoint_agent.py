"""Tests for the opt-in, inventory-only NetworkRadar endpoint agent."""
import hashlib
import hmac
import unittest

from agent import networkradar_agent as agent


class CertificatePinTests(unittest.TestCase):
    def test_normalises_colon_delimited_sha256_pin(self):
        pin = "AA:BB:" + ":".join(["CC"] * 30) + ":DD"
        self.assertEqual(agent.normalise_certificate_pin(pin), "aabb" + "cc" * 30 + "dd")

    def test_rejects_short_or_non_hex_pin(self):
        for value in ("abcd", "z" * 64, "", "00" * 31):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    agent.normalise_certificate_pin(value)


class ServerUrlTests(unittest.TestCase):
    def test_accepts_https_origin_and_default_port(self):
        self.assertEqual(agent.validate_server_url("https://192.168.1.10"),
                         ("192.168.1.10", 443))
        self.assertEqual(agent.validate_server_url("https://radar.local:8767/"),
                         ("radar.local", 8767))

    def test_rejects_http_credentials_paths_and_query(self):
        invalid = (
            "http://192.168.1.10:8767",
            "https://user:pass@radar.local:8767",
            "https://radar.local:8767/api",
            "https://radar.local:8767?token=x",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    agent.validate_server_url(value)


class AgentSignatureTests(unittest.TestCase):
    def test_signature_matches_server_canonical_payload(self):
        key = "ab" * 32
        body = b'{"inventory":{"model":"Test"}}'
        headers = agent.make_auth_headers(
            "nr-" + "1" * 20, key, "POST", "/agent/v1/report", body,
            timestamp="1790000000", nonce="A" * 24,
        )
        canonical = b"POST\\n/agent/v1/report\\n1790000000\\n" + b"A" * 24 + b"\\n" + hashlib.sha256(body).hexdigest().encode()
        expected = hmac.new(bytes.fromhex(key), canonical, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-NR-Signature"], expected)
        self.assertEqual(headers["X-NR-Agent"], "nr-" + "1" * 20)

    def test_rejects_invalid_agent_id_and_key(self):
        with self.assertRaises(ValueError):
            agent.make_auth_headers("bad-id", "ab" * 32, "POST", "/x", b"")
        with self.assertRaises(ValueError):
            agent.make_auth_headers("nr-" + "a" * 20, "bad", "POST", "/x", b"")


class CapabilityBoundaryTests(unittest.TestCase):
    def test_agent_is_inventory_only(self):
        self.assertEqual(agent.CAPABILITIES, ["inventory"])


if __name__ == "__main__":
    unittest.main()
