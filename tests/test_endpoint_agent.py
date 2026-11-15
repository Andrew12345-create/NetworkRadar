"""Tests for the opt-in, inventory-only NetworkRadar endpoint agent."""
import hashlib
import os
import tempfile
import hmac
import unittest
import unittest.mock

from agent import networkradar_agent as agent


class CertificatePinTests(unittest.TestCase):
    def test_normalises_colon_delimited_sha256_pin(self):
        pin = "AA:BB:" + ":".join(["CC"] * 29) + ":DD"
        self.assertEqual(agent.normalise_certificate_pin(pin), "aabb" + "cc" * 29 + "dd")

    def test_rejects_short_or_non_hex_pin(self):
        for value in ("abcd", "z" * 64, "", "00" * 31, "ab" * 32 + "zz"):
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
        canonical = bytes([10]).join([b"POST", b"/agent/v1/report", b"1790000000", b"A" * 24, hashlib.sha256(body).hexdigest().encode()])
        expected = hmac.new(bytes.fromhex(key), canonical, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-NR-Signature"], expected)
        self.assertEqual(headers["X-NR-Agent"], "nr-" + "1" * 20)

    def test_rejects_invalid_agent_id_and_key(self):
        with self.assertRaises(ValueError):
            agent.make_auth_headers("bad-id", "ab" * 32, "POST", "/x", b"")
        with self.assertRaises(ValueError):
            agent.make_auth_headers("nr-" + "a" * 20, "bad", "POST", "/x", b"")


class PinnedTransportTests(unittest.TestCase):
    class FakeResponse:
        status = 200

        def read(self, size=-1):
            return b'{"ok":true}'

    class FakeConnection:
        def __init__(self, certificate):
            self.sock = type("FakeSocket", (), {
                "getpeercert": lambda _self, binary_form=False: certificate
            })()
            self.request_called = False
            self.closed = False

        def connect(self):
            return None

        def request(self, *args, **kwargs):
            self.request_called = True

        def getresponse(self):
            return PinnedTransportTests.FakeResponse()

        def close(self):
            self.closed = True

    def test_certificate_mismatch_fails_before_http_request(self):
        certificate = b"presented-leaf-certificate"
        connection = self.FakeConnection(certificate)
        wrong_pin = hashlib.sha256(b"different-certificate").hexdigest()
        with unittest.mock.patch.object(
            agent.http.client, "HTTPSConnection", return_value=connection
        ), unittest.mock.patch.object(agent.ssl, "SSLContext"):
            client = agent.PinnedHTTPSClient(
                "https://radar.local:8767", wrong_pin
            )
            with self.assertRaises(agent.ssl.SSLError):
                client.request("POST", "/agent/v1/report", b"{}")
        self.assertFalse(connection.request_called)
        self.assertTrue(connection.closed)

    def test_matching_certificate_pin_allows_signed_transport(self):
        certificate = b"presented-leaf-certificate"
        connection = self.FakeConnection(certificate)
        pin = hashlib.sha256(certificate).hexdigest()
        with unittest.mock.patch.object(
            agent.http.client, "HTTPSConnection", return_value=connection
        ), unittest.mock.patch.object(agent.ssl, "SSLContext"):
            client = agent.PinnedHTTPSClient(
                "https://radar.local:8767", pin
            )
            status, payload = client.request("POST", "/agent/v1/report", b"{}")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(connection.request_called)
        self.assertTrue(connection.closed)

    def test_oversized_body_is_rejected_before_connection(self):
        client = agent.PinnedHTTPSClient(
            "https://radar.local:8767", "ab" * 32
        )
        with unittest.mock.patch.object(agent.http.client, "HTTPSConnection") as connection:
            with self.assertRaisesRegex(ValueError, "64 KiB"):
                client.request("POST", "/agent/v1/report", b"x" * 65537)
            connection.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Windows DPAPI is available only on Windows.")
class DPAPIConfigTests(unittest.TestCase):
    def test_agent_configuration_round_trips_encrypted_for_current_user(self):
        config = {
            "server_url": "https://127.0.0.1:8767",
            "certificate_pin": "ab" * 32,
            "agent_id": "nr-" + "a" * 20,
            "auth_key": "cd" * 32,
            "interval_seconds": 300,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "agent.dat")
            agent.save_config(config, path)
            encrypted = open(path, "rb").read()
            self.assertTrue(encrypted.startswith(agent._CONFIG_MAGIC))
            self.assertNotIn(b"auth_key", encrypted)
            self.assertNotIn(config["auth_key"].encode("ascii"), encrypted)
            self.assertEqual(agent.load_config(path), config)


class CapabilityBoundaryTests(unittest.TestCase):
    def test_agent_is_inventory_only(self):
        self.assertEqual(agent.CAPABILITIES, ["inventory-report"])


if __name__ == "__main__":
    unittest.main()
