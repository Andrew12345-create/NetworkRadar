import unittest
import urllib.error
import urllib.request

from networkradar_modules.discovery.probes import (
    _SameHostRedirectHandler,
    is_same_private_http_host,
    netbios_name,
)


class SsdpLocationValidationTests(unittest.TestCase):
    def test_accepts_only_same_private_http_literal_address(self):
        self.assertTrue(is_same_private_http_host(
            "192.168.1.10", "http://192.168.1.10:8080/device.xml"
        ))

    def test_rejects_other_host_public_address_and_https(self):
        self.assertFalse(is_same_private_http_host(
            "192.168.1.10", "http://192.168.1.11/device.xml"
        ))
        self.assertFalse(is_same_private_http_host(
            "192.168.1.10", "http://example.com/device.xml"
        ))
        self.assertFalse(is_same_private_http_host(
            "192.168.1.10", "https://192.168.1.10/device.xml"
        ))

    def test_rejects_malformed_urls(self):
        self.assertFalse(is_same_private_http_host("not-an-ip", "http:///x"))
        self.assertFalse(is_same_private_http_host("192.168.1.10", ""))

    def test_redirect_to_same_private_host_is_allowed(self):
        handler = _SameHostRedirectHandler("192.168.1.10")
        request = urllib.request.Request("http://192.168.1.10/device.xml")
        redirected = handler.redirect_request(
            request, None, 302, "Found", {}, "/description.xml"
        )
        self.assertEqual(
            redirected.full_url,
            "http://192.168.1.10/description.xml",
        )

    def test_redirect_to_another_host_is_rejected(self):
        handler = _SameHostRedirectHandler("192.168.1.10")
        request = urllib.request.Request("http://192.168.1.10/device.xml")
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(
                request, None, 302, "Found", {},
                "http://169.254.169.254/latest/meta-data/",
            )


class NetbiosProbeTests(unittest.TestCase):
    def test_extracts_unique_workstation_name(self):
        output = (
            "       OFFICE-PC     <00>  UNIQUE      Registered\n"
            "       OFFICE-PC     <20>  UNIQUE      Registered\n"
        )

        class Result:
            stdout = output

        name = netbios_name(
            "192.168.1.20",
            runner=lambda *args, **kwargs: Result(),
        )
        self.assertEqual(name, "OFFICE-PC")

    def test_ignores_workgroup_name(self):
        class Result:
            stdout = "       WORKGROUP     <00>  UNIQUE      Registered\n"

        self.assertEqual(
            netbios_name("192.168.1.20",
                         runner=lambda *args, **kwargs: Result()),
            "",
        )

    def test_probe_failure_is_nonfatal(self):
        def fail(*args, **kwargs):
            raise OSError("not installed")

        self.assertEqual(netbios_name("192.168.1.20", runner=fail), "")


if __name__ == "__main__":
    unittest.main()
