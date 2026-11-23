import socket
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from networkradar_modules.discovery import probes
from networkradar_modules.discovery.probes import (
    ssdp_scan,
    _SameHostRedirectHandler,
    is_same_private_http_host,
    netbios_name,
    parse_upnp_description,
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


class SsdpNetworkScopeTests(unittest.TestCase):
    def test_fails_closed_without_selected_interface_and_network(self):
        with patch.object(probes.socket, "socket") as socket_factory:
            self.assertEqual(ssdp_scan(), {})
            socket_factory.assert_not_called()

    def test_binds_multicast_to_selected_adapter_and_accepts_only_in_subnet(self):
        packet = (
            b"HTTP/1.1 200 OK\\r\\n"
            b"LOCATION: http://192.168.1.20:8000/device.xml\\r\\n"
            b"SERVER: Example/1.0 UPnP/1.0\\r\\n"
            b"\\r\\n"
        )
        xml = b"<root><device><friendlyName>Office Router</friendlyName></device></root>"

        class FakeSocket:
            def __init__(self):
                self.options = []
                self.bound = None
                self.sent = []
                self.responses = [(packet, ("192.168.1.20", 1900))]

            def setsockopt(self, *args):
                self.options.append(args)

            def bind(self, address):
                self.bound = address

            def settimeout(self, value):
                self.timeout = value

            def sendto(self, data, address):
                self.sent.append((data, address))

            def recvfrom(self, _limit):
                if self.responses:
                    return self.responses.pop(0)
                raise socket.timeout()

            def close(self):
                self.closed = True

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return xml

        class FakeOpener:
            def open(self, _request, timeout):
                self.timeout = timeout
                return FakeResponse()

        fake_socket = FakeSocket()
        fake_opener = FakeOpener()
        with (
            patch.object(probes.socket, "socket", return_value=fake_socket),
            patch.object(probes.urllib.request, "build_opener", return_value=fake_opener),
            patch.object(probes.time, "monotonic", side_effect=[0.0, 0.1, 3.0]),
        ):
            result = ssdp_scan(
                timeout=1,
                interface_ip="192.168.1.10",
                allowed_network="192.168.1.0/24",
            )

        self.assertEqual(result["192.168.1.20"]["friendlyname"], "Office Router")
        self.assertEqual(fake_socket.bound, ("192.168.1.10", 0))
        self.assertTrue(any(
            option[1] == probes.socket.IP_MULTICAST_IF
            and option[2] == probes.socket.inet_aton("192.168.1.10")
            for option in fake_socket.options
        ))
        self.assertTrue(fake_socket.closed)

    def test_discards_responder_outside_approved_subnet_before_fetch(self):
        packet = (
            b"HTTP/1.1 200 OK\\r\\n"
            b"LOCATION: http://10.0.0.20/device.xml\\r\\n"
            b"\\r\\n"
        )

        class FakeSocket:
            def __init__(self):
                self.responses = [(packet, ("10.0.0.20", 1900))]

            def setsockopt(self, *_args):
                pass

            def bind(self, _address):
                pass

            def settimeout(self, _value):
                pass

            def sendto(self, *_args):
                pass

            def recvfrom(self, _limit):
                if self.responses:
                    return self.responses.pop(0)
                raise socket.timeout()

            def close(self):
                pass

        with (
            patch.object(probes.socket, "socket", return_value=FakeSocket()),
            patch.object(probes.urllib.request, "build_opener") as opener_factory,
            patch.object(probes.time, "monotonic", side_effect=[0.0, 0.1, 3.0]),
        ):
            result = ssdp_scan(
                timeout=1,
                interface_ip="192.168.1.10",
                allowed_network="192.168.1.0/24",
            )
        self.assertEqual(result, {})
        opener_factory.assert_not_called()


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


class UpnpDescriptionTests(unittest.TestCase):
    def test_extracts_root_model_and_embedded_device_fields(self):
        xml = b'''<?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <friendlyName>Office Router</friendlyName>
            <manufacturer>Example Networks</manufacturer>
            <modelName>XR-500</modelName>
            <modelNumber>500</modelNumber>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <UDN>uuid:root-123</UDN>
            <deviceList><device><friendlyName>Wi-Fi Radio</friendlyName>
              <manufacturer>Example Networks</manufacturer>
              <modelName>Radio-X</modelName><UDN>uuid:radio-456</UDN>
            </device></deviceList>
          </device>
        </root>'''
        result = parse_upnp_description(xml)
        self.assertEqual(result["friendlyname"], "Office Router")
        self.assertEqual(result["manufacturer"], "Example Networks")
        self.assertEqual(result["modelname"], "XR-500")
        self.assertEqual(result["modelnumber"], "500")
        self.assertEqual(result["udn"], "uuid:root-123")
        self.assertEqual(result["embedded_devices"][0]["modelname"], "Radio-X")

    def test_rejects_dtd_and_entity_declarations(self):
        xml = b'''<!DOCTYPE root [<!ENTITY x "expanded">]>
        <root><device><friendlyName>&x;</friendlyName></device></root>'''
        with self.assertRaises(ValueError):
            parse_upnp_description(xml)

    def test_rejects_oversized_description(self):
        with self.assertRaises(ValueError):
            parse_upnp_description(b"x" * (256 * 1024 + 1))


    def test_child_model_is_not_attributed_to_parent(self):
        xml = b'''<root><device><friendlyName>Gateway</friendlyName>
        <deviceList><device><modelName>Child Radio</modelName></device></deviceList>
        </device></root>'''
        result = parse_upnp_description(xml)
        self.assertEqual(result["modelname"], "")
        self.assertEqual(result["embedded_devices"][0]["modelname"], "Child Radio")

    def test_returns_empty_when_device_element_is_missing(self):
        self.assertEqual(parse_upnp_description(b"<root><other/></root>"), {})


if __name__ == "__main__":
    unittest.main()
