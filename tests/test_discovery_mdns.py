import struct
import unittest

from networkradar_modules.discovery.mdns import (
    build_ptr_query, parse_mdns_packet, discover_mdns,
)


def dns_name(name):
    out = bytearray()
    for label in name.split("."):
        raw = label.encode()
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def response_record(name, rtype, value):
    owner = dns_name(name)
    if rtype == 12:
        data = dns_name(value)
    elif rtype == 33:
        data = struct.pack("!HHH", 0, 0, value[1]) + dns_name(value[0])
    elif rtype == 16:
        raw = value.encode()
        data = bytes([len(raw)]) + raw
    elif rtype == 1:
        data = bytes([192, 168, 1, 20])
    else:
        raise ValueError(rtype)
    return owner + struct.pack("!HHIH", rtype, 1, 120, len(data)) + data


class MdnsPacketTests(unittest.TestCase):
    def test_query_is_ptr_question_with_qu_unicast_bit(self):
        packet = build_ptr_query("_ipp._tcp.local")
        self.assertEqual(struct.unpack_from("!HHHHHH", packet), (0, 0, 1, 0, 0, 0))
        self.assertTrue(packet.endswith(struct.pack("!HH", 12, 0x8001)))

    def test_parses_ptr_srv_txt_and_a_records(self):
        records = [
            response_record("_ipp._tcp.local", 12, "Office Printer._ipp._tcp.local"),
            response_record("Office Printer._ipp._tcp.local", 33,
                            ("printer.local", 631)),
            response_record("Office Printer._ipp._tcp.local", 16, "rp=print"),
            response_record("printer.local", 1, ""),
        ]
        packet = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)
        parsed = parse_mdns_packet(packet)
        self.assertEqual([r["type"] for r in parsed], ["PTR", "SRV", "TXT", "A"])
        self.assertEqual(parsed[1]["value"]["port"], 631)
        self.assertEqual(parsed[1]["value"]["target"], "printer.local")
        self.assertEqual(parsed[2]["value"], ["rp=print"])
        self.assertEqual(parsed[3]["value"], "192.168.1.20")

    def test_parses_compressed_owner_name(self):
        question = dns_name("_ipp._tcp.local") + struct.pack("!HH", 12, 1)
        target = dns_name("Office Printer._ipp._tcp.local")
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
        packet = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + answer
        parsed = parse_mdns_packet(packet)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["name"], "_ipp._tcp.local")
        self.assertEqual(parsed[0]["value"], "Office Printer._ipp._tcp.local")

    def test_rejects_query_and_malformed_packets(self):
        self.assertEqual(parse_mdns_packet(build_ptr_query("_ipp._tcp.local")), [])
        self.assertEqual(parse_mdns_packet(b"short"), [])
        self.assertEqual(parse_mdns_packet(b"\x00" * 12), [])

    def test_discovery_requires_explicit_interface_and_approved_subnet(self):
        from unittest.mock import patch
        with patch("networkradar_modules.discovery.mdns.socket.socket") as socket_factory:
            self.assertEqual(discover_mdns(), [])
            self.assertEqual(discover_mdns(interface_ip="192.168.1.10"), [])
            self.assertEqual(discover_mdns(allowed_network="192.168.1.0/24"), [])
            socket_factory.assert_not_called()

    def test_discovery_rejects_non_private_interface(self):
        self.assertEqual(
            discover_mdns(interface_ip="8.8.8.8", allowed_network="192.168.1.0/24"), []
        )
        self.assertEqual(
            discover_mdns(interface_ip="not-an-ip", allowed_network="192.168.1.0/24"), []
        )

    def test_discovery_discards_responder_outside_approved_subnet(self):
        from unittest.mock import patch

        question_name = "_ipp._tcp.local"
        question = dns_name(question_name) + struct.pack("!HH", 12, 1)
        answer = response_record(
            question_name, 12, "Office Printer._ipp._tcp.local"
        )
        packet = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + answer

        class FakeSocket:
            def __init__(self):
                self.responses = [(packet, ("10.0.0.20", 5353))]

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
                raise __import__("socket").timeout()

            def close(self):
                pass

        with (
            patch("networkradar_modules.discovery.mdns.socket.socket",
                  return_value=FakeSocket()),
            patch("networkradar_modules.discovery.mdns.time.monotonic",
                  side_effect=[0.0, 0.1, 1.0]),
        ):
            result = discover_mdns(
                duration=0.25,
                interface_ip="192.168.1.10",
                allowed_network="192.168.1.0/24",
            )
        self.assertEqual(result, [])

    def test_discovery_rejects_interface_outside_approved_subnet(self):
        from unittest.mock import patch
        with patch("networkradar_modules.discovery.mdns.socket.socket") as socket_factory:
            self.assertEqual(
                discover_mdns(
                    interface_ip="192.168.2.10",
                    allowed_network="192.168.1.0/24",
                ),
                [],
            )
            socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
