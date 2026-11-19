import ipaddress
import unittest

from networkradar_modules.control.routeros import (
    RouterOSAdapter, format_routeros_rate, validate_duration,
    validate_router_host, validate_target_ip,
)
from networkradar_modules.control.service import NetworkControlManager


class FakeRouterOSClient:
    def __init__(self, ipv6=True):
        self.ipv6 = ipv6
        self.puts = []
        self.patches = []
        self.deletes = []
        self.rules = []
        self.v6_rules = []
        self.v4_entries = []
        self.v6_entries = []
        self.queues = []
        self.ipv6_addresses = (
            [{"interface": "br-lan", "address": "2606:4700:4700::1/64"}, {"interface": "br-guest", "address": "2606:4700:4701::1/64"}]
            if ipv6 else []
        )

    def get(self, path, params=None):
        if path == "/system/resource":
            return {"platform": "MikroTik", "version": "7.16.2", "board-name": "hAP test", "uptime": "1d"}
        if path == "/system/identity":
            return {"name": "test-router"}
        if path == "/interface/list":
            return [{"name": "LAN"}, {"name": "WAN"}]
        if path == "/interface/list/member":
            return [{"list": "LAN", "interface": "br-lan"}, {"list": "LAN", "interface": "br-guest"}, {"list": "WAN", "interface": "ether1"}]
        if path == "/ip/address":
            return [{"interface": "br-lan", "address": "192.168.1.1/24"}, {"interface": "br-guest", "address": "192.168.50.1/24"}]
        if path == "/ip/firewall/filter":
            return list(self.rules)
        if path == "/ipv6/firewall/filter":
            if not self.ipv6:
                raise RuntimeError("IPv6 unavailable")
            return list(self.v6_rules)
        if path == "/ipv6/address":
            if not self.ipv6:
                raise RuntimeError("IPv6 unavailable")
            return list(self.ipv6_addresses)
        if path == "/ip/firewall/address-list":
            return list(self.v4_entries)
        if path == "/ipv6/firewall/address-list":
            if not self.ipv6:
                raise RuntimeError("IPv6 unavailable")
            return list(self.v6_entries)
        if path == "/queue/simple":
            return list(self.queues)
        raise AssertionError("Unexpected GET " + path)

    def put(self, path, payload):
        self.puts.append((path, dict(payload)))
        row = dict(payload)
        row[".id"] = f"*{len(self.puts)}"
        if path == "/ip/firewall/filter":
            self.rules.insert(0, row)
        elif path == "/ipv6/firewall/filter":
            self.v6_rules.insert(0, row)
        elif path == "/ip/firewall/address-list":
            self.v4_entries.append(row)
        elif path == "/ipv6/firewall/address-list":
            self.v6_entries.append(row)
        elif path == "/queue/simple":
            self.queues.insert(0, row)
        return row

    def patch(self, path, item_id, payload):
        self.patches.append((path, item_id, dict(payload)))
        collection = self.queues if path == "/queue/simple" else []
        for row in collection:
            if row.get(".id") == item_id:
                row.update(payload)
                return row
        return {}

    def delete(self, path, item_id):
        self.deletes.append((path, item_id))
        collection = {
            "/ip/firewall/filter": self.rules,
            "/ipv6/firewall/filter": self.v6_rules,
            "/ip/firewall/address-list": self.v4_entries,
            "/ipv6/firewall/address-list": self.v6_entries,
            "/queue/simple": self.queues,
        }.get(path, [])
        collection[:] = [row for row in collection if row.get(".id") != item_id]


def make_adapter(ipv6=True):
    fake = FakeRouterOSClient(ipv6=ipv6)
    adapter = RouterOSAdapter("192.168.1.1", "nr-control", "not-a-real-secret", client=fake)
    adapter.connect()
    return adapter, fake


class NetworkControlValidationTests(unittest.TestCase):
    def test_router_must_be_private_and_inside_authorised_subnet(self):
        self.assertEqual(validate_router_host("192.168.1.1", "192.168.1.0/24"), "192.168.1.1")
        for host, network in [
            ("8.8.8.8", "192.168.1.0/24"),
            ("192.168.2.1", "192.168.1.0/24"),
            ("127.0.0.1", "127.0.0.0/8"),
        ]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_router_host(host, network)

    def test_target_must_be_inside_scope_and_not_gateway(self):
        self.assertEqual(validate_target_ip("192.168.1.20", "192.168.1.0/24", "192.168.1.1"), "192.168.1.20")
        with self.assertRaises(ValueError):
            validate_target_ip("192.168.1.1", "192.168.1.0/24", "192.168.1.1")
        with self.assertRaises(ValueError):
            validate_target_ip("192.168.2.20", "192.168.1.0/24")

    def test_pause_duration_accepts_any_whole_minute_from_one_to_24_hours(self):
        for value in (1, 2, 7, 15, 47, 90, 361, 720, 1439, 1440, "37"):
            with self.subTest(value=value):
                self.assertEqual(validate_duration(value), int(value))

    def test_pause_duration_rejects_invalid_or_out_of_range_values(self):
        for value in (0, -1, 1441, "later", "1.5", 1.5, True, None, ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_duration(value)

    def test_bandwidth_values_are_normalised_to_routeros_units(self):
        self.assertEqual(format_routeros_rate(10), "10M")
        self.assertEqual(format_routeros_rate(1.5), "1500k")
        self.assertEqual(format_routeros_rate(0.128), "128k")
        with self.assertRaises(ValueError):
            format_routeros_rate(0)


class RouterOSAdapterTests(unittest.TestCase):
    def test_connect_is_read_only_and_detects_router_capabilities(self):
        adapter, fake = make_adapter()
        info = adapter.info
        self.assertEqual(info["model"], "hAP test")
        self.assertTrue(info["ipv6_supported"])
        self.assertTrue(info["lan_wan_ready"])
        self.assertEqual(fake.puts, [])

    def test_device_pause_creates_router_expiring_dual_stack_entries(self):
        adapter, fake = make_adapter()
        result = adapter.pause_device("192.168.1.20", ["2606:4700:4700::1234"], 15)
        self.assertTrue(result["ipv4_blocked"])
        self.assertTrue(result["ipv6_complete"])
        self.assertEqual(fake.v4_entries[0]["timeout"], "15m")
        self.assertEqual(fake.v6_entries[0]["timeout"], "15m")
        self.assertEqual(fake.rules[0]["action"], "drop")
        self.assertEqual(fake.v6_rules[0]["action"], "drop")
        self.assertEqual(fake.rules[0]["in-interface-list"], "LAN")
        self.assertEqual(fake.rules[0]["out-interface-list"], "WAN")

    def test_ipv4_only_pause_requires_explicit_acknowledgement(self):
        adapter, fake = make_adapter()
        with self.assertRaisesRegex(ValueError, "IPv4-only"):
            adapter.pause_device("192.168.1.20", [], 15)
        result = adapter.pause_device("192.168.1.20", [], 15, allow_ipv4_only=True)
        self.assertTrue(result["ipv4_blocked"])
        self.assertFalse(result["ipv6_complete"])

    def test_network_pause_uses_lan_ipv6_prefix_and_router_side_expiry(self):
        adapter, fake = make_adapter()
        result = adapter.pause_network("192.168.1.0/24", 30)
        self.assertEqual(fake.v4_entries[0]["address"], "192.168.1.0/24")
        self.assertEqual(fake.v6_entries[0]["address"], "2606:4700:4700::/64")
        self.assertEqual(len(fake.v6_entries), 1, "Only the IPv6 prefix on the authorised IPv4 LAN should be paused.")
        self.assertEqual(result["duration_minutes"], 30)

    def test_bandwidth_queue_uses_upload_download_order_and_is_idempotent(self):
        adapter, fake = make_adapter()
        first = adapter.set_bandwidth_limit("192.168.1.20", 10, 2)
        self.assertEqual(first["max_limit"], "2M/10M")
        self.assertEqual(fake.queues[0]["target"], "192.168.1.20/32")
        second = adapter.set_bandwidth_limit("192.168.1.20", 5, 1)
        self.assertEqual(second["action"], "updated")
        self.assertEqual(len(fake.queues), 1)
        self.assertEqual(fake.queues[0]["max-limit"], "1M/5M")

    def test_resume_and_restore_touch_only_networkradar_owned_entries(self):
        adapter, fake = make_adapter()
        adapter.pause_device("192.168.1.20", ["2606:4700:4700::1234"], 15)
        fake.v4_entries.append({".id": "*user", "address": "192.168.1.30/32", "comment": "manual rule"})
        fake.queues.append({".id": "*other", "comment": "administrator queue"})
        result = adapter.resume_device("192.168.1.20")
        self.assertEqual(result["removed_ipv4_entries"], 1)
        self.assertEqual(result["removed_ipv6_entries"], 1)
        self.assertEqual(len(fake.v4_entries), 1)
        adapter.set_bandwidth_limit("192.168.1.20", 5, 1)
        restored = adapter.restore_all()
        self.assertEqual(restored["removed_bandwidth_queues"], 1)
        self.assertEqual(restored["removed_managed_firewall_rules"], 2)
        self.assertEqual(fake.queues[0]["comment"], "administrator queue")
        self.assertEqual(fake.v4_entries[0]["comment"], "manual rule")

    def test_ipv6_unavailable_requires_explicit_ipv4_only_ack(self):
        adapter, fake = make_adapter(ipv6=False)
        with self.assertRaisesRegex(ValueError, "IPv4-only"):
            adapter.pause_network("192.168.1.0/24", 15)
        result = adapter.pause_network("192.168.1.0/24", 15, allow_ipv4_only=True)
        self.assertFalse(result["ipv6_complete"])


class NetworkControlManagerTests(unittest.TestCase):
    def test_manager_refuses_control_from_a_different_network(self):
        class FakeAdapter:
            def __init__(self, *args, **kwargs):
                self.host = args[0]
                self.info = {}
            def connect(self):
                return {"identity": "test"}
            def status(self):
                return {"connected": True}
        manager = NetworkControlManager(adapter_factory=FakeAdapter)
        manager.connect_routeros("192.168.1.1", "user", "secret", 443, "", "192.168.1.0/24")
        self.assertTrue(manager.status("192.168.1.0/24")["connected"])
        self.assertFalse(manager.status("192.168.2.0/24")["connected"])
        with self.assertRaises(PermissionError):
            manager.remove_bandwidth("192.168.2.0/24", "192.168.1.20")


if __name__ == "__main__":
    unittest.main()
