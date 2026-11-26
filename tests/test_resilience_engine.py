import unittest

from networkradar_modules.diagnostics.resilience import (
    NetworkResilienceMonitor,
    calculate_health_score,
    classify_state,
    parse_ping_output,
)


class PingParsingTests(unittest.TestCase):
    def test_windows_ping_output(self):
        result = parse_ping_output(
            "Reply from 1.1.1.1: bytes=32 time=183ms TTL=50\n"
            "Reply from 1.1.1.1: bytes=32 time=174ms TTL=50\n"
            "Reply from 1.1.1.1: bytes=32 time=175ms TTL=50",
            3,
        )
        self.assertEqual(result["received"], 3)
        self.assertEqual(result["packet_loss_percent"], 0.0)
        self.assertEqual(result["avg_rtt_ms"], 177.3)

    def test_partial_packet_loss(self):
        result = parse_ping_output(
            "64 bytes from 1.1.1.1: icmp_seq=2 ttl=50 time=174 ms\n"
            "64 bytes from 1.1.1.1: icmp_seq=5 ttl=50 time=181 ms",
            3,
        )
        self.assertEqual(result["received"], 2)
        self.assertEqual(result["packet_loss_percent"], 33.3)

    def test_no_replies_means_full_loss(self):
        result = parse_ping_output("Request timed out.", 3)
        self.assertEqual(result["received"], 0)
        self.assertEqual(result["packet_loss_percent"], 100.0)


class ClassificationTests(unittest.TestCase):
    def test_online_even_when_gateway_icmp_is_filtered(self):
        state = classify_state(
            {"received": 0},
            {"packet_loss_percent": 100, "avg_rtt_ms": None},
            {"reachable": True},
            {"resolved": True},
        )
        self.assertEqual(state, "ONLINE")

    def test_filtered_icmp_does_not_degrade_when_tcp_and_dns_work(self):
        state = classify_state(
            {"received": 0},
            {"packet_loss_percent": 100, "avg_rtt_ms": None},
            {"reachable": True},
            {"resolved": True},
        )
        self.assertEqual(state, "ONLINE")
        score = calculate_health_score({
            "status": state, "packet_loss_percent": 100,
            "internet_icmp_status": "NO_RESPONSE",
            "internet_tcp_reachable": True, "avg_latency_ms": None,
            "dns_resolution_ms": 5,
        })
        self.assertEqual(score, 100)

    def test_high_packet_loss_is_degraded(self):
        state = classify_state(
            {"received": 3},
            {"packet_loss_percent": 35, "avg_rtt_ms": 180},
            {"reachable": True},
            {"resolved": True},
        )
        self.assertEqual(state, "DEGRADED")

    def test_gateway_up_but_internet_down(self):
        state = classify_state(
            {"received": 3},
            {"packet_loss_percent": 100, "avg_rtt_ms": None},
            {"reachable": False},
            {"resolved": False},
        )
        self.assertEqual(state, "INTERNET_DOWN")

    def test_no_gateway_or_internet(self):
        state = classify_state(
            {"received": 0},
            {"packet_loss_percent": 100, "avg_rtt_ms": None},
            {"reachable": False},
            {"resolved": False},
        )
        self.assertEqual(state, "OFFLINE")

    def test_score_is_bounded(self):
        self.assertGreaterEqual(calculate_health_score({"status": "OFFLINE"}), 0)
        self.assertLessEqual(calculate_health_score({"status": "ONLINE"}), 100)


class MonitorTests(unittest.TestCase):
    def test_sample_and_recovery_event(self):
        events = []
        samples = []
        def fake_icmp(host):
            state = "ONLINE"
            return {
                "status": "RESPONDING" if state == "ONLINE" else "NO_RESPONSE",
                "sent": 3, "received": 3 if state == "ONLINE" else 0,
                "packet_loss_percent": 0.0 if state == "ONLINE" else 100.0,
                "avg_rtt_ms": 10.0 if state == "ONLINE" else None,
                "min_rtt_ms": 10.0 if state == "ONLINE" else None,
                "max_rtt_ms": 10.0 if state == "ONLINE" else None,
            }

        def fake_tcp(host, port):
            return {"reachable": True, "latency_ms": 10.0}

        def fake_dns(host):
            return {"resolved": True, "latency_ms": 5.0}

        monitor = NetworkResilienceMonitor(
            context_provider=lambda: {
                "gateway": "192.0.2.1", "network": "test", "interface": "test0"
            },
            sample_callback=samples.append,
            event_callback=events.append,
            icmp_probe=fake_icmp,
            tcp_probe=fake_tcp,
            dns_probe=fake_dns,
        )
        first = monitor.sample_once()
        self.assertEqual(first["status"], "ONLINE")
        self.assertEqual(len(samples), 1)
        monitor.stop()

    def test_transition_event_is_created_for_recovery(self):
        event = NetworkResilienceMonitor._transition_event(
            "OFFLINE", {"status": "ONLINE", "health_score": 98, "timestamp": "now"}
        )
        self.assertEqual(event["event_type"], "NETWORK_RECOVERED")


if __name__ == "__main__":
    unittest.main()
