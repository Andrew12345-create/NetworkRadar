"""Local network resilience monitoring.

This module measures the NetworkRadar host's own path to its current gateway
and the internet. It does not scan LAN devices, change router settings, or
generate sustained traffic. A bounded ICMP sample, one TCP connect check and
one DNS lookup are performed on a configurable interval.
"""
from __future__ import annotations

import math
import os
import re
import socket
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Optional


_RTT_RE = re.compile(r"time\s*([=<])\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_REPLY_RE = re.compile(r"(?:reply\s+from|bytes\s+from)", re.IGNORECASE)


def parse_ping_output(output: str, sent: int = 3) -> dict:
    """Parse common Windows and iputils ping output without assuming locale."""
    text = str(output or "")
    rtts = []
    for match in _RTT_RE.finditer(text):
        comparator, raw_value = match.groups()
        value = float(raw_value)
        rtts.append(value / 2.0 if comparator == "<" else value)
    reply_lines = len(_REPLY_RE.findall(text))
    received = min(max(0, int(sent)), max(reply_lines, len(rtts)))
    sent = max(0, int(sent))
    loss = round(((sent - received) / sent) * 100.0, 1) if sent else 0.0
    return {
        "sent": sent,
        "received": received,
        "packet_loss_percent": loss,
        "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else None,
        "min_rtt_ms": round(min(rtts), 1) if rtts else None,
        "max_rtt_ms": round(max(rtts), 1) if rtts else None,
        "status": "RESPONDING" if received else "NO_RESPONSE",
    }


def probe_icmp(host: str, count: int = 3, timeout_ms: int = 1200) -> dict:
    """Run a small, bounded ping sample against one known endpoint."""
    if not host:
        return {**parse_ping_output("", count), "status": "NOT_CONFIGURED"}
    if int(count) < 1 or int(count) > 5:
        raise ValueError("ICMP sample count must be between 1 and 5.")
    if int(timeout_ms) < 250 or int(timeout_ms) > 3000:
        raise ValueError("ICMP timeout must be between 250 and 3000 ms.")
    if os.name == "nt":
        command = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
        process_timeout = (count * timeout_ms / 1000.0) + 3.0
    else:
        command = ["ping", "-c", str(count), "-W",
                   str(max(1, math.ceil(timeout_ms / 1000.0))), host]
        process_timeout = (count * timeout_ms / 1000.0) + 3.0
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=process_timeout, check=False,
        )
        parsed = parse_ping_output(
            (result.stdout or "") + "\n" + (result.stderr or ""), count
        )
        parsed["return_code"] = int(result.returncode)
        if result.returncode != 0 and parsed["received"] == 0:
            parsed["status"] = "NO_RESPONSE"
        return parsed
    except FileNotFoundError:
        return {**parse_ping_output("", count), "status": "UNAVAILABLE",
                "error": "ping executable was not found."}
    except subprocess.TimeoutExpired:
        return {**parse_ping_output("", count), "status": "TIMEOUT"}
    except Exception as exc:
        return {**parse_ping_output("", count), "status": "ERROR",
                "error": type(exc).__name__}


def probe_tcp(host: str = "1.1.1.1", port: int = 443,
              timeout_seconds: float = 2.5) -> dict:
    """Verify outbound TCP reachability without sending application data."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_seconds):
            elapsed = (time.perf_counter() - started) * 1000.0
        return {"reachable": True, "latency_ms": round(elapsed, 1),
                "host": host, "port": int(port)}
    except OSError as exc:
        return {"reachable": False, "latency_ms": None,
                "host": host, "port": int(port),
                "error": type(exc).__name__}


def probe_dns(hostname: str = "example.com",
              timeout_seconds: float = 3.0) -> dict:
    """Measure system DNS resolution with a process-level timeout."""
    started = time.perf_counter()
    if __import__("os").name == "nt":
        command = ["nslookup", hostname]
    else:
        command = ["getent", "ahosts", hostname]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            timeout=max(1.0, float(timeout_seconds)), check=False,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        if __import__("os").name == "nt":
            resolved = (
                result.returncode == 0
                and bool(re.search(r"(?im)^\s*Name\s*:", output))
                and not bool(re.search(
                    r"timed out|non-existent domain|can't find|server failed",
                    output, re.IGNORECASE,
                ))
            )
        else:
            resolved = result.returncode == 0 and bool(output.strip())
        return {
            "resolved": resolved,
            "latency_ms": round((time.perf_counter() - started) * 1000.0, 1)
            if resolved else None,
            "hostname": hostname,
            **({} if resolved else {"error": "DNS lookup failed."}),
        }
    except FileNotFoundError:
        return {"resolved": False, "latency_ms": None,
                "hostname": hostname, "error": "DNS lookup utility unavailable."}
    except subprocess.TimeoutExpired:
        return {"resolved": False, "latency_ms": None,
                "hostname": hostname, "error": "DNS lookup timed out."}
    except Exception as exc:
        return {"resolved": False, "latency_ms": None,
                "hostname": hostname, "error": type(exc).__name__}


def classify_state(gateway: dict, internet_icmp: dict,
                   internet_tcp: dict, dns: dict) -> str:
    """Classify connectivity using independent signals; ICMP alone is not truth."""
    tcp_ok = bool((internet_tcp or {}).get("reachable"))
    dns_ok = bool((dns or {}).get("resolved"))
    loss = (internet_icmp or {}).get("packet_loss_percent")
    rtt = (internet_icmp or {}).get("avg_rtt_ms")
    # A completely silent ICMP target may simply filter echo requests. If
    # TCP/443 and DNS both work, do not call that packet loss or an outage.
    icmp_filtered = (
        loss is not None and float(loss) >= 100.0 and rtt is None
    )
    degraded_icmp = (
        loss is not None and float(loss) >= 10.0 and not icmp_filtered
    ) or (
        rtt is not None and float(rtt) >= 500.0
    )
    if tcp_ok and dns_ok:
        return "DEGRADED" if degraded_icmp else "ONLINE"
    if tcp_ok or dns_ok:
        return "DEGRADED"
    if int((gateway or {}).get("received") or 0) > 0:
        return "INTERNET_DOWN"
    return "OFFLINE"


def calculate_health_score(sample: dict) -> int:
    """Return a transparent 0–100 operational score, not a probability."""
    score = 100.0
    loss = sample.get("packet_loss_percent")
    latency = sample.get("avg_latency_ms")
    dns_latency = sample.get("dns_resolution_ms")
    icmp_filtered = (
        sample.get("internet_icmp_status") in ("NO_RESPONSE", "TIMEOUT", "UNAVAILABLE")
        and bool(sample.get("internet_tcp_reachable"))
    )
    if loss is not None and not icmp_filtered:
        score -= min(55.0, max(0.0, float(loss)) * 0.55)
    if latency is not None and float(latency) > 100.0:
        score -= min(25.0, (float(latency) - 100.0) / 25.0)
    if dns_latency is None:
        score -= 20.0
    elif float(dns_latency) > 250.0:
        score -= min(15.0, (float(dns_latency) - 250.0) / 50.0)
    if sample.get("status") == "DEGRADED":
        score = min(score, 75.0)
    elif sample.get("status") == "INTERNET_DOWN":
        score = min(score, 25.0)
    elif sample.get("status") == "OFFLINE":
        score = min(score, 5.0)
    return max(0, min(100, int(round(score))))


class NetworkResilienceMonitor:
    """Background monitor for the local host's gateway and internet path."""

    def __init__(
        self,
        context_provider: Callable[[], dict],
        sample_callback: Optional[Callable[[dict], None]] = None,
        event_callback: Optional[Callable[[dict], None]] = None,
        interval_seconds: int = 30,
        target_ip: str = "1.1.1.1",
        dns_hostname: str = "example.com",
        icmp_probe: Callable = probe_icmp,
        tcp_probe: Callable = probe_tcp,
        dns_probe: Callable = probe_dns,
    ):
        self.context_provider = context_provider
        self.sample_callback = sample_callback or (lambda _sample: None)
        self.event_callback = event_callback or (lambda _event: None)
        self.interval_seconds = max(15, min(300, int(interval_seconds)))
        self.target_ip = target_ip
        self.dns_hostname = dns_hostname
        self.icmp_probe = icmp_probe
        self.tcp_probe = tcp_probe
        self.dns_probe = dns_probe
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._thread = None
        self._state = {
            "available": False, "status": "STARTING", "health_score": None,
            "timestamp": "", "message": "Waiting for the first resilience sample.",
        }

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def snapshot(self) -> dict:
        with self._lock:
            result = dict(self._state)
        result["running"] = self.running
        return result

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="NR-NetworkResilience", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(0.1, float(timeout)))

    def sample_once(self) -> dict:
        context = self.context_provider() or {}
        gateway_ip = str(context.get("gateway") or "")
        gateway = self.icmp_probe(gateway_ip) if gateway_ip else {
            "status": "NOT_CONFIGURED", "sent": 0, "received": 0,
            "packet_loss_percent": None, "avg_rtt_ms": None,
            "min_rtt_ms": None, "max_rtt_ms": None,
        }
        internet_icmp = self.icmp_probe(self.target_ip)
        internet_tcp = self.tcp_probe(self.target_ip, 443)
        dns = self.dns_probe(self.dns_hostname)
        state = classify_state(gateway, internet_icmp, internet_tcp, dns)
        notes = []
        if gateway_ip and not gateway.get("received"):
            notes.append("Gateway did not answer ICMP; this alone does not prove an outage.")
        if not internet_tcp.get("reachable"):
            notes.append("Outbound TCP connectivity check failed.")
        if not dns.get("resolved"):
            notes.append("System DNS resolution failed.")
        sample = {
            "available": True,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "network": str(context.get("network") or ""),
            "gateway": gateway_ip,
            "adapter": str(context.get("interface") or ""),
            "status": state,
            "health_score": 0,
            "gateway_status": gateway.get("status", "UNKNOWN"),
            "gateway_packet_loss_percent": gateway.get("packet_loss_percent"),
            "gateway_avg_rtt_ms": gateway.get("avg_rtt_ms"),
            "internet_icmp_status": internet_icmp.get("status", "UNKNOWN"),
            "packet_loss_percent": internet_icmp.get("packet_loss_percent"),
            "avg_latency_ms": internet_icmp.get("avg_rtt_ms"),
            "min_latency_ms": internet_icmp.get("min_rtt_ms"),
            "max_latency_ms": internet_icmp.get("max_rtt_ms"),
            "internet_tcp_reachable": bool(internet_tcp.get("reachable")),
            "tcp_latency_ms": internet_tcp.get("latency_ms"),
            "dns_status": "RESOLVED" if dns.get("resolved") else "FAILED",
            "dns_resolution_ms": dns.get("latency_ms"),
            "notes": notes,
        }
        sample["health_score"] = calculate_health_score(sample)
        with self._lock:
            previous = dict(self._state)
            same_network = previous.get("network", "") == sample["network"]
            previous_state = previous.get("status", "STARTING") if same_network else "STARTING"
            self._state = dict(sample)
        try:
            self.sample_callback(dict(sample))
        except Exception:
            pass
        event = self._transition_event(previous_state, sample)
        if event:
            try:
                self.event_callback(event)
            except Exception:
                pass
        return sample

    @staticmethod
    def _transition_event(previous_state: str, sample: dict):
        current = str(sample.get("status") or "UNKNOWN")
        if previous_state in ("", "STARTING", "UNKNOWN") or current == previous_state:
            return None
        if current in ("OFFLINE", "INTERNET_DOWN"):
            event_type, severity = "NETWORK_OUTAGE_STARTED", "CRITICAL"
        elif current == "DEGRADED":
            event_type, severity = "NETWORK_DEGRADED", "MEDIUM"
        elif current == "ONLINE" and previous_state in (
            "OFFLINE", "INTERNET_DOWN", "DEGRADED"
        ):
            event_type, severity = "NETWORK_RECOVERED", "INFO"
        else:
            event_type, severity = "NETWORK_STATE_CHANGED", "INFO"
        return {
            "timestamp": sample.get("timestamp", ""),
            "network": sample.get("network", ""),
            "event_type": event_type,
            "previous_state": previous_state,
            "current_state": current,
            "severity": severity,
            "details": (
                f"Network state changed from {previous_state} to {current}. "
                f"Health score: {sample.get('health_score', '—')}/100."
            ),
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample_once()
            except Exception as exc:
                with self._lock:
                    self._state.update({
                        "available": False, "status": "ERROR",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Resilience sample failed: {type(exc).__name__}",
                    })
            self._stop.wait(self.interval_seconds)
