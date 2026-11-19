"""Bounded, explicit iPerf3 network-load testing.

This module never generates traffic by itself. A local API action must start a
single bounded test against an explicitly supplied iPerf3 server.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import threading
import time
import uuid


MAX_DURATION_SECONDS = 60
MAX_AGGREGATE_MBPS = 50
MAX_STREAMS = 4


def validate_test_config(target, duration_seconds=20, aggregate_mbps=5, streams=1):
    try:
        address = ipaddress.ip_address(str(target).strip())
    except ValueError as exc:
        raise ValueError("Target must be a literal IPv4 address; hostnames are not accepted.") from exc
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
        raise ValueError("Target must be a usable IPv4 address.")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int) or not 5 <= duration_seconds <= MAX_DURATION_SECONDS:
        raise ValueError("Test duration must be between 5 and 60 seconds.")
    if isinstance(aggregate_mbps, bool) or not isinstance(aggregate_mbps, (int, float)) or not 0.25 <= float(aggregate_mbps) <= MAX_AGGREGATE_MBPS:
        raise ValueError("Aggregate traffic rate must be between 0.25 and 50 Mbps.")
    if isinstance(streams, bool) or not isinstance(streams, int) or not 1 <= streams <= MAX_STREAMS:
        raise ValueError("Parallel streams must be between 1 and 4.")
    return {
        "target": str(address),
        "duration_seconds": duration_seconds,
        "aggregate_mbps": float(aggregate_mbps),
        "streams": streams,
    }


class NetworkLoadTestManager:
    """Runs one bounded iperf3 UDP test and retains its latest result."""

    def __init__(self, which=None, popen=None):
        self._which = which or shutil.which
        self._popen = popen or subprocess.Popen
        self._lock = threading.RLock()
        self._job = None
        self._process = None
        self._worker = None

    def status(self):
        with self._lock:
            if not self._job:
                return {"state": "IDLE", "available": bool(self._which("iperf3"))}
            return dict(self._job, available=bool(self._which("iperf3")))

    def start(self, target, duration_seconds=20, aggregate_mbps=5, streams=1):
        config = validate_test_config(target, duration_seconds, aggregate_mbps, streams)
        executable = self._which("iperf3")
        if not executable:
            raise RuntimeError("iperf3 was not found. Install the official iperf3 Windows build and ensure iperf3.exe is on PATH.")
        with self._lock:
            if self._job and self._job.get("state") in ("STARTING", "RUNNING", "STOPPING"):
                raise RuntimeError("A network-load test is already running. Stop it before starting another.")
            job_id = uuid.uuid4().hex[:12]
            self._job = {
                "job_id": job_id, "state": "STARTING", **config,
                "started_at": time.time(), "finished_at": None,
                "throughput_mbps": None, "jitter_ms": None,
                "lost_percent": None, "error": None,
            }
            self._worker = threading.Thread(target=self._run, args=(job_id, executable, config), daemon=True,
                                            name="NetworkRadarLoadTest")
            self._worker.start()
            return dict(self._job)

    def _run(self, job_id, executable, config):
        per_stream = config["aggregate_mbps"] / config["streams"]
        command = [
            executable, "-c", config["target"], "-u", "-b", f"{per_stream:.3f}M",
            "-P", str(config["streams"]), "-t", str(config["duration_seconds"]), "-J",
        ]
        process = None
        try:
            process = self._popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, encoding="utf-8", errors="replace")
            with self._lock:
                if not self._job or self._job.get("job_id") != job_id:
                    process.terminate()
                    return
                self._process = process
                stopping = self._job["state"] == "STOPPING"
                if not stopping:
                    self._job["state"] = "RUNNING"
            # A stop can arrive while Popen is being created. Re-check after
            # publishing the process handle so that early emergency stops win.
            if stopping:
                process.terminate()
            output, _ = process.communicate(timeout=config["duration_seconds"] + 12)
            parsed = {}
            try:
                parsed = json.loads(output or "{}")
            except (TypeError, ValueError):
                pass
            end = parsed.get("end", {}) if isinstance(parsed, dict) else {}
            summary = end.get("sum", {}) if isinstance(end, dict) else {}
            throughput = summary.get("bits_per_second")
            jitter = summary.get(" jitter_ms", summary.get("jitter_ms"))
            lost = summary.get(" lost_percent", summary.get("lost_percent"))
            with self._lock:
                if self._job and self._job.get("job_id") == job_id:
                    stopped = self._job["state"] == "STOPPING"
                    self._job.update({
                        "state": "STOPPED" if stopped else ("COMPLETED" if process.returncode == 0 else "FAILED"),
                        "finished_at": time.time(),
                        "throughput_mbps": round(float(throughput) / 1_000_000, 3) if throughput is not None else None,
                        "jitter_ms": round(float(jitter), 3) if jitter is not None else None,
                        "lost_percent": round(float(lost), 3) if lost is not None else None,
                        "error": None if process.returncode == 0 or stopped else (output or "iperf3 exited unsuccessfully")[-1200:],
                    })
        except subprocess.TimeoutExpired:
            if process:
                process.kill()
                output, _ = process.communicate()
            with self._lock:
                if self._job and self._job.get("job_id") == job_id:
                    self._job.update(state="FAILED", finished_at=time.time(), error="iperf3 exceeded its hard execution timeout.")
        except Exception as exc:
            with self._lock:
                if self._job and self._job.get("job_id") == job_id:
                    self._job.update(state="FAILED", finished_at=time.time(), error=str(exc)[:500])
        finally:
            with self._lock:
                if self._job and self._job.get("job_id") == job_id:
                    self._process = None

    def stop(self):
        with self._lock:
            if not self._job or self._job.get("state") not in ("STARTING", "RUNNING", "STOPPING"):
                return {"stopped": False, "message": "No active load test.", **self.status()}
            self._job["state"] = "STOPPING"
            process = self._process
        if process:
            try:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            except Exception:
                pass
        return {"stopped": True, **self.status()}


NETWORK_LOAD_TEST = NetworkLoadTestManager()
