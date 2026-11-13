"""
startup_guard.py — duplicate-instance prevention + explicit port handling.

Fixes 8.1.0 defect D5: start_web() silently iterated 8765..8772 and fell back
to port 0. Per PART 18, port switching must be explicit and announced.
"""
from __future__ import annotations
import json, os, socket, subprocess, sys, time

_LOCK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "database")
_LOCK_FILE = os.path.join(_LOCK_DIR, ".networkradar.lock")

class StartupError(RuntimeError):
    pass

def _pid_alive(pid: int) -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5).stdout
        return str(pid) in out and "No tasks" not in out
    except Exception:
        return False

def acquire_instance_lock() -> None:
    os.makedirs(_LOCK_DIR, exist_ok=True)
    if os.path.exists(_LOCK_FILE):
        try:
            with open(_LOCK_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            pid = int(data.get("pid", 0))
        except (ValueError, OSError, json.JSONDecodeError):
            pid = 0
        if pid and _pid_alive(pid):
            raise StartupError(
                f"Another NetworkRadar instance is already running (PID {pid}). "
                f"If it is hung, delete {_LOCK_FILE} manually and retry.")
        try: os.remove(_LOCK_FILE)
        except OSError: pass
    with open(_LOCK_FILE, "w", encoding="utf-8") as f:
        json.dump({"pid": os.getpid(), "started": time.time()}, f)

def release_instance_lock() -> None:
    try:
        with open(_LOCK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if int(data.get("pid", 0)) == os.getpid():
            os.remove(_LOCK_FILE)
    except (OSError, ValueError, json.JSONDecodeError):
        pass

def _port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) != 0

def _port_owner(port: int) -> dict | None:
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-NetTCPConnection -LocalPort {port} -State Listen | "
             f"Select-Object -First 1 OwningProcess | ConvertTo-Json"],
            capture_output=True, text=True, timeout=8)
        if p.returncode != 0 or not p.stdout.strip():
            return None
        d = json.loads(p.stdout)
        pid = d.get("OwningProcess")
        if not pid:
            return None
        q = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-Process -Id {pid} | Select-Object Id,ProcessName,Path | "
             f"ConvertTo-Json"],
            capture_output=True, text=True, timeout=8)
        return json.loads(q.stdout) if q.returncode == 0 else {"Id": pid}
    except Exception:
        return None

def require_port(host: str, port: int, allow_alternate: bool = False) -> int:
    """Return a bound port or raise StartupError. Never silently switches."""
    if _port_available(host, port):
        return port
    owner = _port_owner(port)
    msg = f"Port {port} on {host} is already in use"
    if owner:
        msg += f" by PID {owner.get('Id')} ({owner.get('ProcessName', '?')})"
    msg += "."
    if allow_alternate:
        for candidate in range(port + 1, port + 20):
            if _port_available(host, candidate):
                print(f"WARNING: {msg} Using alternate port {candidate} "
                      f"(explicit --allow-alt-port).")
                return candidate
    raise StartupError(msg + " Set NETWORKRADAR_PORT or pass --allow-alt-port.")