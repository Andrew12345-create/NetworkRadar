"""
NetworkRadar 12.0.3 — PHANTOM ACCESS NEXUS. DASHBOARD LOAD HOTFIX.
Modular runtime + established intelligence core. Authorised networks only.\n\n
12.0.1 changes:
  - Adds Phantom Terminal with authenticated interactive SSH sessions over a
    same-origin, local-only WebSocket bridge.
  - Requires explicit SSH host-key fingerprint review and persistent trust before
    authentication; unknown or changed host keys are rejected.
  - Supports SSH agent/default key discovery, explicit private-key paths and
    password authentication; credentials are memory-only and never audited.
  - Adds SSH access discovery, capability reporting and session audit events.
  - Separates the dashboard stylesheet and JavaScript into served local assets.
  - Introduces a redesigned responsive control-centre visual system and terminal UI.
  - Fixes unsafe inline device-row handlers and removes silent bulk-selection truncation.
  - Bulk operations now process all selected devices in visible batches of 12.
  - Preserves all existing NetworkRadar data and management permission boundaries.

11.3.0 changes:
  - Adds bounded bulk Phantom Access control for up to 12 selected ONLINE devices.
  - Adds a selectable endpoint table and bulk Probe, System Inventory, Network,
    Storage and Security snapshot controls.
  - Runs bulk work with a four-worker concurrency ceiling and per-device results;
    one endpoint failure does not cancel the remaining selected devices.
  - Bulk mode is allowlisted to discovery and read-only inventory. Restart,
    shutdown and service changes remain individual and confirmation-gated.
  - Refreshes capability reachability immediately before each bulk read operation.
  - Preserves current-user Windows authentication, private-LAN inventory checks,
    network authorisation checks and per-operation audit records.

11.2.0 changes:
  - Requires three consecutive non-empty completed discovery scans before marking
    a device OFFLINE; an empty discovery result cannot take the inventory offline.
  - Refreshes Phantom Track automatically after each successful inventory
    enrichment and only refreshes anchors for devices currently ONLINE.
  - Marks continuity records for offline devices HISTORICAL rather than giving
    them a false current last-seen timestamp.
  - Improves TShark interface selection, explicitly matches configured interface
    names, prefers Wi-Fi, and captures per-attempt DHCP stderr/exit diagnostics.
  - Reuses an existing open investigation for the same affected device/IP to
    prevent a new investigation for every alert cluster.
  - Classifies 0.0.0.0 ARP sender records as address probes, excludes them from
    duplicate-IP conflict findings, and filters reverse-DNS/mDNS names from the
    external top-domain leaderboard.
  - Marks endpoints NATIVE_READ_VERIFIED for 30 minutes after a successful
    authenticated WMI/WinRM read, separately from port-only capability guesses.
  - Keeps all database changes additive; no destructive migration or history purge.

11.1.0 changes:
  - Adds a tabbed Device Intelligence Workspace covering overview, identity,
    hardware, OS, network, services, behaviour, relationships, security,
    history and investigations.
  - Extends the device profile API with evidence-backed identity assessments,
    DHCP observations, DNS activity, service scan history, exposure findings,
    behaviour alerts, topology links and investigation records.
  - Keeps observed evidence separate from inferred classifications and exposes
    confidence, independent source counts and conflicts in the UI.
  - Uses additive, read-only queries against existing tables; no database
    migration and no destructive changes to existing records.

11.0.1 fixes:
  - Enforces a 3-minute freshness window for capability probes before remote actions.
  - Corrects remote restart/shutdown to execute shutdown.exe inside the authenticated WinRM session; avoids invalid -UseSSL use on Restart-Computer/Stop-Computer.
  - Audits failed agentless actions as well as successful actions.
  - Stops stale agent heartbeats from leaving devices permanently labelled AGENT_MANAGED.
  - Defaults the optional TLS agent hub to loopback; LAN binding must be explicitly configured.
  - Prevents duplicate agent-hub startup and closes the listener socket after TLS startup failure.
  - Prevents a report/result race from reviving a revoked agent.
  - Validates local management API JSON object bodies.

11.0.0 changes:
  - Adds Phantom Access agentless capability discovery for known inventory devices.
  - Adds read-only Windows native management through current-user WinRM/PowerShell Remoting.
  - Adds guarded remote inventory/process/service inspection and explicitly confirmed power/service actions.
  - Adds RDP launch hand-off when the target RDP service is reachable; no embedded remote desktop server.
  - Adds agentless access readiness classifications, persistent probe history and audit events.
  - Keeps the enrolled endpoint agent as an optional advanced management path.

10.0.0 changes:
  - Adds an opt-in TLS endpoint-agent hub with one-time enrolment, per-agent HMAC
    authentication, replay protection, revocation and an audited command queue.
  - Adds a separate Windows endpoint agent for inventory, process/service listing,
    workstation lock and explicitly confirmed restart/shutdown/service restart.
  - Adds Command Centre UI for agent enrolment, health, inventory and approved actions.
  - Agent listener remains disabled unless explicitly enabled and supplied TLS cert/key.

9.6.0 changes:
  - Adds multi-source advanced device recognition with explainable signature matches.
  - Expands Nmap service discovery to the top 100 TCP ports and captures structured product/version metadata.
  - Adds safe HTTP/HTTPS service metadata probes, including page title, server, content type and product hints.
  - Adds optional passive TCP SYN fingerprint observations using TShark; labels these as heuristic, not p0f.
  - Persists recognition assessments and exposes evidence/matches in the device detail panel.
  - Keeps device-reported manufacturer/model separate from IEEE NIC OUI manufacturer.

9.5.0 changes:
  - Restores strict port 8766 behaviour; alternate ports require explicit --allow-alt-port.
  - Tracks per-host Nmap scan completeness and stores append-only port-scan observations.
  - Exposure findings resolve only from a newer completed scan; incomplete scans cannot close findings.
  - Findings become STALE after 30 days without confirmation and remain visible until rechecked.
  - IPv6 collection reports unavailable/error/timeout/no-data states and filters incomplete neighbours.
  - IPv6 neighbour history is append-only; exact MAC matches link IPv6 addresses to inventory evidence.
  - Unknown Device Hunter can create/update deduplicated, low-severity identity-review investigations.
  - SNMPv3 secrets are removed from process arguments and passed through a temporary Net-SNMP config.
  - Dashboard CSS, responsive layouts, focus states, active navigation, refresh locking and request timeouts improved.
  - Device-row interaction no longer interpolates inventory data into inline JavaScript handlers.
  - Local HTTP responses include restrictive security headers; database migrations remain additive.

9.0.0 intelligence panels and existing 8.7.0/Phantom Track functionality are retained.

8.7.0 changes:
  - Default local dashboard port is 8766; NETWORKRADAR_PORT remains configurable.
  - Presence tracking exposes SUSPECTED_OFFLINE after one missed completed scan
    and only transitions to OFFLINE after the configured consecutive misses.
  - DNS NXDOMAIN burst detection correlates response counts with observed query
    volume and unique failed names over a rolling five-minute window.
  - DHCP TShark startup/exit diagnostics include executable, interface, filter,
    exit code and bounded stderr tail where available.
  - Existing database schema and records remain intact; no destructive migration.

8.4.0 recovery changes: OS-managed atomic instance lock; bind-first local HTTP\nstartup (removes port pre-check race); modular PHANTOM TRACK scoring; core\npackage and regression tests. Existing API and database are retained.

8.2.0 changes vs 8.1.0 (authoritative summary — see audit for defect IDs):
  D1  CRITICAL: authorisation bypass at low confidence — CLOSED. Active
      discovery now requires matched + approved + fresh profile AND
      fingerprint confidence >= 55%. A profile is never treated as approved
      merely because its subnet matches.
  D2  HIGH: single fragile PowerShell command — CLOSED. Network detection
      uses 4 independent Windows APIs (Get-NetAdapter, Get-NetIPAddress,
      Get-NetRoute, Get-DnsClientServerAddress). DNS is not lost when
      Get-NetIPConfiguration fails.
  D3  HIGH: fragile `arp -a` text parse for gateway MAC — CLOSED.
      Get-NetNeighbor is used, with state gating (Reachable/Stale/Permanent).
  D4  HIGH: host attributes in network fingerprint — CLOSED. Adapter alias
      and adapter MAC are excluded from network identity (alias is UI/localized;
      MAC is a host attribute). Fingerprint = subnet+gateway+gw_mac+dns+dhcp+ssid+bssid.
  D5  HIGH: silent port fallback + no duplicate-instance lock — CLOSED.
      Port conflicts raise a clear error unless --allow-alt-port; a PID-based
      lock file prevents two instances.
  D6  MEDIUM: unbounded continuity-observation growth — CLOSED. 10-minute
      dedupe window per (continuity_id, ip, mac, class).
  D7  MEDIUM: DHCP "DEGRADED" without distinguishing causes — CLOSED.
      DHCPEngine exposes diagnostic_classification() classifying CAPTURE_UNAVAILABLE,
      CAPTURE_DEGRADED, CAPTURE_STARTING, TRAFFIC_NOT_OBSERVED, OBSERVING, UNKNOWN.
  D9  MEDIUM: no historical network context — CLOSED. network_context_observations
      table stores every detection with per-attribute classification.
  D10 LOW: device_relationships lacks evidence_class — CLOSED. Additive column.
  D11 LOW: _fp_confidence dead code — CLOSED. Weighted fingerprint gates authz.
  D13 MEDIUM: presence states incomplete — CLOSED. SUSPECTED_OFFLINE, OFFLINE,
      RETURNED, INTERMITTENT, UNVERIFIED, UNKNOWN supported. One missed scan
      never marks OFFLINE.

Phantom Track 2.0 (Part 4):
  Weighted identity matching with:
    - independence groups (multiple observations from one source capped)
    - 30-day freshness half-life
    - CONFLICTING_IDENTITY when strong evidence disagrees
    - Locally administered MACs token-only (never merge path)
    - Only CONFIRMED_MATCH auto-merges; every other outcome requires manual review
  Manual review workflow: GET /api/identity/candidates, POST /api/identity/candidates/review

Still deferred (explicitly, honestly):
  - p0f deployment/integration (requires separately installed and validated binary)
  - JA3/JA4 TLS client fingerprint extraction (not yet wired into packet pipeline)
  - Authenticated router/access-point integrations (vendor-specific credentials/APIs)
  - Endpoint agent for exact hardware/serial inventory (not delivered)
  - Digital Twin historical playback and physical topology certainty (not delivered)
  - Full dashboard information-architecture redesign (9.5.0 improves CSS/interaction but retains existing sections)
  - Automated DNS incident grouping (existing alerts and correlations preserved)

Existing 8.1.0 functionality and database are preserved. All schema changes are
additive. No historical records are deleted.
"""

import os, sys, time, uuid, shutil, json, webbrowser, hashlib, csv, math, secrets, hmac, ssl, socketserver, base64, struct, select
import re, threading, subprocess, sqlite3, socket, ipaddress
import urllib.request, urllib.parse, tempfile
import xml.etree.ElementTree as ET
import queue as _queue
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    import paramiko
except ImportError:
    paramiko = None

# The package metadata is the single source of the application version.
from networkradar_modules import __version__ as APP_VERSION
from networkradar_modules.identity.fusion import score_evidence as _modular_score_evidence

class StartupError(RuntimeError):
    pass

_NR_LOCK_HANDLE = None
_NR_LOCK_GUARD = threading.Lock()

def _legacy_pid_is_alive(raw):
    """Deprecated PID-file probe; OS byte-range locking is authoritative.

    A PID is not a process identity: Windows and Unix routinely reuse PIDs.
    Treating a stale PID file as proof of a live NetworkRadar instance can
    prevent startup indefinitely when an unrelated process reuses that PID.
    The exclusive OS lock below safely detects a concurrently running instance
    and is automatically released when its process exits.
    """
    return None

def _acquire_os_lock(path):
    global _NR_LOCK_HANDLE
    with _NR_LOCK_GUARD:
        if _NR_LOCK_HANDLE is not None: return
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        handle = open(path, "a+b")
        try:
            # PID files are not reliable process identities because PIDs are
            # reused. The OS-managed exclusive lock below is authoritative.
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0: handle.write(b"\0"); handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                try: msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc: raise StartupError("Another NetworkRadar instance holds the startup lock.") from exc
            else:
                import fcntl
                try: fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc: raise StartupError("Another NetworkRadar instance holds the startup lock.") from exc
            handle.seek(0); handle.truncate(); handle.write(f"pid={os.getpid()}\n".encode("ascii")); handle.flush()
            _NR_LOCK_HANDLE = handle
        except Exception:
            handle.close(); raise

def _release_os_lock():
    global _NR_LOCK_HANDLE
    with _NR_LOCK_GUARD:
        h, _NR_LOCK_HANDLE = _NR_LOCK_HANDLE, None
        if h is None: return
        try:
            if os.name == "nt":
                import msvcrt
                h.seek(0); msvcrt.locking(h.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(h.fileno(), fcntl.LOCK_UN)
        finally: h.close()

class _LocalOnlyHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False

def bind_local_server(handler, host, requested_port, allow_alternate=False, search_span=20):
    if not (1 <= int(requested_port) <= 65535): raise StartupError(f"Invalid TCP port: {requested_port}")
    ports = [int(requested_port)]
    if allow_alternate: ports.extend(range(int(requested_port)+1, min(65536, int(requested_port)+search_span+1)))
    last = None
    for port in ports:
        try:
            server = _LocalOnlyHTTPServer((host, port), handler)
            return server, int(server.server_address[1])
        except OSError as exc: last = exc
    msg = f"{host}:{requested_port} could not be bound ({last})."
    msg += f" Tried next {search_span} ports." if allow_alternate else " Choose another port with NETWORKRADAR_PORT or explicitly use --allow-alt-port."
    raise StartupError(msg) from last

def _score_identity_evidence(candidate, *, now=None, thresholds=None,
                              half_life_days=30.0, group_cap=0.45,
                              auto_merge=frozenset({"CONFIRMED_MATCH"}),
                              conflict_kinds=frozenset({"hostname", "client_id", "oui_global"}),
                              local_group="oui_local"):
    """Use the tested PHANTOM TRACK scorer; keep the legacy call signature."""
    return _modular_score_evidence(
        candidate,
        now=now,
        thresholds=thresholds or {
            "CONFIRMED_MATCH": 0.85,
            "STRONG_MATCH": 0.70,
            "POSSIBLE_MATCH": 0.50,
            "WEAK_MATCH": 0.30,
        },
        half_life_days=half_life_days,
        group_cap=group_cap,
        auto_merge=frozenset(auto_merge),
        conflict_kinds=frozenset(conflict_kinds),
        local_group=local_group,
    )

def engine_record(name, reported_status, *, last_error="", configured=True, details=None):
    raw = str(reported_status or "UNKNOWN").upper()
    if not configured: state = "NOT_CONFIGURED"
    elif raw in {"RUNNING", "OBSERVING"}: state = "DEGRADED" if last_error else "ONLINE"
    elif raw in {"ONLINE", "DEGRADED", "FAILED", "STOPPED", "STARTING", "DISABLED", "NOT_CONFIGURED"}: state = raw
    else: state = "UNKNOWN"
    return {"engine": str(name), "status": state, "reported_status": raw, "last_error": str(last_error or "")[:500], "details": details or {}}


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
LOG_DIR = DATA / "logs"
DB = ROOT / "database" / "networkradar.db"
NMAP_LOG = LOG_DIR / "nmap-latest.log"
DNS_LOG = LOG_DIR / "tshark-dns.log"
DHCP_LOG = LOG_DIR / "tshark-dhcp.log"
ARP_LOG = LOG_DIR / "tshark-arp.log"
LOCK_FILE = ROOT / "database" / ".networkradar.lock"

NMAP = Path(os.environ.get("NETWORKRADAR_NMAP") or shutil.which("nmap")
            or r"C:\Program Files (x86)\Nmap\nmap.exe")
TSHARK = Path(os.environ.get("NETWORKRADAR_TSHARK") or shutil.which("tshark")
              or r"C:\Program Files\Wireshark\tshark.exe")
NETWORK_OVERRIDE = os.environ.get("NETWORKRADAR_NETWORK", "").strip()
PREFERRED_INTERFACE = os.environ.get("NETWORKRADAR_TSHARK_INTERFACE", "").strip()

WEB_HOST, WEB_PORT = "127.0.0.1", 8766  # 8.7.0 default; override with NETWORKRADAR_PORT
WEB_URL = f"http://{WEB_HOST}:{WEB_PORT}"
SCAN_INTERVAL = 30
FINGERPRINT_EVERY_N_SCANS = 10
FINGERPRINT_TOP_PORTS = 100
ALERTS_DEDUP_WINDOW_SECONDS = 900
DEVICE_OFFLINE_CONFIRM_SCANS = 3
DNS_TUNNEL_WINDOW_SECONDS = 600
DNS_TUNNEL_MIN_UNIQUE_LABELS = 20
RISK_HALF_LIFE_HOURS = 24.0
MIN_FP_CONFIDENCE = 0.55
PROFILE_MAX_AGE_DAYS = 90

DNS_CAPTURE_FILTER = "udp port 53 or tcp port 53 or udp port 5353 or udp port 5355"
DHCP_CAPTURE_FILTER = "udp port 67 or udp port 68"
ARP_CAPTURE_FILTER = "arp"

DATA.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
DB.parent.mkdir(parents=True, exist_ok=True)

STOP_EVENT = threading.Event()
SCAN_NOW_EVENT = threading.Event()

JOB_LOCK = threading.Lock()
JOB_STATE = {"state": "IDLE", "phase": "Waiting", "percent": 0,
             "started_at": "", "updated_at": "", "message": "Initialising.",
             "scan_number": 0, "last_error": ""}

NET_LOCK = threading.RLock()
NET_CTX = {"network": "", "ip": "", "gateway": "", "interface": "",
           "prefix": None, "ssid": "", "mode": "AUTO", "dns_servers": "",
           "adapter_mac": "", "gateway_mac": "", "bssid": "",
           "fingerprint": "", "fingerprint_raw": "", "authorized": False,
           "authorized_at": "", "confidence": 0, "confidence_notes": "",
           "warning": "", "changed": False, "last_checked": "",
           "auth_decision": "INDETERMINATE", "auth_reasons": []}

HEALTH_LOCK = threading.RLock()
HEALTH = {"status": "STARTING", "gateway": "", "gateway_latency_ms": None,
          "dns_resolution_ms": None, "internet": "UNKNOWN", "adapter": "",
          "sampled_at": "", "notes": []}

DNS_STATE_LOCK = threading.Lock()
DNS_STATE = {"status": "STARTING", "interface": "Not selected", "queries": 0,
             "responses": 0, "alerts": 0, "last_event": "Waiting", "error": ""}
DHCP_STATE_LOCK = threading.Lock()
DHCP_STATE = {"status": "STARTING", "interface": "Not selected", "messages": 0,
              "offers": 0, "acks": 0, "rogue": 0, "last_event": "Waiting",
              "error": "", "restart_count": 0, "last_started": "",
              "last_exit": "", "last_error": "", "failure_streak": 0}
ARP_STATE_LOCK = threading.Lock()
ARP_STATE = {"status": "STARTING", "interface": "Not selected",
             "observations": 0, "changes": 0, "gratuitous": 0,
             "last_event": "Waiting", "error": ""}

DNS_TYPE_NAMES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
                  "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV",
                  "35": "NAPTR", "65": "HTTPS", "41": "OPT", "43": "DS",
                  "46": "RRSIG", "47": "NSEC", "48": "DNSKEY", "52": "TLSA",
                  "255": "ANY"}
DNS_RCODE_NAMES = {"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL",
                   "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED"}
DHCP_TYPE_NAMES = {"1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE",
                   "5": "ACK", "6": "NAK", "7": "RELEASE", "8": "INFORM"}

# ============================================================
# UTILITIES
# ============================================================

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _clean(v, limit=180):
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v or ""))
    return re.sub(r"\s+", " ", v).strip()[:limit]

def _placeholder(v):
    return not v or v in ("-", "Unknown", "Unavailable", "Unidentified device")

def _decay(age_seconds):
    return 0.5 ** (max(0.0, age_seconds) / 3600.0 / RISK_HALF_LIFE_HOURS)

def shannon(v):
    if not v:
        return 0.0
    n = len(v)
    return -sum((v.count(c) / n) * math.log2(v.count(c) / n) for c in set(v))

def valid_unicast_mac(value):
    v = str(value or "").strip().upper().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", v):
        return False
    first = int(v[:2], 16)
    return not (first & 1) and v not in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}

def norm_domain(d):
    return (d or "").strip().rstrip(".").lower()

def classify_name_resolution(domain, qtype="", src="", dst=""):
    d = norm_domain(domain)
    qt = str(qtype or "").upper()
    try:
        dip = ipaddress.ip_address(dst) if dst else None
    except ValueError:
        dip = None
    if qt.startswith("MDNS/") or (dip and dip.is_multicast and
                                  str(dip) in {"224.0.0.251", "ff02::fb"}):
        return "MDNS"
    if qt.startswith("LLMNR/") or (dip and str(dip).lower() == "224.0.0.252"):
        return "LLMNR"
    if d.endswith(".in-addr.arpa") or d.endswith(".ip6.arpa") or qt == "PTR":
        return "REVERSE_DNS"
    if d.endswith(".local"):
        return "MDNS"
    return "UNICAST_DNS"

def update_job(**kw):
    with JOB_LOCK:
        for k, v in kw.items():
            if k == "state" and v == "RUNNING":
                JOB_STATE["started_at"] = now_text()
            if k == "percent" and v is not None:
                v = max(0, min(100, int(v)))
            if k == "message" and v is not None:
                v = str(v)[:240]
            if k == "error" and v is not None:
                v = str(v)[:500]
            if v is not None:
                JOB_STATE[k if k != "error" else "last_error"] = v
        JOB_STATE["updated_at"] = now_text()

# ============================================================
# STARTUP GUARD (D5)
# ============================================================

def acquire_instance_lock():
    try:
        _acquire_os_lock(LOCK_FILE)
    except StartupError as exc:
        raise RuntimeError(str(exc)) from exc

def release_instance_lock():
    _release_os_lock()

def _port_available(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex((host, port)) != 0

def _port_owner(port):
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

def require_port(host, port, allow_alternate=False):
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
    raise RuntimeError(msg + " Set NETWORKRADAR_PORT or pass --allow-alt-port.")

# ============================================================
# DATABASE MANAGER (unchanged from 8.1.0 — this is correct)
# ============================================================

class NestedWriteError(RuntimeError):
    pass

class DatabaseManager:
    def __init__(self, path, busy_ms=15000, queue_max=10000, batch_interval=0.03,
                 batch_max=200):
        self.path = Path(path)
        self.busy_ms = busy_ms
        self.q = _queue.Queue(maxsize=queue_max)
        self.batch_interval = batch_interval
        self.batch_max = batch_max
        self.stop_flag = threading.Event()
        self.ready = threading.Event()
        self.start_error = None
        self.thread = None
        self.wconn = None
        self.in_txn = threading.local()
        self.health_data = {"running": False, "processed": 0, "failed": 0,
                            "last_write_ms": 0.0, "last_error": "",
                            "dropped_async": 0}
        self.hlock = threading.Lock()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_flag.clear()
        self.ready.clear()
        self.start_error = None
        self.thread = threading.Thread(target=self._loop, daemon=True,
                                       name="NR-DBWriter")
        self.thread.start()
        if not self.ready.wait(10):
            raise RuntimeError("Database writer did not become ready.")
        if self.start_error:
            raise RuntimeError(f"Database writer startup failed: {self.start_error}")
        with self.hlock:
            self.health_data["running"] = True

    def stop(self, timeout=10.0):
        self.stop_flag.set()
        if self.thread:
            self.thread.join(timeout=timeout)
        alive = bool(self.thread and self.thread.is_alive())
        with self.hlock:
            self.health_data["running"] = alive
            if alive:
                self.health_data["last_error"] = "Writer did not stop before timeout."
        return not alive

    @contextmanager
    def read(self):
        conn = sqlite3.connect(self.path, timeout=self.busy_ms / 1000,
                               check_same_thread=False)
        try:
            conn.execute(f"PRAGMA busy_timeout={self.busy_ms}")
            conn.execute("PRAGMA query_only=ON")
            conn.row_factory = sqlite3.Row
            yield conn
        finally:
            conn.close()

    def write(self, fn, timeout=30.0):
        if getattr(self.in_txn, "active", False):
            raise NestedWriteError(
                "Write from inside a write. Pass the existing conn instead.")
        if self.stop_flag.is_set():
            raise RuntimeError("Database writer is stopping.")
        holder, done = {}, threading.Event()

        def _wrap(conn):
            self.in_txn.active = True
            try:
                return fn(conn)
            finally:
                self.in_txn.active = False

        try:
            self.q.put(("write", _wrap, holder, done), timeout=max(0.1, timeout))
        except _queue.Full:
            raise TimeoutError("Database write queue remained full.")
        if not done.wait(timeout):
            raise TimeoutError(
                "Database write is still queued or executing; check database health.")
        if "error" in holder:
            raise holder["error"]
        return holder.get("result")

    def submit_async(self, fn):
        if self.stop_flag.is_set():
            with self.hlock:
                self.health_data["dropped_async"] += 1
            return False
        try:
            self.q.put_nowait(("async", fn, None, None))
            return True
        except _queue.Full:
            with self.hlock:
                self.health_data["failed"] += 1
                self.health_data["dropped_async"] += 1
            return False

    def flush(self, timeout=10.0):
        done = threading.Event()
        if not self.thread or not self.thread.is_alive():
            return self.q.empty()
        try:
            self.q.put(("flush", None, None, done), timeout=min(2.0, timeout))
        except _queue.Full:
            return False
        return done.wait(timeout)

    def health(self):
        with self.hlock:
            return dict(self.health_data, queued=self.q.qsize())

    def _loop(self):
        try:
            self.wconn = sqlite3.connect(
                self.path, timeout=self.busy_ms / 1000, check_same_thread=False)
            self.wconn.execute(f"PRAGMA busy_timeout={self.busy_ms}")
            self.wconn.execute("PRAGMA journal_mode=WAL")
            self.wconn.execute("PRAGMA synchronous=NORMAL")
            self.wconn.execute("PRAGMA foreign_keys=ON")
            self.wconn.row_factory = sqlite3.Row
            self.ready.set()
        except Exception as exc:
            self.start_error = str(exc)
            self.ready.set()
            return

        while not self.stop_flag.is_set():
            batch, barriers = self._drain()
            if batch:
                self._exec(batch)
            for barrier in barriers:
                barrier.set()
            if not batch and not barriers:
                time.sleep(0.01)

        while True:
            batch, barriers = self._drain(final=True)
            if batch:
                self._exec(batch)
            for barrier in barriers:
                barrier.set()
            if not batch and not barriers:
                break
        try:
            self.wconn.close()
        except Exception:
            pass

    def _drain(self, final=False):
        batch, barriers = [], []
        deadline = time.monotonic() + self.batch_interval
        while len(batch) < self.batch_max:
            try:
                if not batch and not barriers:
                    item = self.q.get(timeout=0.05 if not final else 0.001)
                else:
                    item = self.q.get_nowait()
            except _queue.Empty:
                if final or time.monotonic() >= deadline:
                    break
                continue
            if item[0] == "flush":
                barriers.append(item[3])
                break
            batch.append(item)
        return batch, barriers

    def _exec(self, batch):
        started = time.perf_counter()
        failures = 0
        try:
            self.wconn.execute("BEGIN IMMEDIATE")
            for index, (_, fn, holder, done) in enumerate(batch):
                savepoint = f"nr_op_{index}"
                try:
                    self.wconn.execute(f"SAVEPOINT {savepoint}")
                    result = fn(self.wconn)
                    self.wconn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    if holder is not None:
                        holder["result"] = result
                except Exception as exc:
                    failures += 1
                    self.wconn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self.wconn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    if holder is not None:
                        holder["error"] = exc
                    with self.hlock:
                        self.health_data["last_error"] = str(exc)[:200]
            self.wconn.execute("COMMIT")
            for _, _, _, done in batch:
                if done is not None:
                    done.set()
            with self.hlock:
                self.health_data["processed"] += len(batch) - failures
                self.health_data["failed"] += failures
                self.health_data["last_write_ms"] = round(
                    (time.perf_counter() - started) * 1000, 2)
        except Exception as exc:
            try:
                self.wconn.execute("ROLLBACK")
            except Exception:
                pass
            for _, _, holder, done in batch:
                if holder is not None:
                    holder["error"] = exc
                if done is not None:
                    done.set()
            with self.hlock:
                self.health_data["failed"] += len(batch)
                self.health_data["last_error"] = str(exc)[:200]

DB_MANAGER = DatabaseManager(DB)

# ============================================================
# SCHEMA (8.1.0 preserved + 8.2.0 additions)
# ============================================================

def initialize_database():
    DB_MANAGER.start()
    with DB_MANAGER.read() as _:
        pass

    def _init(conn):
        conn.execute("PRAGMA journal_mode=WAL")
        # All 8.1.0 tables preserved verbatim + 8.2.0 additions
        schemas = [
            "CREATE TABLE IF NOT EXISTS devices(ip TEXT PRIMARY KEY, mac TEXT, "
            "manufacturer TEXT, hostname TEXT, first_seen TEXT, last_seen TEXT, status TEXT)",
            "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, ip TEXT, event_type TEXT, details TEXT)",
            "CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, network TEXT, hosts_up INTEGER, duration REAL)",
            "CREATE TABLE IF NOT EXISTS dns_events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, client_ip TEXT, resolver_ip TEXT, domain TEXT, "
            "query_type TEXT, is_response INTEGER DEFAULT 0, response_code TEXT, "
            "response_time REAL, answers TEXT, interface TEXT)",
            "CREATE TABLE IF NOT EXISTS domain_intel(domain TEXT PRIMARY KEY, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, query_count INTEGER DEFAULT 0, "
            "unique_clients INTEGER DEFAULT 0, last_response_code TEXT, "
            "risk_score INTEGER DEFAULT 0, risk_level TEXT DEFAULT 'INFO')",
            "CREATE TABLE IF NOT EXISTS dns_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, client_ip TEXT, domain TEXT, rule_id TEXT, "
            "severity TEXT, score INTEGER, details TEXT)",
            "CREATE TABLE IF NOT EXISTS dns_client_domains(client_ip TEXT NOT NULL, "
            "domain TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "query_count INTEGER DEFAULT 0, PRIMARY KEY(client_ip, domain))",
            "CREATE TABLE IF NOT EXISTS device_behavior_samples(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, device_id TEXT NOT NULL, ip TEXT NOT NULL, "
            "dns_queries INTEGER DEFAULT 0, unique_domains INTEGER DEFAULT 0, "
            "nxdomain_count INTEGER DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS device_behavior_baselines(device_id TEXT PRIMARY KEY, "
            "sample_count INTEGER DEFAULT 0, mean_dns_queries REAL DEFAULT 0, "
            "m2_dns_queries REAL DEFAULT 0, mean_unique_domains REAL DEFAULT 0, "
            "m2_unique_domains REAL DEFAULT 0, last_sample_at TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS behavior_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, device_id TEXT NOT NULL, ip TEXT NOT NULL, "
            "metric TEXT NOT NULL, observed REAL NOT NULL, baseline REAL NOT NULL, "
            "severity TEXT NOT NULL, details TEXT NOT NULL, status TEXT DEFAULT 'NEW')",
            "CREATE TABLE IF NOT EXISTS network_profiles(network TEXT PRIMARY KEY, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, interface TEXT DEFAULT '', "
            "gateway TEXT DEFAULT '', ssid TEXT DEFAULT '', approved INTEGER DEFAULT 0, "
            "profile_name TEXT DEFAULT '', notes TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, updated_at TEXT NOT NULL, title TEXT NOT NULL, "
            "severity TEXT NOT NULL, status TEXT DEFAULT 'OPEN', "
            "device_id TEXT DEFAULT '', source_alert_id INTEGER, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS network_health_samples(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, network TEXT, gateway TEXT, "
            "gateway_latency_ms REAL, dns_resolution_ms REAL, internet_status TEXT, "
            "adapter TEXT, notes TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS arp_bindings(ip TEXT PRIMARY KEY, "
            "mac TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "change_count INTEGER DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS network_security_events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT DEFAULT 'MEDIUM', "
            "ip TEXT DEFAULT '', old_value TEXT DEFAULT '', new_value TEXT DEFAULT '', "
            "details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS threat_indicators(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, "
            "source TEXT DEFAULT 'LOCAL', severity TEXT DEFAULT 'MEDIUM', "
            "description TEXT DEFAULT '', created_at TEXT NOT NULL, "
            "UNIQUE(indicator_type, indicator_value, source))",
            "CREATE TABLE IF NOT EXISTS threat_matches(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, indicator_id INTEGER, domain TEXT, client_ip TEXT, "
            "source_event_id INTEGER, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS pcap_imports(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, file_name TEXT, packet_count INTEGER DEFAULT 0, "
            "dns_queries INTEGER DEFAULT 0, status TEXT DEFAULT 'QUEUED', summary TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS device_observations(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, ip TEXT NOT NULL, method TEXT NOT NULL, "
            "observation TEXT NOT NULL, confidence INTEGER DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS device_identities(device_id TEXT PRIMARY KEY, "
            "identity_key TEXT UNIQUE NOT NULL, identity_basis TEXT NOT NULL, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS device_ip_history(device_id TEXT NOT NULL, "
            "ip TEXT NOT NULL, mac TEXT DEFAULT '', first_seen TEXT NOT NULL, "
            "last_seen TEXT NOT NULL, PRIMARY KEY(device_id, ip))",
            "CREATE TABLE IF NOT EXISTS network_events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, ip TEXT, device_id TEXT, category TEXT, "
            "event_type TEXT, severity TEXT DEFAULT 'INFO', details TEXT)",
            "CREATE TABLE IF NOT EXISTS dhcp_events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, msg_type TEXT, client_mac TEXT, client_ip TEXT, "
            "server_ip TEXT, requested_ip TEXT, hostname TEXT, vendor_class TEXT, "
            "router_opt TEXT, dns_opt TEXT, subnet_mask TEXT, lease_seconds INTEGER, "
            "network TEXT, interface TEXT, is_rogue INTEGER DEFAULT 0, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS arp_observations(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, opcode TEXT, sender_mac TEXT, sender_ip TEXT, "
            "target_mac TEXT, target_ip TEXT, interface TEXT, "
            "is_gratuitous INTEGER DEFAULT 0, change_type TEXT DEFAULT '', details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "investigation_id INTEGER, timestamp TEXT NOT NULL, evidence_type TEXT NOT NULL, "
            "source_ref TEXT DEFAULT '', content TEXT NOT NULL, content_sha256 TEXT NOT NULL, "
            "created_by TEXT DEFAULT 'system', notes TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS investigations(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, updated_at TEXT NOT NULL, title TEXT NOT NULL, "
            "description TEXT, severity TEXT NOT NULL, confidence INTEGER DEFAULT 0, "
            "status TEXT DEFAULT 'OPEN', affected_device_id TEXT DEFAULT '', "
            "affected_ip TEXT DEFAULT '', closure_reason TEXT DEFAULT '', notes TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS investigation_events(investigation_id INTEGER NOT NULL, "
            "network_event_id INTEGER NOT NULL, link_reason TEXT DEFAULT '', "
            "PRIMARY KEY(investigation_id, network_event_id))",
            "CREATE TABLE IF NOT EXISTS device_risk_scores(device_id TEXT PRIMARY KEY, "
            "timestamp TEXT NOT NULL, score INTEGER NOT NULL, band TEXT NOT NULL, "
            "explanation TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS topology_relationships(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, "
            "kind TEXT NOT NULL, evidence TEXT DEFAULT '', confidence INTEGER DEFAULT 0, "
            "last_seen TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS user_settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, device_id TEXT DEFAULT '', ip TEXT DEFAULT '', "
            "source TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, "
            "confidence INTEGER DEFAULT 0, title TEXT NOT NULL, details TEXT NOT NULL, "
            "dedup_key TEXT NOT NULL, status TEXT DEFAULT 'NEW', investigation_id INTEGER)",
            "CREATE TABLE IF NOT EXISTS network_changes(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, network_fp TEXT DEFAULT '', device_id TEXT DEFAULT '', "
            "ip TEXT DEFAULT '', change_type TEXT NOT NULL, category TEXT NOT NULL, "
            "severity TEXT DEFAULT 'INFO', details TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS config_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, network_fp TEXT DEFAULT '', finding_key TEXT NOT NULL, "
            "title TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, "
            "confidence INTEGER DEFAULT 0, evidence TEXT NOT NULL, recommendation TEXT NOT NULL, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, status TEXT DEFAULT 'OPEN', "
            "UNIQUE(finding_key))",
            "CREATE TABLE IF NOT EXISTS saved_queries(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, query_json TEXT NOT NULL, created_at TEXT NOT NULL, "
            "last_run_at TEXT DEFAULT '', UNIQUE(name))",
            "CREATE TABLE IF NOT EXISTS alert_investigations(alert_id INTEGER NOT NULL, "
            "investigation_id INTEGER NOT NULL, PRIMARY KEY(alert_id, investigation_id))",
            "CREATE TABLE IF NOT EXISTS network_approval_history(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, fingerprint TEXT NOT NULL, network TEXT NOT NULL, "
            "action TEXT NOT NULL, actor TEXT DEFAULT '', reason TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS device_network_presence(device_id TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "PRIMARY KEY(device_id, fingerprint))",
            "CREATE TABLE IF NOT EXISTS device_identity_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "device_id TEXT DEFAULT '', ip TEXT NOT NULL, source TEXT NOT NULL, "
            "attribute TEXT NOT NULL, observed_value TEXT NOT NULL, "
            "confidence INTEGER DEFAULT 0, evidence_class TEXT DEFAULT 'INFERRED', "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, source_version TEXT DEFAULT '', "
            "UNIQUE(ip, source, attribute, observed_value))",
            "CREATE TABLE IF NOT EXISTS device_identity_history(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "device_id TEXT DEFAULT '', ip TEXT NOT NULL, timestamp TEXT NOT NULL, "
            "attribute TEXT NOT NULL, old_value TEXT DEFAULT '', new_value TEXT DEFAULT '', "
            "reason TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS device_relationships(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, source_device_id TEXT DEFAULT '', source_ip TEXT NOT NULL, "
            "target_ip TEXT NOT NULL, relationship_type TEXT NOT NULL, evidence TEXT DEFAULT '', "
            "confidence INTEGER DEFAULT 0, last_seen TEXT NOT NULL, "
            "UNIQUE(source_ip, target_ip, relationship_type))",
            "CREATE TABLE IF NOT EXISTS oui_cache(prefix TEXT PRIMARY KEY, "
            "organization TEXT NOT NULL, registry TEXT DEFAULT '', updated_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS identity_engine_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, devices_processed INTEGER DEFAULT 0, "
            "evidence_added INTEGER DEFAULT 0, identified INTEGER DEFAULT 0, "
            "unknown INTEGER DEFAULT 0, errors TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS identity_assessments(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "device_id TEXT DEFAULT '', ip TEXT NOT NULL, attribute TEXT NOT NULL, "
            "assessed_value TEXT NOT NULL, confidence INTEGER DEFAULT 0, status TEXT DEFAULT 'LOW', "
            "supporting_sources TEXT DEFAULT '[]', conflicting_values TEXT DEFAULT '[]', "
            "evidence_count INTEGER DEFAULT 0, independent_sources INTEGER DEFAULT 0, "
            "rationale TEXT DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
            "UNIQUE(ip, attribute))",
            "CREATE TABLE IF NOT EXISTS identity_continuity_registry(continuity_id TEXT PRIMARY KEY, "
            "identity_key TEXT NOT NULL UNIQUE, anchor_type TEXT NOT NULL, anchor_hash TEXT NOT NULL, "
            "first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, current_ip TEXT DEFAULT '', "
            "current_mac TEXT DEFAULT '', hostname TEXT DEFAULT '', vendor_class TEXT DEFAULT '', "
            "device_type TEXT DEFAULT '', confidence INTEGER DEFAULT 0, "
            "status TEXT DEFAULT 'OBSERVED', notes TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS identity_continuity_observations(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "continuity_id TEXT NOT NULL, timestamp TEXT NOT NULL, ip TEXT NOT NULL, "
            "mac TEXT DEFAULT '', hostname TEXT DEFAULT '', vendor_class TEXT DEFAULT '', "
            "source TEXT NOT NULL, fingerprint_hash TEXT DEFAULT '', "
            "mac_class TEXT DEFAULT 'UNKNOWN', confidence INTEGER DEFAULT 0, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS identity_continuity_events(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT NOT NULL, continuity_id TEXT DEFAULT '', event_type TEXT NOT NULL, "
            "severity TEXT DEFAULT 'INFO', ip TEXT DEFAULT '', old_value TEXT DEFAULT '', "
            "new_value TEXT DEFAULT '', confidence INTEGER DEFAULT 0, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS identity_integration_registry(integration_id TEXT PRIMARY KEY, "
            "integration_type TEXT NOT NULL, display_name TEXT NOT NULL, "
            "status TEXT DEFAULT 'NOT_CONFIGURED', endpoint TEXT DEFAULT '', "
            "last_seen TEXT DEFAULT '', notes TEXT DEFAULT '', "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
            # ---- 8.2.0 new tables ----
            "CREATE TABLE IF NOT EXISTS network_context_observations("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
            "fingerprint TEXT, fingerprint_class TEXT, fingerprint_weight REAL, "
            "subnet TEXT, gateway TEXT, gateway_class TEXT, gateway_mac TEXT, "
            "gateway_mac_class TEXT, dns TEXT, dns_class TEXT, dhcp TEXT, dhcp_class TEXT, "
            "ssid TEXT, bssid TEXT, source_json TEXT)",
            "CREATE TABLE IF NOT EXISTS identity_candidates("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, device_a TEXT NOT NULL, "
            "device_b TEXT NOT NULL, outcome TEXT NOT NULL, score REAL NOT NULL, "
            "explain_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', "
            "created_at TEXT NOT NULL, reviewed_at TEXT, reviewer TEXT, "
            "UNIQUE(device_a, device_b, outcome))",
            "CREATE TABLE IF NOT EXISTS device_presence_events("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
            "device_id TEXT, ip TEXT, state TEXT NOT NULL, prior_state TEXT, "
            "confidence REAL, evidence_json TEXT)",
            "CREATE TABLE IF NOT EXISTS engine_diagnostics("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
            "engine TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, detail_json TEXT)",
        ]
        # 10.0.0 endpoint management: additive, agent identity and command audit only.
        schemas.extend([
            "CREATE TABLE IF NOT EXISTS remote_agents(agent_id TEXT PRIMARY KEY, hostname TEXT NOT NULL, platform TEXT NOT NULL, os_version TEXT DEFAULT '', agent_version TEXT DEFAULT '', secret_hash TEXT NOT NULL, status TEXT DEFAULT 'PENDING', enrolled_at TEXT NOT NULL, last_seen TEXT DEFAULT '', last_ip TEXT DEFAULT '', inventory_json TEXT DEFAULT '{}', capabilities_json TEXT DEFAULT '[]', revoked_at TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS agent_enrollment_tokens(token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT DEFAULT '', created_by TEXT DEFAULT 'local-user')",
            "CREATE TABLE IF NOT EXISTS agent_commands(id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, action TEXT NOT NULL, args_json TEXT DEFAULT '{}', status TEXT DEFAULT 'QUEUED', created_at TEXT NOT NULL, expires_at TEXT NOT NULL, approved_by TEXT NOT NULL, result_json TEXT DEFAULT '{}', completed_at TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS agent_request_nonces(agent_id TEXT NOT NULL, nonce TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(agent_id,nonce))",
            "CREATE TABLE IF NOT EXISTS agent_audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, agent_id TEXT DEFAULT '', actor TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, details TEXT DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS agentless_device_access(ip TEXT PRIMARY KEY, last_probe TEXT NOT NULL, probes_json TEXT DEFAULT '{}', readiness TEXT DEFAULT 'DISCOVERY_ONLY', readiness_score INTEGER DEFAULT 0, last_action TEXT DEFAULT '', last_result TEXT DEFAULT '')",
        ])
        for s in schemas:
            conn.execute(s)

        # 9.0.0 additive intelligence tables. Existing records are untouched.
        conn.execute("""CREATE TABLE IF NOT EXISTS ipv6_observations(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
            ipv6 TEXT NOT NULL, mac TEXT DEFAULT '', interface_index INTEGER DEFAULT 0,
            interface_alias TEXT DEFAULT '', state TEXT DEFAULT '',
            is_router INTEGER DEFAULT 0, source TEXT DEFAULT 'Windows neighbour table',
            UNIQUE(ipv6, mac, interface_index))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS exposure_findings(
            id INTEGER PRIMARY KEY AUTOINCREMENT, finding_key TEXT NOT NULL UNIQUE,
            ip TEXT NOT NULL, device_id TEXT DEFAULT '', rule_id TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER DEFAULT 0,
            observed_ports TEXT DEFAULT '', evidence TEXT DEFAULT '',
            recommendation TEXT DEFAULT '', first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL, status TEXT DEFAULT 'OPEN')""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ipv6_last_seen ON ipv6_observations(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exposure_status ON exposure_findings(status,severity,last_seen)")
        # 9.5.0: append-only scan evidence. An incomplete scan must never close a finding.
        conn.execute("""CREATE TABLE IF NOT EXISTS port_scan_observations(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ip TEXT NOT NULL,
            device_id TEXT DEFAULT '', completed INTEGER NOT NULL DEFAULT 0,
            open_ports TEXT DEFAULT '', scan_method TEXT DEFAULT 'nmap', detail TEXT DEFAULT '')""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_scan_ip_time ON port_scan_observations(ip,timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_port_scan_device_time ON port_scan_observations(device_id,timestamp DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS intelligence_cursors(
            cursor_name TEXT PRIMARY KEY, last_id INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS ipv6_observation_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, ipv6 TEXT NOT NULL,
            mac TEXT DEFAULT '', interface_index INTEGER DEFAULT 0, interface_alias TEXT DEFAULT '',
            state TEXT DEFAULT '', source TEXT DEFAULT '', linked_device_id TEXT DEFAULT '')""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ipv6_event_time ON ipv6_observation_events(timestamp DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS engine_health_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, engine TEXT NOT NULL,
            state TEXT NOT NULL, reason TEXT DEFAULT '', detail TEXT DEFAULT '')""")

        for idx in [
            "CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_dns_client ON dns_events(client_ip)",
            "CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_events(domain)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_time ON dns_alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_behavior_time ON behavior_alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_behavior_dev ON device_behavior_samples(device_id,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_health_time ON network_health_samples(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_obs_ip ON device_observations(ip)",
            "CREATE INDEX IF NOT EXISTS idx_iph_ip ON device_ip_history(ip)",
            "CREATE INDEX IF NOT EXISTS idx_ne_time ON network_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_ne_dev ON network_events(device_id,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_dhcp_time ON dhcp_events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_dhcp_mac ON dhcp_events(client_mac)",
            "CREATE INDEX IF NOT EXISTS idx_arpobs_time ON arp_observations(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_arpobs_ip ON arp_observations(sender_ip)",
            "CREATE INDEX IF NOT EXISTS idx_ev_inv ON evidence(investigation_id)",
            "CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_nc_time ON network_changes(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_cf_status ON config_findings(status,severity)",
            "CREATE INDEX IF NOT EXISTS idx_nah_fp ON network_approval_history(fingerprint,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_dnp_dev ON device_network_presence(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_die_ip ON device_identity_evidence(ip,last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_die_attr ON device_identity_evidence(attribute,observed_value)",
            "CREATE INDEX IF NOT EXISTS idx_dir_src ON device_relationships(source_ip,last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_ia_ip ON identity_assessments(ip,last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_ico_ip ON identity_continuity_observations(ip,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_ico_id ON identity_continuity_observations(continuity_id,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_ice_time ON identity_continuity_events(timestamp)",
            # 8.2.0 indexes
            "CREATE INDEX IF NOT EXISTS idx_nco_time ON network_context_observations(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_ic_status ON identity_candidates(status,created_at)",
            "CREATE INDEX IF NOT EXISTS idx_dpe_dev ON device_presence_events(device_id,timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_ed_engine ON engine_diagnostics(engine,timestamp)",
        ]:
            conn.execute(idx)

        def add_cols(table, cols):
            existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            for c, d in cols.items():
                if c not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {c} {d}")

        add_cols("devices", {
            "offline_misses": "INTEGER DEFAULT 0",
            "device_name": "TEXT DEFAULT 'Unidentified device'",
            "friendly_name": "TEXT DEFAULT ''",
            "device_type": "TEXT DEFAULT 'Unclassified device'",
            "os_guess": "TEXT DEFAULT 'Unknown'",
            "model": "TEXT DEFAULT ''",
            "identification_confidence": "INTEGER DEFAULT 0",
            "identification_methods": "TEXT DEFAULT ''",
            "open_ports": "TEXT DEFAULT ''",
            "service_summary": "TEXT DEFAULT ''",
            "last_identified": "TEXT DEFAULT ''",
            "device_id": "TEXT DEFAULT ''",
            "identity_basis": "TEXT DEFAULT ''",
            "manual_name": "TEXT DEFAULT ''",
            "trust_state": "TEXT DEFAULT 'UNREVIEWED'",
            "notes": "TEXT DEFAULT ''",
            "risk_score": "INTEGER DEFAULT 0",
            "risk_band": "TEXT DEFAULT 'UNKNOWN'",
            "oui_manufacturer": "TEXT DEFAULT ''",
            "reported_manufacturer": "TEXT DEFAULT ''",
            "identity_conflicts": "TEXT DEFAULT '[]'",
            "identity_category_confidence": "INTEGER DEFAULT 0",
            "identity_last_assessed": "TEXT DEFAULT ''",
            "recognition_json": "TEXT DEFAULT '{}'",
        })
        add_cols("dhcp_events", {
            "parameter_request_list": "TEXT DEFAULT ''",
            "client_identifier": "TEXT DEFAULT ''",
            "fingerprint": "TEXT DEFAULT ''",
        })
        add_cols("network_profiles", {
            "fingerprint": "TEXT DEFAULT ''",
            "gateway_mac": "TEXT DEFAULT ''",
            "adapter_mac": "TEXT DEFAULT ''",
            "dns_servers": "TEXT DEFAULT ''",
            "bssid": "TEXT DEFAULT ''",
            "last_authorized": "TEXT DEFAULT ''",
            "confidence": "INTEGER DEFAULT 0",
        })
        add_cols("device_risk_scores", {
            "threat_risk": "INTEGER DEFAULT 0",
            "identification_uncertainty": "INTEGER DEFAULT 0",
            "operational_health": "INTEGER DEFAULT 0",
            "explanation_json": "TEXT DEFAULT '{}'",
        })
        add_cols("threat_indicators", {
            "confidence": "INTEGER DEFAULT 50",
            "expires_at": "TEXT DEFAULT ''",
        })
        add_cols("alerts", {
            "first_seen": "TEXT DEFAULT ''",
            "last_seen": "TEXT DEFAULT ''",
            "occurrence_count": "INTEGER DEFAULT 1",
        })
        add_cols("dns_alerts", {
            "first_seen": "TEXT DEFAULT ''",
            "last_seen": "TEXT DEFAULT ''",
            "occurrence_count": "INTEGER DEFAULT 1",
        })
        conn.execute("UPDATE dns_alerts SET first_seen=timestamp WHERE first_seen IS NULL OR first_seen=''")
        conn.execute("UPDATE dns_alerts SET last_seen=timestamp WHERE last_seen IS NULL OR last_seen=''")

        add_cols("arp_bindings", {
            "candidate_mac": "TEXT DEFAULT ''",
            "candidate_count": "INTEGER DEFAULT 0",
            "candidate_first_seen": "TEXT DEFAULT ''",
            "candidate_last_seen": "TEXT DEFAULT ''",
        })
        # 8.2.0 additive columns
        add_cols("device_relationships", {
            "evidence_class": "TEXT DEFAULT 'INFERRED'",
            "independence_group": "TEXT DEFAULT ''",
        })
        add_cols("network_approval_history", {
            "reason": "TEXT DEFAULT ''",
        })

        conn.execute("UPDATE alerts SET first_seen=timestamp WHERE first_seen='' OR first_seen IS NULL")
        conn.execute("UPDATE alerts SET last_seen=timestamp WHERE last_seen='' OR last_seen IS NULL")
        conn.execute(
            "UPDATE network_profiles SET approved=0 WHERE network=?",
            ("192.168.100.0/24",))

    DB_MANAGER.write(_init)

# ============================================================
# NETWORK CONTEXT INTELLIGENCE 2.0 (D1-D4, D9, D11)
# ============================================================

class Conf(str):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    MISSING = "MISSING"
    STALE = "STALE"

FP_WEIGHTS = {"subnet": 0.30, "gateway": 0.20, "gateway_mac": 0.25,
              "dns": 0.10, "dhcp": 0.05, "ssid": 0.05, "bssid": 0.05}

def _ps(cmd, timeout=15):
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace")
    except Exception:
        return []
    if p.returncode != 0 or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]

def _norm_mac(m):
    if not m:
        return ""
    clean = re.sub(r"[^0-9A-Fa-f]", "", m).upper()
    return ":".join(clean[i:i+2] for i in range(0, 12, 2)) if len(clean) == 12 else ""

def _is_real_mac(m):
    if not m:
        return False
    clean = re.sub(r"[^0-9A-Fa-f]", "", m)
    return len(clean) == 12 and clean.upper() not in {"000000000000", "FFFFFFFFFFFF"}

def _gateway_mac_via_neighbor(gw_ip):
    if not gw_ip:
        return None
    rows = _ps(f"Get-NetNeighbor -AddressFamily IPv4 -IPAddress '{gw_ip}' | "
               f"Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Depth 3")
    for r in rows:
        ll = _norm_mac(r.get("LinkLayerAddress"))
        st = str(r.get("State") or "")
        if _is_real_mac(ll) and st in ("Reachable", "Stale", "Permanent"):
            return ll
    return None

def _wifi_details():
    try:
        p = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                           capture_output=True, text=True, timeout=8,
                           encoding="utf-8", errors="replace")
    except Exception:
        return "", ""
    if p.returncode != 0:
        return "", ""
    ssid = bssid = ""
    for line in p.stdout.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower(); v = v.strip()
        if k == "ssid" and not ssid:
            ssid = v
        elif k == "bssid" and not bssid:
            bssid = v
    return ssid, bssid

def _select_primary_adapter(adapters, default_routes):
    """Choose the active interface with the lowest effective default-route metric."""
    routed = [item for item in adapters if item.get("idx") in default_routes]
    if routed:
        return min(
            routed,
            key=lambda item: int(default_routes[item["idx"]].get("_metric", 999999)),
        )
    return adapters[0] if adapters else None


def _select_ipv4_interface_rows(rows):
    """Choose one usable, preferred IPv4 address per Windows interface."""
    selected = {}
    priorities = {}
    for row in rows:
        try:
            idx = int(row["InterfaceIndex"])
            address = ipaddress.ip_address(str(row.get("IPAddress") or "").strip())
            if (address.version != 4 or address.is_loopback or address.is_link_local
                    or address.is_unspecified or address.is_multicast):
                continue
            state = str(row.get("AddressState") or "").casefold()
            skip_source = str(row.get("SkipAsSource", "False")).casefold() in {
                "true", "1", "yes"
            }
            priority = (1 if state == "preferred" else 0, 0 if skip_source else 1)
        except (KeyError, ValueError, TypeError):
            continue
        if idx not in priorities or priority > priorities[idx]:
            selected[idx] = row
            priorities[idx] = priority
    return selected


def detect_network():
    """Return network context as a legacy dict (8.1.0 compatible shape).

    Uses 4 independent Windows APIs. Handles VPN, multiple adapters,
    missing gateway, missing MAC. Never invents a gateway.
    """
    if NETWORK_OVERRIDE:
        try:
            net = ipaddress.ip_network(NETWORK_OVERRIDE, strict=False)
            if net.num_addresses > 4096:
                raise RuntimeError(f"Manual network {net} too large.")
            return {"network": str(net), "ip": "", "gateway": "",
                    "interface": "Manual override", "interface_description": "",
                    "interface_guid": "", "prefix": net.prefixlen,
                    "ssid": "", "bssid": "", "mode": "MANUAL",
                    "dns_servers": "", "adapter_mac": "",
                    "gateway_mac": "", "fingerprint": "", "fingerprint_raw": "",
                    "confidence": 0, "confidence_notes": "manual override",
                    "_classification": {"gateway": Conf.MISSING,
                                        "gateway_mac": Conf.MISSING,
                                        "dns": Conf.MISSING,
                                        "dhcp": Conf.MISSING,
                                        "fingerprint": Conf.MISSING}}
        except ValueError:
            raise RuntimeError("NETWORKRADAR_NETWORK invalid CIDR")

    adapters_raw = _ps(
        "Get-NetAdapter | Select-Object Name,InterfaceIndex,InterfaceDescription,InterfaceGuid,"
        "MacAddress,Status,MediaType | ConvertTo-Json -Depth 3")
    ip_raw = _ps(
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressState,SkipAsSource | ConvertTo-Json -Depth 3")
    route_raw = _ps(
        "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | "
        "Select-Object InterfaceIndex,NextHop,RouteMetric,InterfaceMetric | "
        "ConvertTo-Json -Depth 3")
    dns_raw = _ps(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,ServerAddresses | ConvertTo-Json -Depth 3")
    dhcp_raw = _ps(
        "Get-NetIPInterface -AddressFamily IPv4 | "
        "Select-Object InterfaceIndex,Dhcp | ConvertTo-Json -Depth 3")

    ips_by_idx = _select_ipv4_interface_rows(ip_raw)
    dns_by_idx, dhcp_by_idx = {}, {}
    for r in dns_raw:
        try: dns_by_idx[int(r["InterfaceIndex"])] = list(r.get("ServerAddresses") or [])
        except (KeyError, ValueError, TypeError): pass
    for r in dhcp_raw:
        try: dhcp_by_idx[int(r["InterfaceIndex"])] = str(r.get("Dhcp", ""))
        except (KeyError, ValueError, TypeError): pass
    default_routes = {}
    for r in route_raw:
        try:
            idx = int(r["InterfaceIndex"])
            metric = int(r.get("RouteMetric", 9999)) + int(r.get("InterfaceMetric", 0))
        except (KeyError, ValueError, TypeError):
            continue
        if idx not in default_routes or metric < default_routes[idx]["_metric"]:
            default_routes[idx] = {**r, "_metric": metric}

    adapters = []
    for a in adapters_raw:
        try:
            idx = int(a["InterfaceIndex"])
            name = a.get("Name") or f"if{idx}"
        except (KeyError, ValueError, TypeError):
            continue
        status = str(a.get("Status") or "Unknown")
        mac_val = _norm_mac(a.get("MacAddress"))
        ip_r = ips_by_idx.get(idx) or {}
        ip_val = ip_r.get("IPAddress")
        pfx = ip_r.get("PrefixLength")
        adapters.append({"idx": idx, "name": name,
                         "description": str(a.get("InterfaceDescription") or ""),
                         "guid": str(a.get("InterfaceGuid") or ""),
                         "status": status,
                         "mac": mac_val if _is_real_mac(mac_val) else "",
                         "ip": ip_val, "prefix": pfx})

    up = [x for x in adapters if x["status"] == "Up" and x["ip"]]
    primary = _select_primary_adapter(up, default_routes)

    if primary is None:
        return {"network": "", "ip": "", "gateway": "",
                "interface": "No active adapter", "interface_description": "",
                "interface_guid": "", "prefix": None,
                "ssid": "", "bssid": "", "mode": "AUTO",
                "dns_servers": "", "adapter_mac": "", "gateway_mac": "",
                "fingerprint": "", "fingerprint_raw": "",
                "confidence": 0, "confidence_notes": "no active adapter with IPv4",
                "_classification": {"gateway": Conf.MISSING,
                                    "gateway_mac": Conf.MISSING,
                                    "dns": Conf.MISSING,
                                    "dhcp": Conf.MISSING,
                                    "fingerprint": Conf.MISSING}}

    # Gateway — NEVER invented
    gateway_val = ""
    gw_mac = ""
    gw_class = Conf.MISSING
    if primary["idx"] in default_routes:
        nh = default_routes[primary["idx"]].get("NextHop")
        if nh and nh not in ("0.0.0.0", ""):
            gateway_val = nh
            gw_class = Conf.CONFIRMED
            gw_mac = _gateway_mac_via_neighbor(nh) or ""
    gw_mac_class = Conf.CONFIRMED if gw_mac else Conf.MISSING

    dns_servers = sorted(set(dns_by_idx.get(primary["idx"], [])))
    dns_class = Conf.CONFIRMED if dns_servers else Conf.MISSING

    dhcp_flag = dhcp_by_idx.get(primary["idx"])
    dhcp_class = (Conf.CONFIRMED if dhcp_flag in ("Enabled", "Disabled")
                  else Conf.MISSING)

    ssid, bssid = _wifi_details()

    try:
        subnet_str = str(ipaddress.ip_network(
            f"{primary['ip']}/{int(primary['prefix'])}", strict=False))
    except (ValueError, TypeError):
        subnet_str = ""

    components = {
        "subnet": subnet_str or None,
        "gateway": gateway_val or None,
        "gateway_mac": gw_mac or None,
        "dns": dns_servers or None,
        "dhcp": dhcp_flag if dhcp_flag in ("Enabled", "Disabled") else None,
        "ssid": ssid or None,
        "bssid": bssid or None,
    }
    weight = sum(FP_WEIGHTS[k] for k, v in components.items() if v is not None)
    has_strong = components["gateway_mac"] is not None or components["bssid"] is not None

    if weight == 0:
        fingerprint = ""
        fp_class = Conf.MISSING
    else:
        fingerprint = hashlib.sha256(
            json.dumps(components, sort_keys=True).encode()).hexdigest()[:24]
        fp_class = (Conf.CONFIRMED if weight >= 0.75 and has_strong
                    else Conf.INFERRED if weight >= 0.40
                    else Conf.MISSING)

    return {
        "network": subnet_str,
        "ip": primary["ip"] or "",
        "gateway": gateway_val,
        "interface": primary["name"],
        "interface_description": primary.get("description", ""),
        "interface_guid": primary.get("guid", ""),
        "prefix": int(primary["prefix"]) if isinstance(primary["prefix"], int) else None,
        "ssid": ssid,
        "bssid": bssid,
        "mode": "AUTO",
        "dns_servers": ",".join(dns_servers),
        "adapter_mac": primary["mac"],
        "gateway_mac": gw_mac,
        "fingerprint": fingerprint,
        "fingerprint_raw": json.dumps(components, sort_keys=True),
        "confidence": int(round(weight * 100)),
        "confidence_notes": (
            "Strong anchor present." if has_strong
            else "No gateway MAC or BSSID observed; confidence capped."),
        "_classification": {
            "gateway": gw_class,
            "gateway_mac": gw_mac_class,
            "dns": dns_class,
            "dhcp": dhcp_class,
            "fingerprint": fp_class,
        },
    }

def _profile_authorization_fresh(profile, now=None):
    """Approval expires from last_authorized, never from routine last_seen updates."""
    raw = str(profile.get("last_authorized") or "").strip()
    if not raw:
        return False, "No successful approval timestamp is recorded. Re-approve this network."
    try:
        approved_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if approved_at.tzinfo is not None:
            approved_at = approved_at.astimezone().replace(tzinfo=None)
    except (TypeError, ValueError):
        return False, "The network approval timestamp is invalid. Re-approve this network."

    current = now or datetime.now()
    if current.tzinfo is not None:
        current = current.astimezone().replace(tzinfo=None)
    age = current - approved_at
    if age < timedelta(minutes=-5):
        return False, "The network approval timestamp is in the future. Re-approve this network."
    if age > timedelta(days=PROFILE_MAX_AGE_DAYS):
        return False, (
            f"Network approval expired ({age.days} days > {PROFILE_MAX_AGE_DAYS}). "
            "Re-approve required."
        )
    return True, "Approval is within the configured freshness period."


def _authz_decision(detected, profiles):
    """Single authoritative decision. Closes D1."""
    fp = detected.get("fingerprint") or ""
    weight = float(detected.get("confidence", 0)) / 100.0
    fp_class = detected.get("_classification", {}).get("fingerprint", Conf.MISSING)

    if not fp or fp_class == Conf.MISSING:
        return False, "INDETERMINATE", [
            "Network fingerprint could not be computed from confirmed evidence.",
            f"Classification: {fp_class}."], None
    if weight < MIN_FP_CONFIDENCE:
        return False, "INDETERMINATE", [
            f"Fingerprint confidence {weight:.0%} < {MIN_FP_CONFIDENCE:.0%}.",
            "Active discovery disabled until confidence improves."], None

    matches = [p for p in profiles if p.get("fingerprint") == fp]
    if not matches:
        return False, "NOT_AUTHORISED", [
            "No network profile matches the current fingerprint."], None

    approved_matches = [p for p in matches if p.get("approved")]
    if not approved_matches:
        pid = matches[0].get("id") or matches[0].get("network") or "?"
        return False, "NOT_AUTHORISED", [
            f"Profile {pid} exists but approved != True."], pid

    fresh_matches = []
    stale_reason = ""
    for profile in approved_matches:
        fresh, reason = _profile_authorization_fresh(profile)
        if fresh:
            fresh_matches.append(profile)
        elif not stale_reason:
            stale_reason = reason
    if not fresh_matches:
        pid = approved_matches[0].get("id") or approved_matches[0].get("network") or "?"
        return False, "INDETERMINATE", [stale_reason or
            "Network approval is stale or invalid. Re-approve required."], pid

    match = fresh_matches[0]
    pid = match.get("id") or match.get("network") or "?"
    return True, "AUTHORISED", [
        f"Profile {pid} approved recently; weight {weight:.0%}; class {fp_class}."], pid

def refresh_network_context():
    detected = detect_network()

    def _persist(conn):
        # D9: record every observation
        conn.execute("""INSERT INTO network_context_observations(
            timestamp, fingerprint, fingerprint_class, fingerprint_weight,
            subnet, gateway, gateway_class, gateway_mac, gateway_mac_class,
            dns, dns_class, dhcp, dhcp_class, ssid, bssid, source_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (now_text(), detected.get("fingerprint", ""),
             detected.get("_classification", {}).get("fingerprint", Conf.MISSING),
             float(detected.get("confidence", 0)) / 100.0,
             detected.get("network", ""), detected.get("gateway", ""),
             detected.get("_classification", {}).get("gateway", Conf.MISSING),
             detected.get("gateway_mac", ""),
             detected.get("_classification", {}).get("gateway_mac", Conf.MISSING),
             detected.get("dns_servers", ""),
             detected.get("_classification", {}).get("dns", Conf.MISSING),
             "", detected.get("_classification", {}).get("dhcp", Conf.MISSING),
             detected.get("ssid", ""), detected.get("bssid", ""),
             detected.get("fingerprint_raw", "")))
        # Upsert profile — never overwrites approval
        conn.execute("""
            INSERT INTO network_profiles(network, first_seen, last_seen,
                interface, gateway, ssid, approved, fingerprint, gateway_mac,
                adapter_mac, dns_servers, bssid, confidence)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(network) DO UPDATE SET
                last_seen=excluded.last_seen,
                interface=excluded.interface,
                gateway=excluded.gateway,
                ssid=excluded.ssid,
                fingerprint=excluded.fingerprint,
                gateway_mac=excluded.gateway_mac,
                adapter_mac=excluded.adapter_mac,
                dns_servers=excluded.dns_servers,
                bssid=excluded.bssid,
                confidence=excluded.confidence
        """, (detected.get("network", ""), now_text(), now_text(),
              detected.get("interface", ""), detected.get("gateway", ""),
              detected.get("ssid", ""), detected.get("fingerprint", ""),
              detected.get("gateway_mac", ""), detected.get("adapter_mac", ""),
              detected.get("dns_servers", ""), detected.get("bssid", ""),
              int(detected.get("confidence", 0))))
        rows = conn.execute(
            "SELECT network, approved, last_seen, last_authorized, fingerprint "
            "FROM network_profiles WHERE fingerprint=?",
            (detected.get("fingerprint", ""),)).fetchall()
        return [{"id": r[0], "approved": bool(r[1]),
                 "last_seen": r[2], "last_authorized": r[3],
                 "fingerprint": r[4]} for r in rows]

    profiles = DB_MANAGER.write(_persist) if detected.get("fingerprint") else []
    authorised, decision, reasons, pid = _authz_decision(detected, profiles)

    with NET_LOCK:
        changed = bool(NET_CTX.get("network")
                       and detected.get("network")
                       and detected["network"] != NET_CTX["network"])
        NET_CTX.update(detected)
        NET_CTX["changed"] = changed
        NET_CTX["last_checked"] = now_text()
        NET_CTX["authorized"] = authorised
        NET_CTX["auth_decision"] = decision
        NET_CTX["auth_reasons"] = reasons
        NET_CTX["authorized_at"] = now_text() if authorised else NET_CTX.get("authorized_at", "")
        NET_CTX["warning"] = ("" if authorised else
            f"Network fingerprint {detected.get('fingerprint', '')[:12]} — "
            f"{decision}. " + " ".join(reasons) + " Passive monitoring only.")

    return changed, authorised

def current_network():
    with NET_LOCK:
        return NET_CTX.get("network", "")

def current_fingerprint():
    with NET_LOCK:
        return NET_CTX.get("fingerprint", "")

def is_authorized():
    with NET_LOCK:
        return bool(NET_CTX.get("authorized"))

def authorize_current(actor="local-user"):
    with NET_LOCK:
        fp = NET_CTX.get("fingerprint", "")
        network = NET_CTX.get("network", "")
        conf = int(NET_CTX.get("confidence", 0) or 0)
    if not fp:
        raise RuntimeError("No fingerprint — cannot authorise")
    if conf < int(MIN_FP_CONFIDENCE * 100):
        raise RuntimeError(
            f"Refusing to authorise: fingerprint confidence {conf}% is below "
            f"the minimum {int(MIN_FP_CONFIDENCE*100)}%. "
            "Improve evidence (connect through the gateway, run a fresh scan, "
            "confirm DNS) before approving.")
    def _w(conn):
        cur = conn.execute("UPDATE network_profiles SET approved=1, last_seen=?, "
                           "last_authorized=? WHERE fingerprint=?",
                           (now_text(), now_text(), fp))
        if cur.rowcount < 1:
            raise RuntimeError("The current network profile no longer exists. Refresh network detection and try again.")
        conn.execute(
            "INSERT INTO network_approval_history(timestamp, fingerprint, "
            "network, action, actor, reason) VALUES (?, ?, ?, 'APPROVED', ?, ?)",
            (now_text(), fp, network, actor, f"fp_confidence={conf}%"))
    DB_MANAGER.write(_w)
    with NET_LOCK:
        NET_CTX["authorized"] = True
        NET_CTX["auth_decision"] = "AUTHORISED"
        NET_CTX["auth_reasons"] = [f"Manually authorised by {actor} at {conf}%."]
        NET_CTX["authorized_at"] = now_text()
        NET_CTX["warning"] = ""

# [Continues below — health, ARP, SSDP, discovery, identification, capture engines, web, main]
# ============================================================
# HEALTH SAMPLES
# ============================================================

def health_sample():
    with NET_LOCK:
        ctx = dict(NET_CTX)
    notes = []
    gw_ms = None
    dns_ms = None
    internet = "UNKNOWN"
    gw = ctx.get("gateway") or ""
    if gw:
        try:
            start = time.perf_counter()
            flag = "-n" if os.name == "nt" else "-c"
            cmd = ["ping", flag, "1", gw]
            if os.name == "nt":
                cmd.insert(1, "-w")
                cmd.insert(2, "1200")
            else:
                cmd.extend(["-W", "2"])
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            gw_ms = (round((time.perf_counter() - start) * 1000, 1)
                     if r.returncode == 0 else None)
            if gw_ms is None:
                notes.append("Gateway did not respond to ICMP.")
        except Exception as e:
            notes.append(f"Gateway probe: {str(e)[:80]}")
    try:
        start = time.perf_counter()
        socket.getaddrinfo("example.com", 443)
        dns_ms = round((time.perf_counter() - start) * 1000, 1)
        internet = "AVAILABLE"
    except OSError:
        internet = "DNS_UNAVAILABLE"
        notes.append("DNS resolution failed.")
    status = ("HEALTHY" if gw_ms is not None and internet == "AVAILABLE"
              else "PARTIAL" if internet == "AVAILABLE" else "DEGRADED")
    sample = {"status": status, "gateway": gw, "gateway_latency_ms": gw_ms,
              "dns_resolution_ms": dns_ms, "internet": internet,
              "adapter": ctx.get("interface", ""), "sampled_at": now_text(),
              "notes": notes}
    with HEALTH_LOCK:
        HEALTH.update(sample)
    def _w(conn):
        conn.execute("INSERT INTO network_health_samples(timestamp, network, "
                     "gateway, gateway_latency_ms, dns_resolution_ms, "
                     "internet_status, adapter, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (sample["sampled_at"], ctx.get("network"), gw, gw_ms,
                      dns_ms, internet, sample["adapter"], "; ".join(notes)))
    try:
        DB_MANAGER.write(_w)
    except Exception:
        pass
    return sample

# ============================================================
# ARP CACHE, LOCAL IDENTITY, SSDP
# ============================================================

def read_arp_cache():
    mapping = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=8)
        for line in r.stdout.splitlines():
            m = re.search(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})",
                line)
            if m:
                mapping[m.group(1)] = m.group(2).replace("-", ":").upper()
    except Exception:
        pass
    return mapping

def local_identity():
    ident = {"ip": "", "mac": "",
             "hostname": os.environ.get("COMPUTERNAME", socket.gethostname()),
             "adapter": ""}
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with NET_LOCK:
            gw = NET_CTX.get("gateway") or "1.1.1.1"
        probe.connect((gw, 9))
        ident["ip"] = probe.getsockname()[0]
        probe.close()
    except Exception:
        pass
    if not ident["ip"]:
        return ident
    if os.name == "nt":
        ps = (f"$ip='{ident['ip']}'; Get-NetIPConfiguration | "
              "Where-Object { $_.IPv4Address.IPAddress -contains $ip } | "
              "ForEach-Object { $a=Get-NetAdapter -InterfaceIndex $_.InterfaceIndex; "
              "[pscustomobject]@{Mac=$a.MacAddress;Adapter=$a.Name} } | "
              "ConvertTo-Json -Compress")
        try:
            r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=8)
            if r.returncode == 0 and r.stdout.strip():
                info = json.loads(r.stdout)
                if isinstance(info, list):
                    info = info[0] if info else {}
                ident["mac"] = _clean(info.get("Mac", "")).replace("-", ":").upper()
                ident["adapter"] = _clean(info.get("Adapter", ""))
        except Exception:
            pass
    return ident

def reverse_dns(ip):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        name = _clean(name.rstrip("."))
        if name and name != ip:
            return name
    except (OSError, socket.timeout):
        pass
    return ""

def netbios_name(ip):
    try:
        r = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=5)
        for line in (r.stdout or "").splitlines():
            m = re.match(r"^\s*([^\s]+)\s+<([0-9A-Fa-f]{2})>\s+(UNIQUE|GROUP)", line)
            if m and m.group(2).upper() == "00" and m.group(3).upper() == "UNIQUE":
                c = _clean(m.group(1))
                if c and c.upper() not in ("WORKGROUP", "IS~"):
                    return c
    except Exception:
        pass
    return ""

def _same_private_host(src_ip, url):
    try:
        p = urllib.parse.urlparse(url)
        t = p.hostname
        if not t:
            return False
        tip = ipaddress.ip_address(t)
        sip = ipaddress.ip_address(src_ip)
        return tip == sip and tip.is_private and p.scheme.lower() == "http"
    except ValueError:
        return False

def ssdp_scan(timeout=2.0):
    found = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(0.25)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pkt, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            ip = addr[0]
            h = {}
            for line in pkt.decode("utf-8", errors="replace").splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    h[k.strip().lower()] = v.strip()
            loc = h.get("location", "")
            if not loc or not _same_private_host(ip, loc):
                continue
            meta = {"ssdp_server": _clean(h.get("server", "")),
                    "usn": _clean(h.get("usn", ""))}
            try:
                req = urllib.request.Request(
                    loc, headers={"User-Agent": f"NR/{APP_VERSION}"})
                with urllib.request.urlopen(req, timeout=2) as r:
                    xml = r.read(256 * 1024)
                root = ET.fromstring(xml)
                for el in root.iter():
                    tag = el.tag.split("}")[-1].lower()
                    val = _clean(el.text or "")
                    if tag in ("friendlyname", "manufacturer", "modelname",
                               "modelnumber", "devicetype", "serialnumber"):
                        meta[tag] = val
            except Exception:
                pass
            found[ip] = meta
    finally:
        s.close()
    return found

# ============================================================
# DISCOVERY + IDENTIFICATION (mostly preserved from 8.1.0)
# ============================================================

def discover_devices():
    net = current_network()
    if not net:
        return [], 0.0
    cmd = [str(NMAP), "-sn", "-R", "-oX", "-", net]
    started = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=150)
    dur = round(time.time() - started, 2)
    NMAP_LOG.write_text((r.stderr or "") + "\n" + (r.stdout or "")[:2000],
                        encoding="utf-8")
    if r.returncode != 0:
        raise RuntimeError(f"Nmap failed: {(r.stderr or '')[-1000:]}")
    root = ET.fromstring(r.stdout)
    devices = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip, mac, vendor, hostname = "", "Unavailable", "Unknown", "-"
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "Unavailable")
                vendor = addr.get("vendor") or "Unknown"
        names = host.find("hostnames")
        if names is not None:
            cands = [n.get("name") for n in names.findall("hostname") if n.get("name")]
            if cands:
                hostname = cands[0]
        if ip:
            devices.append({
                "ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
                "device_name": hostname if hostname != "-" else "",
                "friendly_name": "", "device_type": "Unclassified device",
                "os_guess": "Unknown", "model": "",
                "identification_confidence": 0, "identification_methods": "",
                "open_ports": "", "service_summary": ""})
    return devices, dur

def derive_identity(device):
    mac = (device.get("mac") or "").replace("-", ":").upper()
    if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", mac):
        first = int(mac.split(":")[0], 16)
        if first & 0x02:
            # Randomised/locally administered MACs are observations, not durable
            # identity anchors. Keep identity scoped to the current IP instead.
            basis = "IP fallback (locally administered MAC ignored)"
            key = f"ip:{device['ip']}"
        else:
            basis = "MAC"
            key = f"mac:{mac}"
    else:
        basis = "IP fallback"
        key = f"ip:{device['ip']}"
    return uuid.uuid5(uuid.NAMESPACE_URL, "nr:" + key).hex[:24], key, basis

def persist_identity(conn, device, ts):
    derived_id, key, basis = derive_identity(device)
    identity_row = conn.execute(
        "SELECT device_id, identity_basis FROM device_identities WHERE identity_key=?",
        (key,)).fetchone()
    if identity_row:
        did = identity_row[0]
        existing_basis = identity_row[1] or ""
        if existing_basis and not existing_basis.startswith("IP fallback"):
            basis = existing_basis
    else:
        did = derived_id
    old = conn.execute(
        "SELECT device_id, identity_basis FROM devices WHERE ip=?",
        (device["ip"],)).fetchone()
    old_id, old_basis = (old[0], old[1]) if old else ("", "")
    if old_id and old_id != did and str(old_basis or "").startswith("IP fallback"):
        hist = conn.execute(
            "SELECT ip, mac, first_seen, last_seen FROM device_ip_history WHERE device_id=?",
            (old_id,)).fetchall()
        for oip, omac, fs, ls in hist:
            conn.execute(
                """INSERT INTO device_ip_history(device_id, ip, mac, first_seen, last_seen)
                   VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(device_id, ip) DO UPDATE SET
                     mac=CASE WHEN excluded.mac='' THEN device_ip_history.mac
                              ELSE excluded.mac END,
                     first_seen=MIN(device_ip_history.first_seen, excluded.first_seen),
                     last_seen=MAX(device_ip_history.last_seen, excluded.last_seen)""",
                (did, oip, omac, fs, ls))
        conn.execute("DELETE FROM device_ip_history WHERE device_id=?", (old_id,))
        conn.execute("UPDATE devices SET device_id=? WHERE device_id=?", (did, old_id))
        conn.execute(
            "DELETE FROM device_identities WHERE device_id=? AND identity_key<>?",
            (old_id, key))
    conn.execute(
        """INSERT INTO device_identities(device_id, identity_key, identity_basis,
                                          first_seen, last_seen)
           VALUES(?, ?, ?, ?, ?)
           ON CONFLICT(device_id) DO UPDATE SET
             identity_key=excluded.identity_key,
             identity_basis=excluded.identity_basis,
             last_seen=excluded.last_seen""",
        (did, key, basis, ts, ts))
    conn.execute(
        """INSERT INTO device_ip_history(device_id, ip, mac, first_seen, last_seen)
           VALUES(?, ?, ?, ?, ?)
           ON CONFLICT(device_id, ip) DO UPDATE SET
             mac=CASE WHEN excluded.mac='' THEN device_ip_history.mac
                      ELSE excluded.mac END,
             last_seen=excluded.last_seen""",
        (did, device["ip"], device.get("mac", ""), ts, ts))
    fp = current_fingerprint()
    if fp:
        conn.execute(
            """INSERT INTO device_network_presence(device_id, fingerprint, first_seen, last_seen)
               VALUES(?, ?, ?, ?)
               ON CONFLICT(device_id, fingerprint) DO UPDATE SET
                 last_seen=excluded.last_seen""",
            (did, fp, ts, ts))
    conn.execute(
        "UPDATE devices SET device_id=?, identity_basis=? WHERE ip=?",
        (did, basis, device["ip"]))
    device["device_id"] = did
    device["identity_basis"] = basis

def infer_type(device, ssdp=None):
    ssdp = ssdp or {}
    text = " ".join(str(x or "") for x in (
        device.get("device_name", ""), device.get("hostname", ""),
        device.get("friendly_name", ""), device.get("model", ""),
        device.get("service_summary", ""), device.get("os_guess", ""),
        ssdp.get("devicetype", ""), ssdp.get("friendlyname", ""),
        ssdp.get("manufacturer", ""), ssdp.get("modelname", ""),
        " ".join(device.get("services_found", []) or []),
        " ".join(x.get("banner", "") for x in device.get("service_intel", []) or [])
    )).lower()
    ports = set(device.get("port_numbers", []) or [])
    with NET_LOCK:
        gateway_ip = NET_CTX.get("gateway", "")
    if device.get("_is_gateway") or (gateway_ip and device.get("ip") == gateway_ip):
        return "Router / network gateway (role-confirmed)"
    patterns = [
        (r"\b(printer|laserjet|deskjet|epson|brother|canon|xerox|ricoh|kyocera|ipp)\b", "Printer (probable)"),
        (r"\b(ipcam|camera|cctv|hikvision|dahua|axis communications|rtsp)\b", "IP camera / video (probable)"),
        (r"\b(iphone|ipad|ipod|ios device)\b", "Apple mobile (probable)"),
        (r"\b(macbook|imac|mac mini|mac studio)\b", "Apple computer (probable)"),
        (r"\b(android|galaxy|pixel|oneplus|xiaomi|redmi|oppo|vivo|huawei phone)\b", "Android/mobile device (probable)"),
        (r"\b(windows|win10|win11|desktop-|laptop|thinkpad|elitebook|latitude|optiplex|probook)\b", "Computer (probable)"),
        (r"\b(xbox|playstation|ps[345]|nintendo|switch console)\b", "Gaming console (probable)"),
        (r"\b(chromecast|google tv|fire tv|roku|smart.?tv|mediarenderer|airplay receiver|webos tv|tizen)\b", "Smart TV / streaming (probable)"),
        (r"\b(synology|qnap|truenas|freenas|nas[0-9-]|network attached storage)\b", "NAS / storage (probable)"),
        (r"\b(mikrotik|routeros|openwrt|opnsense|pfsense|unifi|ubiquiti|access.?point|wireless controller|switch[0-9-])\b", "Router / switch / access point (probable)"),
        (r"\b(asterisk|yealink|polycom|grandstream|voip|sip phone)\b", "VoIP / IP phone (probable)"),
        (r"\b(esxi|vmware|hyper-v|proxmox|xenserver|virtual machine)\b", "Virtualisation host (probable)"),
        (r"\b(server|windows server|ubuntu server|debian|rhel|centos|almalinux|rocky linux)\b", "Server (probable)"),
        (r"\b(sonos|bose|echo dot|echo show|homepod|smart speaker)\b", "Smart speaker / audio (probable)"),
        (r"\b(thermostat|smart plug|zigbee|zwave|tasmota|shelly|tuya|home assistant)\b", "Smart-home / IoT device (probable)"),
        (r"\b(ups|apc smart|eaton power|powerware)\b", "UPS / power equipment (probable)"),
        (r"\b(doorbell|intercom|access control|biometric|badge reader)\b", "Access control / intercom (probable)"),
        (r"\b(nvr|dvr|video recorder|surveillance recorder)\b", "Video surveillance recorder (probable)"),
        (r"\b(air.?condition|refrigerator|washing machine|dishwasher|oven|smart appliance)\b", "Smart appliance (probable)"),
    ]
    for pattern, category in patterns:
        if re.search(pattern, text, re.I):
            return category
    if ports & {9100, 631, 515}:
        return "Device exposing printing service (type unconfirmed)"
    if ports & {554, 8554, 10554}:
        return "Device exposing RTSP/video service (type unconfirmed)"
    if ports & {8008, 8009, 32400, 1900}:
        return "Device exposing media/UPnP service (type unconfirmed)"
    if ports & {161, 162}:
        return "Device exposing SNMP service (type unconfirmed)"
    if 3389 in ports or ({445, 139} <= ports):
        return "Device exposing Windows remote/file services (type unconfirmed)"
    if ports & {22, 80, 443, 445, 3389}:
        return "Network service host (type unconfirmed)"
    return "Unclassified network device"

# ============================================================
# RADAR IDENTITY (preserved from 8.1.0)
# ============================================================

OUI_DIR = DATA / "fingerprints"
OUI_DIR.mkdir(parents=True, exist_ok=True)
OUI_FILES = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.txt",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.txt",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.txt",
}
_OUI_LOCK = threading.RLock()
_OUI_MEM = {}

def dhcp_fingerprint(vendor_class, parameter_request_list):
    vc = re.sub(r"\s+", " ", (vendor_class or "").strip().lower())[:120]
    prl = ",".join(x.strip() for x in (parameter_request_list or "").split(",") if x.strip())
    return hashlib.sha256((vc + "|" + prl).encode("utf-8", "ignore")).hexdigest()[:24]

def _normalise_mac(mac):
    m = (mac or "").strip().replace("-", ":").upper()
    return m if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", m) else ""

def mac_properties(mac):
    m = _normalise_mac(mac)
    if not m:
        return {"valid": False, "multicast": False, "locally_administered": False,
                "unicast": False, "prefix": ""}
    first = int(m[:2], 16)
    return {"valid": True, "multicast": bool(first & 1),
            "locally_administered": bool(first & 2),
            "unicast": not bool(first & 1), "prefix": m[:8].replace(":", "")}

def load_oui_cache():
    global _OUI_MEM
    with _OUI_LOCK:
        if _OUI_MEM:
            return _OUI_MEM
        try:
            with DB_MANAGER.read() as conn:
                _OUI_MEM = {r[0]: r[1] for r in conn.execute(
                    "SELECT prefix, organization FROM oui_cache")}
        except Exception:
            _OUI_MEM = {}
        return _OUI_MEM

def oui_lookup(mac):
    props = mac_properties(mac)
    if not props["valid"] or props["multicast"] or props["locally_administered"]:
        return "", props
    cache = load_oui_cache()
    for n in (9, 7, 6):
        prefix = props["prefix"][:n]
        if prefix in cache:
            return cache[prefix], props
    return "", props

def update_oui_database(timeout=20):
    added = 0
    errors = []
    for registry, url in OUI_FILES.items():
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": f"NetworkRadar/{APP_VERSION}"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                raw = response.read(25 * 1024 * 1024).decode("utf-8", "replace")
            parsed = {}
            for line in raw.splitlines():
                m = re.search(r"^\s*([0-9A-Fa-f-]{6,11})\s+\((?:hex|MA-L|MA-M|MA-S)\)\s+(.+)$", line, re.I)
                if m:
                    prefix = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()
                    org = _clean(m.group(2), 180)
                    if len(prefix) in (6, 7, 9) and org:
                        parsed[prefix] = org
            if parsed:
                def _w(conn, items=list(parsed.items()), reg=registry):
                    conn.executemany("""INSERT INTO oui_cache(prefix,organization,registry,updated_at)
                        VALUES(?,?,?,?) ON CONFLICT(prefix) DO UPDATE SET
                        organization=excluded.organization,registry=excluded.registry,
                        updated_at=excluded.updated_at""",
                        [(k, v, reg, now_text()) for k, v in items])
                DB_MANAGER.write(_w)
                added += len(parsed)
                with _OUI_LOCK:
                    _OUI_MEM.clear()
        except Exception as exc:
            errors.append(f"{registry}: {_clean(exc, 160)}")
    return {"updated": added, "errors": errors, "timestamp": now_text()}

def _add_identity_evidence(conn, device, source, attribute, value, confidence,
                           evidence_class="OBSERVED", source_version=""):
    value = _clean(value, 500)
    if not value or value.lower() in {"unknown", "unavailable", "-", "none"}:
        return 0
    ts = now_text()
    cur = conn.execute("""INSERT INTO device_identity_evidence(
        device_id,ip,source,attribute,observed_value,confidence,evidence_class,
        first_seen,last_seen,source_version) VALUES(?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip,source,attribute,observed_value) DO UPDATE SET
        device_id=excluded.device_id,confidence=MAX(device_identity_evidence.confidence,excluded.confidence),
        last_seen=excluded.last_seen,evidence_class=excluded.evidence_class""",
        (device.get("device_id", ""), device["ip"], source, attribute, value,
         max(0, min(100, int(confidence))), evidence_class, ts, ts, source_version))
    return max(0, cur.rowcount)

def _recent_dhcp_evidence(conn, device):
    mac = _normalise_mac(device.get("mac", ""))
    ip = device.get("ip", "")
    if mac:
        rows = conn.execute("""SELECT hostname,vendor_class,parameter_request_list,
            client_identifier,client_mac FROM dhcp_events WHERE upper(client_mac)=?
            ORDER BY id DESC LIMIT 8""", (mac,)).fetchall()
    else:
        rows = conn.execute("""SELECT hostname,vendor_class,parameter_request_list,
            client_identifier,client_mac FROM dhcp_events WHERE client_ip=?
            ORDER BY id DESC LIMIT 8""", (ip,)).fetchall()
    return rows

def _classify_from_signatures(device, dhcp_rows):
    candidates = []
    with NET_LOCK:
        gateway_ip = NET_CTX.get("gateway", "")
    if device.get("_is_gateway") or (gateway_ip and device.get("ip") == gateway_ip):
        return [("Router / network equipment", 98, "Default-gateway role observed")]
    mdns = str(device.get("mdns_records", "") or "").lower()
    ssdp = device.get("ssdp_intel") or {}
    snmp = device.get("snmp_intel") or {}
    service_rows = device.get("service_intel", []) or []
    service_text = " ".join(str(x.get(k, "")) for x in service_rows for k in ("banner", "server", "http_title"))
    services = " ".join(device.get("services_found", []) or [])
    text = " ".join(str(x or "") for x in (
        device.get("hostname", ""), device.get("friendly_name", ""),
        device.get("device_name", ""), device.get("model", ""),
        device.get("os_guess", ""),
        device.get("service_summary", ""), device.get("lldp_cdp_records", ""),
        (device.get("lldp_cdp") or {}).get("name", ""),
        (device.get("lldp_cdp") or {}).get("description", ""),
        ssdp.get("friendlyname", ""), ssdp.get("manufacturer", ""),
        ssdp.get("modelname", ""), ssdp.get("modelnumber", ""),
        ssdp.get("devicetype", ""), snmp.get("sysDescr", ""),
        snmp.get("sysObjectID", ""), mdns, service_text, services
    )).lower()
    ports = set(int(p) for p in (device.get("port_numbers", []) or []) if str(p).isdigit())
    dhcp_text = []
    for row in dhcp_rows:
        hn, vc, prl, cid, _mac = row
        dhcp_text.extend(str(x or "").lower() for x in (hn, vc, prl, cid))
    text += " " + " ".join(dhcp_text)

    patterns = [
        (r"\b(iphone|ipad|ipod|ios|apple.?mobile)\b", "Apple mobile", 82, "Apple device name / OS signature"),
        (r"\b(macbook|imac|mac mini|mac studio|macos|mac os)\b", "Apple computer", 84, "Apple computer name / OS signature"),
        (r"\b(android|galaxy|pixel|oneplus|redmi|oppo|vivo|mi\s?[0-9]{1,2}|iphone)\b", "Android/mobile device", 80, "Explicit mobile hostname / OS signature"),
        (r"\b(windows|microsoft windows|win.?10|win.?11|thinkpad|elitebook|latitude|optiplex|probook|laptop|desktop)\b", "Windows computer", 82, "Computer name / OS signature"),
        (r"\b(linux|ubuntu|debian|fedora|arch linux|freebsd|openbsd)\b", "Linux/Unix device", 72, "OS/service signature; form factor unconfirmed"),
        (r"\b(printer|laserjet|deskjet|epson|brother|canon|xerox|ricoh|kyocera|ipp)\b", "Printer", 86, "Printer name / service signature"),
        (r"\b(camera|ipcam|cctv|hikvision|dahua|axis|rtsp)\b", "IP camera / video", 84, "Camera name / video service signature"),
        (r"\b(chromecast|google.?tv|roku|fire.?tv|smart.?tv|airplay|mediarenderer|webos|tizen)\b", "Smart TV / streaming", 82, "Media device / service signature"),
        (r"\b(xbox|playstation|nintendo|ps[345])\b", "Gaming console", 90, "Gaming platform signature"),
        (r"\b(synology|qnap|truenas|freenas|nas)\b", "NAS / storage", 86, "Storage platform signature"),
        (r"\b(mikrotik|routeros|openwrt|opnsense|pfsense|ubiquiti|unifi|access.?point|router|switch)\b", "Router / network equipment", 86, "Network infrastructure signature"),
        (r"\b(yealink|polycom|grandstream|asterisk|voip|sip phone)\b", "VoIP / IP phone", 86, "VoIP platform signature"),
        (r"\b(esxi|vmware|hyper.?v|proxmox|xenserver)\b", "Virtualisation host", 84, "Hypervisor signature"),
        (r"\b(windows server|server 20[0-9]{2}|ubuntu server|red hat|rhel|centos|almalinux|rocky linux)\b", "Server", 82, "Server OS signature"),
        (r"\b(sonos|homepod|echo dot|echo show|smart speaker)\b", "Smart speaker / audio", 84, "Audio endpoint signature"),
        (r"\b(tasmota|shelly|tuya|zigbee|zwave|thermostat|smart plug|home assistant)\b", "Smart-home / IoT device", 80, "IoT platform signature"),
        (r"\b(ups|apc smart|eaton power|powerware)\b", "UPS / power equipment", 86, "Power equipment signature"),
        (r"\b(doorbell|intercom|access control|badge reader|biometric)\b", "Access control / intercom", 82, "Access-control signature"),
        (r"\b(nvr|dvr|surveillance recorder)\b", "Video surveillance recorder", 84, "Recorder signature"),
        (r"\b(refrigerator|washing machine|dishwasher|air.?condition|smart appliance)\b", "Smart appliance", 80, "Appliance signature"),
    ]
    for pat, category, score, why in patterns:
        if re.search(pat, text, re.I):
            candidates.append((category, score, why))

    for row in dhcp_rows:
        vc = (row[1] or "").lower()
        prl = (row[2] or "").strip()
        if "android" in vc or "android" in (row[0] or "").lower():
            candidates.append(("Android/mobile device", 76, "DHCP vendor class / hostname"))
        if "msft" in vc or "microsoft" in vc:
            candidates.append(("Windows computer", 74, "DHCP vendor class"))
        if any(x in vc for x in ("udhcp", "busybox", "openwrt", "udhcpd")):
            candidates.append(("Embedded Linux / IoT", 68, "DHCP vendor class"))
        if prl:
            opts = {x.strip() for x in prl.split(",") if x.strip().isdigit()}
            if {1, 3, 6, 15, 119, 252}.issubset(opts):
                candidates.append(("Windows-compatible network client", 60, "DHCP parameter-request-list pattern"))
            elif {1, 3, 6, 12, 15, 28, 42}.issubset(opts):
                candidates.append(("Unix-like network client", 58, "DHCP parameter-request-list pattern"))

    mdns_rules = [
        (("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"), "Printer", 82, "mDNS/DNS-SD printing service"),
        (("_googlecast._tcp",), "Smart TV / streaming", 82, "mDNS/DNS-SD Google Cast service"),
        (("_airplay._tcp", "_raop._tcp"), "Apple ecosystem device (type unconfirmed)", 76, "mDNS/DNS-SD AirPlay service"),
        (("_smb._tcp", "_device-info._tcp", "_workstation._tcp"), "Computer / file-sharing endpoint", 68, "mDNS/DNS-SD workstation service"),
        (("_ssh._tcp",), "Unix-like or embedded network host", 58, "mDNS/DNS-SD SSH service"),
        (("_hap._tcp",), "Apple HomeKit / smart-home device", 80, "mDNS/DNS-SD HomeKit service"),
        (("_home-assistant._tcp",), "Smart-home controller", 88, "mDNS/DNS-SD Home Assistant service"),
        (("_sonos._tcp",), "Smart speaker / audio", 84, "mDNS/DNS-SD Sonos service"),
        (("_spotify-connect._tcp",), "Media / audio endpoint", 72, "mDNS/DNS-SD Spotify Connect service"),
        (("_sftp-ssh._tcp",), "File server / network storage candidate", 60, "mDNS/DNS-SD file service"),
    ]
    for tokens, category, score, why in mdns_rules:
        if any(token in mdns for token in tokens):
            candidates.append((category, score, why))

    port_rules = [
        ({9100, 631, 515}, "Printer", 55, "printing ports exposed"),
        ({554, 8554, 10554}, "IP camera / video", 48, "RTSP port exposed"),
        ({161}, "Network equipment / managed endpoint", 48, "SNMP port exposed"),
        ({445, 139}, "Computer / file-sharing endpoint", 48, "SMB/NetBIOS ports exposed"),
        ({3389}, "Windows remote-access endpoint", 45, "RDP port exposed"),
        ({8008, 8009, 32400}, "Media endpoint", 48, "media service ports exposed"),
        ({5060, 5061}, "VoIP / SIP endpoint", 48, "SIP ports exposed"),
        ({500, 4500}, "VPN/network appliance candidate", 42, "IPsec VPN ports exposed"),
        ({53, 67, 68}, "Network infrastructure candidate", 42, "DNS/DHCP ports exposed"),
    ]
    for required, category, score, why in port_rules:
        if required.issubset(ports):
            candidates.append((category, score, why))
    if device.get("_is_gateway"):
        candidates.append(("Router / network equipment", 98, "Default-gateway role observed"))

    best = {}
    for category, score, why in candidates:
        if category not in best or score > best[category][0]:
            best[category] = (score, why)
    return [(cat, score, why) for cat, (score, why) in best.items()]

# ------------------------------------------------------------
# ADVANCED DEVICE RECOGNITION 1.0
# Multi-signal, explainable classification. This identifies device
# families and reported hardware details; it does not guess exact models.
# ------------------------------------------------------------
_RECOGNITION_RULES = [
    # category, weight, source-family, regexes
    ("Printer", 0.94, "service", (r"\bipp\b", r"printer", r"jetdirect", r"pdl-datastream", r"_ipp\._tcp", r"_printer\._tcp")),
    ("IP camera / surveillance", 0.94, "service", (r"\bonvif\b", r"rtsp", r"hikvision", r"dahua", r"axis communications", r"ip.?camera", r"_onvif\._tcp")),
    ("NAS / network storage", 0.93, "product", (r"synology", r"diskstation", r"qnap", r"qts", r"truenas", r"freenas", r"asustor", r"terramaster")),
    ("Router / firewall", 0.94, "product", (r"routeros", r"mikrotik", r"openwrt", r"ubiquiti", r"unifi", r"edgeos", r"opnsense", r"pfsense", r"fortigate", r"sonicwall", r"cisco ios")),
    ("Wireless access point", 0.91, "product", (r"access.?point", r"wireless controller", r"unifi ap", r"ruckus", r"arubaos", r"omada")),
    ("VoIP phone / telephony", 0.92, "service", (r"yealink", r"polycom", r"grandstream", r"asterisk", r"sip phone", r"_sip\._tcp")),
    ("Smart TV / media streamer", 0.92, "service", (r"googlecast", r"chromecast", r"roku", r"fire.?tv", r"webos", r"tizen", r"mediarenderer", r"airplay", r"_googlecast\._tcp")),
    ("Smart speaker / audio", 0.91, "service", (r"sonos", r"homepod", r"spotify.?connect", r"echo dot", r"echo show", r"_sonos\._tcp")),
    ("Gaming console", 0.94, "reported", (r"xbox", r"playstation", r"nintendo switch", r"ps[345]")),
    ("Virtualisation host", 0.92, "product", (r"proxmox", r"esxi", r"vmware", r"hyper.?v", r"xenserver")),
    ("Windows computer", 0.88, "os", (r"windows 10", r"windows 11", r"windows workstation", r"microsoft windows", r"microsoft-ds")),
    ("Linux / Unix computer", 0.84, "os", (r"ubuntu", r"debian", r"fedora", r"freebsd", r"openbsd", r"openssh", r"linux")),
    ("Apple computer", 0.91, "reported", (r"macbook", r"imac", r"mac mini", r"macos", r"darwin")),
    ("Apple mobile device", 0.91, "reported", (r"iphone", r"ipad", r"ios device", r"apple mobile")),
    ("Android mobile device", 0.88, "reported", (r"android", r"pixel [0-9]", r"samsung galaxy", r"oneplus", r"xiaomi", r"redmi", r"oppo", r"vivo")),
    ("Smart-home / IoT", 0.88, "service", (r"home assistant", r"tasmota", r"shelly", r"tuya", r"zigbee", r"zwave", r"_hap\._tcp")),
    ("UPS / power equipment", 0.91, "reported", (r"apc ups", r"eaton ups", r"powerware", r"ups network management")),
]

def advanced_device_recognition(device):
    """Produce explainable category, vendor and model assessments from independent signals."""
    facts = []
    def add(family, value, source, reliability=0.7):
        value = _clean(value, 500)
        if value and not _placeholder(value):
            facts.append({"family": family, "value": value, "source": source,
                          "reliability": float(reliability)})

    # Device-reported identity and naming signals.
    for key, label in (("hostname", "Hostname"), ("friendly_name", "Friendly name"),
                       ("device_name", "Discovered name"), ("model", "Reported model"),
                       ("reported_manufacturer", "Reported manufacturer")):
        add("reported", device.get(key, ""), label, 0.78 if key in ("hostname", "device_name") else 0.92)
    add("oui", device.get("oui_manufacturer") or device.get("vendor", ""), "IEEE OUI allocation", 0.55)
    add("os", device.get("os_guess", ""), "Nmap OS fingerprint", 0.82)
    passive = device.get("passive_tcp") or {}
    add("tcpip", passive.get("signature", ""), "Passive TCP SYN fingerprint", 0.55)
    add("tcpip", passive.get("os_family_hint", ""), "Passive TCP OS-family hint", 0.35)
    add("mdns", device.get("mdns_records", ""), "mDNS/DNS-SD", 0.82)
    ssdp = device.get("ssdp_intel") or {}
    for key in ("friendlyname", "manufacturer", "modelname", "modelnumber", "devicetype", "ssdp_server"):
        add("upnp", ssdp.get(key, ""), "SSDP/UPnP " + key, 0.91)
    for key in ("sysDescr", "sysObjectID", "sysName"):
        add("snmp", (device.get("snmp_intel") or {}).get(key, ""), "SNMPv3 " + key, 0.96)
    for row in device.get("nmap_service_intel", []) or []:
        desc = " ".join(str(row.get(k, "")) for k in ("name", "product", "version", "extrainfo"))
        add("service", desc, f"Nmap service {row.get('port')}", 0.86)
        if row.get("product"):
            add("product", row.get("product"), f"Nmap product on {row.get('port')}", 0.9)
    for row in device.get("service_intel", []) or []:
        add("service", " ".join(str(row.get(k, "")) for k in ("banner", "server", "http_title", "api_identity", "powered_by", "www_authenticate")),
            f"Active service probe {row.get('port', '')}", 0.84)
    for row in device.get("dhcp_identity", []) or []:
        add("dhcp", " ".join(str(row.get(k, "")) for k in ("vendor_class", "hostname", "parameter_request_list")),
            "DHCP client fingerprint", 0.72)

    searchable = " | ".join(x["value"] for x in facts).lower()
    ports = {int(x) for x in device.get("port_numbers", []) if str(x).isdigit()}
    # Service combinations are useful but deliberately lower-weight than product/banner evidence.
    service_tokens = []
    for row in device.get("nmap_service_intel", []) or []:
        service_tokens.append(str(row.get("name", "")).lower())
    service_tokens += [str(x).lower() for x in device.get("services_found", []) or []]
    service_text = " ".join(service_tokens)
    candidates = defaultdict(dict)
    matches = []
    for category, weight, _rule_family, patterns in _RECOGNITION_RULES:
        for fact in facts:
            hit = next((pat for pat in patterns if re.search(pat, fact["value"], re.I)), None)
            if hit:
                family = fact["family"]
                contribution = weight * fact["reliability"]
                candidates[category][family] = max(candidates[category].get(family, 0), contribution)
                matches.append({"category": category, "matched": hit, "source_family": family,
                                "source": fact["source"], "weight": round(contribution, 2)})
    # High-value combinations which are not reliable from a single open port.
    combos = [
        ({"ipp", "http"}, "Printer", "IPP and HTTP services", 0.76),
        ({"rtsp", "http"}, "IP camera / surveillance", "RTSP and HTTP services", 0.74),
        ({"smb", "http"}, "NAS / network storage candidate", "SMB and HTTP services", 0.68),
        ({"ssh", "http"}, "Linux / Unix computer", "SSH and HTTP services", 0.62),
    ]
    for required, category, why, score in combos:
        if required.issubset(set(service_tokens)):
            candidates[category]["service_combination"] = max(candidates[category].get("service_combination", 0), score)
            matches.append({"category": category, "matched": why, "source_family": "service_combination", "weight": score})
    # Ports alone are weak supporting clues, never enough to assert an exact device type.
    port_rules = [
        ({631, 9100}, "Printer candidate", 0.40), ({554, 80}, "IP camera candidate", 0.34),
        ({445, 5000}, "NAS candidate", 0.36), ({5060}, "VoIP endpoint candidate", 0.30),
    ]
    for required, category, score in port_rules:
        if required.issubset(ports):
            candidates[category]["port_combination"] = score
            matches.append({"category": category, "matched": f"ports {sorted(required)}", "source_family": "port_combination", "weight": score})

    ranked = []
    for category, families in candidates.items():
        # Combine independent families with diminishing returns; do not count many banners
        # from the same service family as independent confirmations.
        vals = sorted(families.values(), reverse=True)
        score = 1.0
        for index, val in enumerate(vals):
            contribution = val * (0.90 if index == 0 else 0.72)
            score *= (1.0 - min(0.95, contribution))
        confidence = int(min(97, round((1.0 - score) * 100)))
        ranked.append((confidence, category, sorted(families)))
    ranked.sort(reverse=True)
    best = ranked[0] if ranked else (0, "Unclassified network device", [])
    runner = ranked[1] if len(ranked) > 1 else (0, "", [])
    conflict = bool(runner[0] >= 45 and best[0] - runner[0] < 12)
    if conflict:
        confidence = max(25, best[0] - 15)
        category = "Ambiguous: " + best[1] + " / " + runner[1]
    else:
        confidence, category = best[0], best[1]
    # Explicit device-reported model/manufacturer only. Never infer a model from OUI or ports.
    reported_model = _clean(device.get("model", ""), 160)
    reported_maker = _clean(device.get("reported_manufacturer", ""), 160)
    result = {
        "category": category, "confidence": confidence,
        "status": "HIGH" if confidence >= 80 else "PROBABLE" if confidence >= 60 else "LOW" if confidence else "UNKNOWN",
        "model": reported_model if reported_model and not _placeholder(reported_model) else "",
        "manufacturer": reported_maker if reported_maker and not _placeholder(reported_maker) else "",
        "nic_manufacturer": _clean(device.get("oui_manufacturer") or device.get("vendor", ""), 160),
        "evidence": facts, "matches": matches,
        "passive_tcp_os_hint": (device.get("passive_tcp") or {}).get("os_family_hint", ""),
        "alternatives": [{"category": x[1], "confidence": x[0], "source_families": x[2]} for x in ranked[1:4]],
        "conflicting_classifications": conflict,
        "limitations": ["NIC manufacturer is not necessarily device manufacturer.",
                        "Open ports alone do not establish device identity.",
                        "Exact hardware model is shown only when explicitly reported by a device or service."]
    }
    device["recognition"] = result
    if confidence >= 55 and not conflict:
        device["device_type"] = category
        device["identity_category_confidence"] = confidence
        device["identification_confidence"] = max(int(device.get("identification_confidence", 0) or 0), confidence)
    return result

def identity_fusion(device, ssdp=None, mdns_records=""):
    ssdp = ssdp or {}
    evidence = []
    ip, mac = device.get("ip", ""), _normalise_mac(device.get("mac", ""))
    vendor = device.get("vendor", "")
    if mac:
        org, props = oui_lookup(mac)
        if org:
            device["oui_manufacturer"] = org
            evidence.append(("IEEE OUI", "NIC manufacturer", org, 58, "OBSERVED"))
        if props["locally_administered"]:
            evidence.append(("MAC analysis", "MAC address type",
                             "Locally administered/randomisable MAC", 65, "OBSERVED"))
        if props["multicast"]:
            evidence.append(("MAC analysis", "MAC address type",
                             "Multicast MAC; not a normal host identity", 95, "OBSERVED"))
    if device.get("hostname") and not _placeholder(device.get("hostname")):
        evidence.append(("Hostname discovery", "Hostname", device["hostname"], 70, "OBSERVED"))
    if mdns_records:
        evidence.append(("mDNS/DNS-SD", "Service advertisement",
                         _clean(mdns_records, 500), 76, "DEVICE_REPORTED"))
    if ssdp:
        for key, attr, conf in (("friendlyname", "Friendly name", 92),
                                ("manufacturer", "Manufacturer", 92),
                                ("modelname", "Model", 94),
                                ("modelnumber", "Model number", 92),
                                ("devicetype", "UPnP device type", 94),
                                ("ssdp_server", "SSDP server banner", 72)):
            if ssdp.get(key):
                evidence.append(("SSDP/UPnP", attr, ssdp[key], conf, "DEVICE_REPORTED"))
    dhcp_rows = []
    try:
        with DB_MANAGER.read() as conn:
            dhcp_rows = _recent_dhcp_evidence(conn, device)
    except Exception:
        pass
    device["dhcp_identity"] = [
        {"hostname": r[0] or "", "vendor_class": r[1] or "",
         "parameter_request_list": r[2] or "", "client_identifier": r[3] or ""}
        for r in dhcp_rows]
    for row in dhcp_rows:
        hn, vc, prl, cid, _ = row
        if hn:
            evidence.append(("DHCP", "Hostname", hn, 78, "DEVICE_REPORTED"))
        if vc:
            evidence.append(("DHCP", "Vendor class", vc, 70, "DEVICE_REPORTED"))
        if prl:
            evidence.append(("DHCP", "Parameter request list", prl, 58, "OBSERVED"))
        if cid:
            evidence.append(("DHCP", "Client identifier", cid, 55, "OBSERVED"))
    if dhcp_rows:
        signatures = sorted({dhcp_fingerprint(row[1] or "", row[2] or "")
                             for row in dhcp_rows if row[1] or row[2]})
        if signatures:
            evidence.append(("DHCP", "DHCP fingerprint",
                             ",".join(signatures[:3]), 60, "OBSERVED"))
    l2 = device.get("lldp_cdp") or {}
    if l2:
        if l2.get("name"):
            evidence.append(("LLDP/CDP", "Advertised system name", l2["name"], 88, "DEVICE_REPORTED"))
        if l2.get("description"):
            evidence.append(("LLDP/CDP", "Advertised system description", l2["description"], 88, "DEVICE_REPORTED"))
        if l2.get("port"):
            evidence.append(("LLDP/CDP", "Advertised switch port", l2["port"], 85, "DEVICE_REPORTED"))
    if device.get("_is_gateway"):
        evidence.append(("Network role", "Device category", "Router / network equipment", 98, "OBSERVED"))
    for cat, score, why in _classify_from_signatures(device, dhcp_rows):
        evidence.append(("Identity classifier", "Device category", cat, score, "INFERRED"))
    for item in device.get("service_intel", []):
        if item.get("banner"):
            evidence.append(("Service banner", "Service identification",
                             f"{item.get('port')}/{item.get('protocol', 'tcp')}: {item['banner']}",
                             78, "OBSERVED"))
        if item.get("http_title"):
            evidence.append(("HTTP service", "Web interface title", item["http_title"], 82, "DEVICE_REPORTED"))
        if item.get("server"):
            evidence.append(("HTTP service", "HTTP server", item["server"], 76, "OBSERVED"))
    for key, val in (device.get("snmp_intel") or {}).items():
        if val:
            attr = {"sysDescr": "Operating system", "sysObjectID": "SNMP object identifier",
                    "sysName": "Hostname"}.get(key, key)
            evidence.append(("SNMPv3", attr, val, 96, "DEVICE_REPORTED"))
    for cert in device.get("tls_intel", []):
        if cert.get("subject"):
            evidence.append(("TLS certificate", "TLS certificate subject", cert["subject"], 65, "OBSERVED"))
        for san in cert.get("san", [])[:8]:
            evidence.append(("TLS certificate", "TLS certificate SAN", san, 60, "OBSERVED"))
    if device.get("os_guess") and device["os_guess"] not in ("Unknown", "Not yet fingerprinted"):
        evidence.append(("Nmap OS detection", "Operating system", device["os_guess"], 80, "INFERRED"))
    passive = device.get("passive_tcp") or {}
    if passive.get("signature"):
        evidence.append(("Passive TCP/IP fingerprint", "TCP/IP SYN signature",
                         passive["signature"], 55, "OBSERVED"))
        evidence.append(("Passive TCP/IP fingerprint", "OS family hint",
                         passive.get("os_family_hint", ""),
                         int(passive.get("confidence", 20)), "INFERRED"))

    votes = defaultdict(dict)
    for src, attr, val, conf, cls in evidence:
        if attr == "Device category":
            family = _identity_source_family(src)
            old = votes[val].get(family, 0)
            votes[val][family] = max(old, max(0, min(100, int(conf))))
    if votes:
        ranked = sorted(votes, key=lambda k: sum(votes[k].values()) + 7 * max(0, len(votes[k]) - 1), reverse=True)
        top = ranked[0]
        top_score = sum(votes[top].values())
        second_score = sum(votes[ranked[1]].values()) if len(ranked) > 1 else 0
        independent = len(votes[top])
        category_conf = min(94, int(30 + min(40, top_score * 0.22) + min(24, max(0, independent - 1) * 12)))
        if second_score and (top_score - second_score) < max(18, top_score * 0.18):
            device["identity_conflicts"] = ranked[1:]
            category_conf = max(20, category_conf - 15)
        else:
            device["identity_conflicts"] = ranked[1:]
        if category_conf >= 48 and (not second_score or top_score - second_score >= max(18, top_score * 0.18)):
            device["device_type"] = top
        device["identity_category_confidence"] = category_conf
        device["identification_confidence"] = max(
            int(device.get("identification_confidence", 0) or 0), category_conf)
    else:
        device["identity_category_confidence"] = 0
        device["identity_conflicts"] = []
    if ssdp.get("modelname"):
        device["model"] = _clean(" ".join(x for x in (ssdp.get("modelname"), ssdp.get("modelnumber")) if x))
    if ssdp.get("manufacturer"):
        device["reported_manufacturer"] = ssdp["manufacturer"]
    if ssdp.get("friendlyname"):
        device["friendly_name"] = ssdp["friendlyname"]
    device["identity_evidence"] = evidence
    return evidence

_IDENTITY_SOURCE_FAMILY = {
    "ieee oui": "mac_allocation", "mac analysis": "mac_properties",
    "hostname discovery": "name_resolution", "reverse dns": "name_resolution",
    "netbios": "windows_name_service", "dhcp": "dhcp",
    "mdns/dns-sd": "mdns", "ssdp/upnp": "upnp",
    "nmap os detection": "tcpip_fingerprint", "identity classifier": "heuristic_classifier",
    "tls certificate": "tls", "snmpv3": "snmp", "local adapter": "local_endpoint",
    "endpoint agent": "endpoint_agent", "service fingerprint": "service_probe",
    "service probe": "service_probe", "lldp/cdp": "network_neighbour_discovery",
}

def _identity_source_family(source):
    key = str(source or "").strip().lower()
    return _IDENTITY_SOURCE_FAMILY.get(key, key.split(":", 1)[0] or "unknown")

def assess_identity_evidence(device, evidence=None):
    evidence = list(evidence if evidence is not None else device.get("identity_evidence", []))
    groups = defaultdict(list)
    for row in evidence:
        if len(row) < 5:
            continue
        source, attribute, value, confidence, evidence_class = row[:5]
        a = str(attribute or "").strip().casefold()
        value = _clean(value, 500)
        if not value or _placeholder(value):
            continue
        if a in {"nic manufacturer", "mac vendor", "oui manufacturer"}:
            a = "nic manufacturer"
        elif a in {"manufacturer", "upnp manufacturer", "reported manufacturer"}:
            a = "manufacturer"
        elif a in {"model", "model number", "hardware model"}:
            a = "model"
        elif a in {"operating system", "os estimate", "os family"}:
            a = "operating system"
        elif a in {"device category", "device type", "upnp type"}:
            a = "device category"
        elif a in {"dhcp fingerprint"}:
            a = "dhcp fingerprint"
        else:
            continue
        cls = str(evidence_class or "INFERRED").upper()
        if a in {"manufacturer", "model"} and cls not in {"DEVICE_REPORTED", "OBSERVED"}:
            continue
        if a == "model" and str(source).lower() in {"ieee oui", "identity classifier", "mac analysis"}:
            continue
        key = re.sub(r"\s+", " ", value).strip().casefold()
        groups[a].append({"source": str(source), "family": _identity_source_family(source),
                          "value": value, "key": key,
                          "confidence": max(0, min(100, int(confidence or 0))),
                          "class": cls})
    results = []
    for attribute, rows in groups.items():
        candidates = defaultdict(dict)
        for row in rows:
            old = candidates[row["key"]].get(row["family"])
            if old is None or row["confidence"] > old["confidence"]:
                candidates[row["key"]][row["family"]] = row
        scored = []
        for key, families in candidates.items():
            contributions = []
            for family, row in families.items():
                if family == "mac_allocation" and attribute != "nic manufacturer":
                    continue
                reliability = {"DEVICE_REPORTED": 0.88, "OBSERVED": 0.82,
                               "INFERRED": 0.52}.get(row["class"], 0.45)
                contributions.append(row["confidence"] / 100.0 * reliability)
            if not contributions:
                continue
            remaining = 1.0
            for contribution in contributions:
                remaining *= 1.0 - min(0.95, contribution)
            score = 1.0 - remaining
            if len(contributions) > 1:
                score = min(0.97, score + min(0.12, 0.035 * (len(contributions) - 1)))
            scored.append((score, key, families))
        if not scored:
            continue
        scored.sort(key=lambda x: x[0], reverse=True)
        best, _, families = scored[0]
        competing = scored[1][0] if len(scored) > 1 else 0.0
        conflicts = [{"value": max(v.values(), key=lambda r: r["confidence"])["value"],
                      "confidence": int(vv * 100),
                      "sources": sorted(v.keys())}
                     for vv, _, v in scored[1:] if vv >= 0.25]
        if competing >= 0.35:
            best *= max(0.55, 1.0 - min(0.40, competing * 0.35))
        chosen = list(families.values())
        if attribute == "model":
            if not any(x["class"] == "DEVICE_REPORTED" for x in chosen):
                continue
            if len(families) < 2:
                best = min(best, 0.74)
        value = max(chosen, key=lambda x: (x["confidence"], x["class"] == "DEVICE_REPORTED"))["value"]
        confidence = int(max(0, min(97, round(best * 100))))
        status = ("CONFIRMED" if confidence >= 90 and len(families) >= 2 and competing < 0.35
                  else "HIGH" if confidence >= 75
                  else "PROBABLE" if confidence >= 55 else "LOW")
        rationale = (f"{len(families)} independent source families support this value; "
                     f"{len(rows)} observations considered. " +
                     ("Competing evidence reduced confidence." if conflicts
                      else "No material competing candidate."))
        if attribute == "nic manufacturer":
            rationale += " This identifies the network-interface allocation, not necessarily the device maker."
        results.append({"attribute": attribute, "value": value, "confidence": confidence,
                        "status": status, "sources": sorted({x["source"] for x in chosen}),
                        "conflicts": conflicts, "evidence_count": len(rows),
                        "independent_sources": len(families), "rationale": rationale})
    return results

def persist_identity_assessments(conn, device, assessments, timestamp=None):
    ts = timestamp or now_text()
    for item in assessments:
        conn.execute("""INSERT INTO identity_assessments(device_id,ip,attribute,assessed_value,
            confidence,status,supporting_sources,conflicting_values,evidence_count,independent_sources,
            rationale,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip,attribute) DO UPDATE SET device_id=excluded.device_id,
            assessed_value=excluded.assessed_value,confidence=excluded.confidence,status=excluded.status,
            supporting_sources=excluded.supporting_sources,conflicting_values=excluded.conflicting_values,
            evidence_count=excluded.evidence_count,independent_sources=excluded.independent_sources,
            rationale=excluded.rationale,last_seen=excluded.last_seen""",
            (device.get("device_id", ""), device.get("ip", ""), item["attribute"],
             item["value"], item["confidence"], item["status"],
             json.dumps(item["sources"]), json.dumps(item["conflicts"]),
             item["evidence_count"], item["independent_sources"],
             item["rationale"], ts, ts))

def tls_certificate_intelligence(ip, ports, timeout=1.5):
    results = []
    for port in sorted(set(ports) & {443, 8443, 9443, 10443}):
        try:
            import ssl
            ctx = ssl._create_unverified_context()
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=None) as sock:
                    der = sock.getpeercert(binary_form=True)
                    cert = sock.getpeercert() or {}
            if der:
                names = [v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"][:12]
                subject = ", ".join("=".join(x) for group in cert.get("subject", []) for x in group)
                issuer = ", ".join("=".join(x) for group in cert.get("issuer", []) for x in group)
                results.append({"port": port, "sha256": hashlib.sha256(der).hexdigest(),
                                "subject": _clean(subject, 300),
                                "issuer": _clean(issuer, 300),
                                "san": names, "not_before": cert.get("notBefore", ""),
                                "not_after": cert.get("notAfter", "")})
        except Exception:
            continue
    return results

def snmpv3_intelligence(ip, timeout=2):
    """Read-only SNMPv3 query. Secrets are written to a short-lived private config, never argv."""
    exe = shutil.which("snmpget")
    user = os.environ.get("NETWORKRADAR_SNMPV3_USER", "").strip()
    auth_proto = os.environ.get("NETWORKRADAR_SNMPV3_AUTH_PROTO", "SHA").strip().upper()
    auth_pass = os.environ.get("NETWORKRADAR_SNMPV3_AUTH_PASS", "")
    priv_proto = os.environ.get("NETWORKRADAR_SNMPV3_PRIV_PROTO", "AES").strip().upper()
    priv_pass = os.environ.get("NETWORKRADAR_SNMPV3_PRIV_PASS", "")
    if not (exe and user and auth_pass and priv_pass): return {}
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user): return {}
    # Net-SNMP config directives are line-oriented; reject whitespace/control characters.
    if any(ch.isspace() or ord(ch) < 32 for ch in auth_pass + priv_pass): return {}
    if auth_proto not in {"MD5","SHA","SHA-224","SHA-256","SHA-384","SHA-512"}: return {}
    if priv_proto not in {"DES","AES","AES-128","AES-192","AES-256"}: return {}
    out = {}
    # Net-SNMP reads def* settings from SNMPCONFPATH. The file is mode 0600 on POSIX
    # and is deleted immediately after use. No secret appears in the child command line.
    try:
        with tempfile.TemporaryDirectory(prefix="nr-snmp-") as td:
            cfg = Path(td) / "snmp.conf"
            cfg.write_text("\n".join([
                f'defSecurityName {user}', 'defSecurityLevel authPriv',
                f'defAuthType {auth_proto}', f'defAuthPassphrase {auth_pass}',
                f'defPrivType {priv_proto}', f'defPrivPassphrase {priv_pass}',
            ]) + "\n", encoding="utf-8")
            try: os.chmod(cfg, 0o600)
            except OSError: pass
            env = os.environ.copy(); env["SNMPCONFPATH"] = td
            for key, oid in (("sysDescr","1.3.6.1.2.1.1.1.0"),
                             ("sysObjectID","1.3.6.1.2.1.1.2.0"),
                             ("sysName","1.3.6.1.2.1.1.5.0")):
                cmd = [exe,"-v3","-l","authPriv","-u",user,"-t",str(timeout),"-r","0",ip,oid]
                try:
                    r = subprocess.run(cmd,capture_output=True,text=True,timeout=timeout+2,
                                       encoding="utf-8",errors="replace",env=env)
                    if r.returncode == 0 and r.stdout.strip():
                        out[key] = _clean(r.stdout.split("=",1)[-1],400)
                except Exception:
                    continue
    except Exception:
        return {}
    return out


def collect_lldp_cdp(interface=None, duration=3):
    if not TSHARK.exists():
        return []
    iface = interface or choose_iface()
    if not iface:
        return []
    fields = ["frame.time_epoch", "eth.src", "lldp.chassis.id", "lldp.port.id",
              "lldp.system.name", "lldp.system.desc", "cdp.deviceid",
              "cdp.platform", "cdp.portid"]
    cmd = [str(TSHARK), "-n", "-i", str(iface),
           "-a", f"duration:{max(1, min(6, int(duration)))}",
           "-Y", "lldp || cdp", "-T", "fields", "-E", "separator=/t", "-E", "quote=d"]
    for f in fields:
        cmd.extend(["-e", f])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 8, encoding="utf-8", errors="replace")
        found = []
        for line in (r.stdout or "").splitlines()[:200]:
            row = next(csv.reader([line], delimiter="\t", quotechar='"'))
            row += [""] * (len(fields) - len(row))
            epoch, mac, chassis, port, name, desc, cdp_name, platform, cdp_port = row[:9]
            name = name or cdp_name
            if name or desc or platform:
                found.append({"mac": mac, "chassis": chassis, "port": port or cdp_port,
                              "name": _clean(name), "description": _clean(desc or platform)})
        return found
    except Exception:
        return []

def parse_passive_tcp_syn_rows(raw_text):
    """Parse TShark TCP SYN metadata into conservative p0f-style signatures."""
    found = {}
    fields = (raw_text or "").splitlines()
    for line in fields[:2000]:
        try:
            row = next(csv.reader([line], delimiter="\t", quotechar='"'))
        except Exception:
            continue
        row += [""] * max(0, 8 - len(row))
        src = (row[0] or row[1]).strip()
        if not src:
            continue
        ttl = (row[2] or row[3]).strip()
        window, mss, scale, sack = (x.strip() for x in row[4:8])
        if not any((ttl, window, mss, scale, sack)):
            continue
        signature = f"ttl={ttl or '?'};win={window or '?'};mss={mss or '?'};ws={scale or '?'};sack={sack or '?'}"
        try:
            ttl_n = int(ttl) if ttl else 0
        except ValueError:
            ttl_n = 0
        # TTL is hop-decremented and therefore only a weak family hint.
        if ttl_n and ttl_n <= 64:
            hint = "Unix-like / mobile / embedded TCP stack candidate"
        elif ttl_n and ttl_n <= 128:
            hint = "Windows / embedded TCP stack candidate"
        else:
            hint = "TCP/IP stack family undetermined"
        found[src] = {"signature": signature,
                      "signature_hash": hashlib.sha256(signature.encode()).hexdigest()[:24],
                      "observed_ttl": ttl_n or None, "os_family_hint": hint,
                      "confidence": 35 if ttl_n else 20,
                      "method": "passive TCP SYN heuristic; not a p0f database match"}
    return found


def passive_tcp_fingerprint_snapshot(duration=4):
    """Observe visible SYN packets on the selected local interface (best-effort)."""
    if not TSHARK.exists():
        return {"status": "UNAVAILABLE", "devices": {}, "detail": "TShark is not installed."}
    iface = choose_iface()
    if not iface:
        return {"status": "UNAVAILABLE", "devices": {}, "detail": "No capture interface selected."}
    fields = ["ip.src", "ipv6.src", "ip.ttl", "ipv6.hlim", "tcp.window_size_value",
              "tcp.options.mss_val", "tcp.options.wscale.shift", "tcp.options.sack_perm"]
    cmd = [str(TSHARK), "-n", "-i", str(iface), "-a",
           f"duration:{max(2, min(8, int(duration)))}", "-Y",
           "tcp.flags.syn==1 && tcp.flags.ack==0", "-T", "fields",
           "-E", "separator=/t", "-E", "quote=d"]
    for field in fields:
        cmd.extend(["-e", field])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=max(12, int(duration) + 8),
                             encoding="utf-8", errors="replace")
        if proc.returncode != 0:
            return {"status": "ERROR", "devices": {},
                    "detail": _clean(proc.stderr or "TShark capture failed", 240)}
        rows = parse_passive_tcp_syn_rows(proc.stdout)
        return {"status": "OBSERVED" if rows else "NO_TRAFFIC_OBSERVED",
                "devices": rows,
                "detail": "Only packets visible at this capture interface are observable; switched Wi-Fi client-to-client traffic may be hidden."}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "devices": {}, "detail": "Passive TCP capture timed out."}
    except Exception as exc:
        return {"status": "ERROR", "devices": {}, "detail": _clean(exc, 240)}


def persist_identity_evidence(devices):
    total = identified = unknown = 0
    def _w(conn):
        nonlocal total, identified, unknown
        for dev in devices:
            for src, attr, val, conf, cls in dev.get("identity_evidence", []):
                total += _add_identity_evidence(conn, dev, src, attr, val, conf, cls, APP_VERSION)
            for cert in dev.get("tls_intel", []):
                total += _add_identity_evidence(conn, dev, "TLS certificate", "Certificate SHA256",
                                                cert.get("sha256", ""), 90, "OBSERVED", "TLS")
                for san in cert.get("san", []):
                    total += _add_identity_evidence(conn, dev, "TLS certificate", "Certificate SAN",
                                                    san, 78, "DEVICE_REPORTED", "TLS")
                if cert.get("subject"):
                    total += _add_identity_evidence(conn, dev, "TLS certificate", "Certificate subject",
                                                    cert["subject"], 70, "DEVICE_REPORTED", "TLS")
            if dev.get("snmp_intel"):
                for attr, val in dev["snmp_intel"].items():
                    total += _add_identity_evidence(conn, dev, "SNMPv3", attr, val, 96, "DEVICE_REPORTED", "SNMPv3")
            if dev.get("device_type") not in ("Unclassified device", "Unclassified network device"):
                identified += 1
            else:
                unknown += 1
        conn.execute("INSERT INTO identity_engine_runs(timestamp,devices_processed,evidence_added,identified,unknown,errors) VALUES(?,?,?,?,?,?)",
                     (now_text(), len(devices), total, identified, unknown, ""))
    DB_MANAGER.write(_w)
    return {"devices": len(devices), "evidence_added": total,
            "identified": identified, "unknown": unknown}

def identify_device(device, ssdp=None, deep=False):
    ip = device["ip"]
    methods, observations = [], []
    ssdp = ssdp or {}
    local = device.get("_local_identity", {})
    if local and local.get("ip") == ip:
        device["_is_local"] = True
        name = local.get("hostname") or "This computer"
        device["hostname"] = name
        device["device_name"] = name
        if local.get("mac") and device.get("mac") in ("", "Unavailable"):
            device["mac"] = local["mac"]
        methods.append("Local adapter")
        observations.append(("Local identity",
                             f"{name} on {local.get('adapter') or 'adapter'}", 100))
    if device.get("hostname") not in ("", "-", "Unknown") and not device.get("_is_local"):
        methods.append("Nmap hostname")
        observations.append(("Nmap hostname", device["hostname"], 70))
    if device.get("vendor") not in ("", "Unknown"):
        methods.append("MAC OUI")
        observations.append(("NIC vendor (not device vendor)", device["vendor"], 55))
    mac = device.get("mac", "")
    if mac and mac != "Unavailable":
        try:
            if int(mac.split(":")[0], 16) & 0x02:
                observations.append(("MAC properties", "Locally administered MAC", 60))
                methods.append("MAC flag")
        except (ValueError, IndexError):
            pass
    with ThreadPoolExecutor(max_workers=2) as pool:
        rf = pool.submit(reverse_dns, ip)
        nbf = pool.submit(netbios_name, ip)
        try:
            rev = rf.result(timeout=6)
        except Exception:
            rev = ""
        try:
            nb = nbf.result(timeout=6)
        except Exception:
            nb = ""
    if rev:
        device["hostname"] = rev
        methods.append("Reverse DNS")
        observations.append(("Reverse DNS", rev, 75))
    if nb:
        if _placeholder(device.get("hostname")) or device.get("hostname") == ip:
            device["hostname"] = nb
        methods.append("NetBIOS")
        observations.append(("NetBIOS name", nb, 85))
    if ssdp:
        f = ssdp.get("friendlyname", "")
        m = ssdp.get("manufacturer", "")
        mn = ssdp.get("modelname", "")
        mo = ssdp.get("modelnumber", "")
        if f:
            device["friendly_name"] = f
            methods.append("UPnP")
            observations.append(("UPnP name", f, 95))
        if m:
            device["reported_manufacturer"] = m
            observations.append(("UPnP manufacturer (device-reported)", m, 95))
        if mn:
            device["model"] = " ".join(x for x in (mn, mo) if x)
            observations.append(("UPnP model", device["model"], 95))
        if ssdp.get("devicetype"):
            observations.append(("UPnP type", ssdp["devicetype"], 95))
    if device.get("port_numbers"):
        methods.append("TCP fingerprint")
        observations.append(("Open TCP ports",
                             ",".join(map(str, sorted(set(device["port_numbers"])))), 80))
        if device.get("services_found"):
            observations.append(("Services", "; ".join(device["services_found"]), 85))
    if device.get("os_guess") and device["os_guess"] not in ("Unknown", "Not yet fingerprinted"):
        methods.append("OS fingerprint")
        observations.append(("OS estimate", device["os_guess"], 75))
    names = [device.get("friendly_name", ""), nb, rev,
             device.get("hostname", "") if device.get("hostname") != "-" else ""]
    chosen = next((n for n in names if not _placeholder(n)), "")
    if not chosen:
        vendor = device.get("vendor", "Unknown")
        chosen = (f"{vendor} device at {ip}" if vendor != "Unknown"
                  else f"Unidentified device at {ip}")
    device["device_name"] = _clean(chosen)
    device["port_numbers"] = sorted(set(device.get("port_numbers", [])))
    device["open_ports"] = (", ".join(map(str, device["port_numbers"]))
                            or "Not fingerprinted")
    device["service_summary"] = "; ".join(device.get("services_found", []))[:500]
    device["device_type"] = infer_type(device, ssdp=ssdp)
    conf = 30 if device.get("_is_local") else 0
    if device.get("mac") not in ("", "Unavailable"):
        conf += 10
        methods.append("MAC")
    if device.get("hostname") not in ("", "-", "Unknown"):
        conf += 20
    if rev:
        conf += 10
    if nb:
        conf += 15
    if ssdp.get("friendlyname") or ssdp.get("modelname"):
        conf += 30
    if device.get("port_numbers"):
        conf += 10
    if device.get("vendor") not in ("", "Unknown"):
        conf += 5
    device["identification_confidence"] = min(98, conf)
    device["identification_methods"] = ", ".join(dict.fromkeys(methods))
    if device.get("os_guess") in ("", "Unknown", None):
        device["os_guess"] = "Not yet fingerprinted"
    return observations

def service_banner_intelligence(ip, ports, timeout=1.5):
    """Collect low-impact service metadata; never submits credentials or exploit payloads."""
    out = []
    http_ports = {80, 81, 443, 631, 3000, 5000, 5001, 7001, 8000, 8008,
                  8009, 8080, 8081, 8443, 8888, 9000, 9443}
    selected = sorted(set(int(p) for p in (ports or []) if str(p).isdigit()) &
                      ({22, 445, 9100} | http_ports))
    for port in selected:
        item = {"port": int(port), "protocol": "tcp"}
        try:
            if port in http_ports:
                secure = port in {443, 5001, 7001, 8443, 9443}
                scheme = "https" if secure else "http"
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *args, **kwargs):
                        return None
                handlers = [NoRedirect()]
                if secure:
                    import ssl
                    handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
                opener = urllib.request.build_opener(*handlers)
                rq = urllib.request.Request(
                    f"{scheme}://{ip}:{port}/",
                    headers={"User-Agent": f"NetworkRadar/{APP_VERSION}",
                             "Accept": "text/html,application/json,*/*", "Connection": "close"})
                try:
                    with opener.open(rq, timeout=timeout) as r:
                        raw = r.read(32768).decode("utf-8", "replace")
                        item["server"] = _clean(r.headers.get("Server", ""), 180)
                        item["http_status"] = int(getattr(r, "status", 200))
                        item["content_type"] = _clean(r.headers.get("Content-Type", ""), 100)
                        item["www_authenticate"] = _clean(r.headers.get("WWW-Authenticate", ""), 180)
                        item["powered_by"] = _clean(r.headers.get("X-Powered-By", ""), 120)
                        m = re.search(r"<title[^>]*>(.*?)</title", raw, re.I | re.S)
                        if m:
                            item["http_title"] = _clean(re.sub(r"<[^>]+>", " ", m.group(1)), 180)
                        # JSON/API landing pages can expose a product name without parsing arbitrary content.
                        if "json" in item["content_type"].lower():
                            try:
                                obj = json.loads(raw[:16000])
                                if isinstance(obj, dict):
                                    for key in ("name", "product", "model", "manufacturer", "deviceName"):
                                        if isinstance(obj.get(key), (str, int, float)):
                                            item["api_identity"] = _clean(str(obj[key]), 160)
                                            break
                            except Exception:
                                pass
                except Exception as exc:
                    item["probe_note"] = _clean(exc, 120)
                item["scheme"] = scheme
            elif port == 22:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    try:
                        banner = sock.recv(512).decode("utf-8", "replace").strip()
                    except Exception:
                        banner = ""
                    if banner:
                        item["banner"] = _clean(banner, 180)
            elif port == 445:
                item["banner"] = "SMB service exposed; detailed dialect/OS requires protocol negotiation"
            elif port == 9100:
                item["banner"] = "Raw printer service candidate; no payload sent"
            if len(item) > 2:
                out.append(item)
        except Exception as exc:
            item["probe_error"] = _clean(exc, 120)
            if len(item) > 2:
                out.append(item)
    return out

def enrich_devices(devices, deep=False, mdns_rows=None):
    arp = read_arp_cache()
    local = local_identity()
    with NET_LOCK:
        gateway_ip = NET_CTX.get("gateway", "")
    for dev in devices:
        dev["_local_identity"] = local
        dev["_is_gateway"] = bool(gateway_ip and dev.get("ip") == gateway_ip)
        if dev.get("mac") in ("", "Unavailable") and dev["ip"] in arp:
            dev["mac"] = arp[dev["ip"]]
            dev.setdefault("_extra", []).append(("ARP cache", dev["mac"], 70))
    ssdp = {}
    try:
        ssdp = ssdp_scan(timeout=2.0)
    except Exception:
        pass
    mdns_by_ip = defaultdict(list)
    for item in (mdns_rows or []):
        if item.get("ip") and item.get("records"):
            mdns_by_ip[item["ip"]].append(item["records"])
    if deep:
        deep_fingerprint(devices)
    passive_tcp = {"status": "NOT_RUN", "devices": {}, "detail": "Deep discovery not requested."}
    if deep and is_authorized():
        passive_tcp = passive_tcp_fingerprint_snapshot(duration=4)
    for dev in devices:
        if dev.get("ip") in passive_tcp.get("devices", {}):
            dev["passive_tcp"] = passive_tcp["devices"][dev["ip"]]
    l2_by_mac = {}
    try:
        if deep:
            for item in collect_lldp_cdp(duration=2):
                lm = _normalise_mac(item.get("mac", ""))
                if lm:
                    l2_by_mac[lm] = item
    except Exception:
        pass
    for dev in devices:
        lm = _normalise_mac(dev.get("mac", ""))
        if lm and lm in l2_by_mac:
            dev["lldp_cdp"] = l2_by_mac[lm]
    obs_by_ip = {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        fs = {pool.submit(identify_device, dev, ssdp.get(dev["ip"], {}), False): dev
              for dev in devices}
        for fut in as_completed(fs):
            dev = fs[fut]
            try:
                obs_by_ip[dev["ip"]] = fut.result()
            except Exception as e:
                obs_by_ip[dev["ip"]] = [("Error", _clean(e, 160), 0)]
    for dev in devices:
        try:
            dev["tls_intel"] = tls_certificate_intelligence(dev["ip"], dev.get("port_numbers", []))
            dev["snmp_intel"] = snmpv3_intelligence(dev["ip"])
            dev["service_intel"] = (service_banner_intelligence(dev["ip"], dev.get("port_numbers", []))
                                    if deep else [])
            dev["mdns_records"] = " | ".join(mdns_by_ip.get(dev["ip"], []))[:500]
            dev["ssdp_intel"] = ssdp.get(dev["ip"], {})
            if dev.get("lldp_cdp"):
                dev["lldp_cdp_records"] = json.dumps(dev["lldp_cdp"], sort_keys=True)
            identity_fusion(dev, ssdp.get(dev["ip"], {}),
                            mdns_records=dev["mdns_records"])
            advanced_device_recognition(dev)
            if passive_tcp.get("status") not in ("NOT_RUN", "OBSERVED"):
                dev.setdefault("recognition", {}).setdefault("collection_notes", []).append(
                    "Passive TCP fingerprint: " + passive_tcp.get("status", "UNKNOWN") +
                    " — " + passive_tcp.get("detail", ""))
        except Exception as exc:
            dev["identity_engine_error"] = _clean(exc, 160)
    for dev in devices:
        dev["identity_assessments"] = assess_identity_evidence(dev, dev.get("identity_evidence", []))

    def _w(conn):
        ts = now_text()
        for dev in devices:
            ip = dev["ip"]
            prior = conn.execute(
                "SELECT hostname,manufacturer,device_type,os_guess,model FROM devices WHERE ip=?",
                (ip,)).fetchone()
            conn.execute("""UPDATE devices SET
                mac=CASE WHEN ? IN ('','Unavailable') THEN mac ELSE ? END,
                hostname=CASE WHEN ? IN ('','-','Unknown') THEN hostname ELSE ? END,
                manufacturer=CASE WHEN ? IN ('','Unknown') THEN manufacturer ELSE ? END,
                device_name=CASE WHEN ?='' OR ? LIKE 'Unidentified device at %'
                    THEN COALESCE(NULLIF(device_name,''),?) ELSE ? END,
                friendly_name=CASE WHEN ?='' THEN friendly_name ELSE ? END,
                device_type=CASE WHEN ? IN ('','Unclassified network device')
                    THEN device_type ELSE ? END,
                os_guess=CASE WHEN ? IN ('','Unknown','Not yet fingerprinted')
                    THEN os_guess ELSE ? END,
                model=CASE WHEN ?='' THEN model ELSE ? END,
                identification_confidence=MAX(identification_confidence,?),
                identification_methods=CASE WHEN ?='' THEN identification_methods ELSE ? END,
                open_ports=CASE WHEN ? IN ('','Not fingerprinted','No common TCP ports found')
                    THEN open_ports ELSE ? END,
                service_summary=CASE WHEN ?='' THEN service_summary ELSE ? END,
                last_identified=? WHERE ip=?""",
                (dev.get("mac", ""), dev.get("mac", ""),
                 dev.get("hostname", ""), dev.get("hostname", ""),
                 dev.get("vendor", ""), dev.get("vendor", ""),
                 dev.get("device_name", ""), dev.get("device_name", ""),
                 dev.get("device_name", f"Unidentified device at {ip}"),
                 dev.get("device_name", f"Unidentified device at {ip}"),
                 dev.get("friendly_name", ""), dev.get("friendly_name", ""),
                 dev.get("device_type", ""), dev.get("device_type", ""),
                 dev.get("os_guess", ""), dev.get("os_guess", ""),
                 dev.get("model", ""), dev.get("model", ""),
                 dev.get("identification_confidence", 0),
                 dev.get("identification_methods", ""),
                 dev.get("identification_methods", ""),
                 dev.get("open_ports", ""), dev.get("open_ports", ""),
                 dev.get("service_summary", ""), dev.get("service_summary", ""),
                 ts, ip))
            conn.execute("""UPDATE devices SET oui_manufacturer=?,reported_manufacturer=?,
                identity_conflicts=?,identity_category_confidence=?,identity_last_assessed=?,
                recognition_json=? WHERE ip=?""",
                (dev.get("oui_manufacturer", ""), dev.get("reported_manufacturer", ""),
                 json.dumps(dev.get("identity_conflicts", [])),
                 dev.get("identity_category_confidence", 0), ts,
                 json.dumps(dev.get("recognition", {}), ensure_ascii=False), ip))
            if prior:
                current_values = [dev.get("hostname", ""), dev.get("vendor", ""),
                                  dev.get("device_type", ""), dev.get("os_guess", ""),
                                  dev.get("model", "")]
                for attr, old_value, new_value in zip(
                        ("hostname", "manufacturer", "device_type", "os_guess", "model"),
                        prior, current_values):
                    old_value, new_value = str(old_value or ""), str(new_value or "")
                    if (new_value and new_value not in
                            ("Unknown", "Not yet fingerprinted", "Unclassified network device")
                            and old_value != new_value):
                        conn.execute("""INSERT INTO device_identity_history(device_id,ip,timestamp,attribute,old_value,new_value,reason)
                            VALUES(?,?,?,?,?,?,?)""",
                            (dev.get("device_id", ""), ip, ts, attr, old_value,
                             new_value, "New discovery evidence"))
            persist_identity(conn, dev, ts)
            combined = list(obs_by_ip.get(ip, []))
            combined.extend(dev.get("_extra", []))
            for method, obs, conf in combined:
                if obs:
                    conn.execute("INSERT INTO device_observations(timestamp, ip, "
                                 "method, observation, confidence) VALUES (?, ?, ?, ?, ?)",
                                 (ts, ip, method, obs, conf))
            for src, attr, val, conf, cls in dev.get("identity_evidence", []):
                _add_identity_evidence(conn, dev, src, attr, val, conf, cls, APP_VERSION)
            persist_identity_assessments(conn, dev, dev.get("identity_assessments", []), ts)
            record_event(conn, ip, "DEVICE_FINGERPRINTED",
                         f"{dev.get('device_name')} | {dev.get('device_type')} | "
                         f"{dev.get('identification_confidence')}%",
                         category="discovery", severity="INFO",
                         device_id=dev.get("device_id", ""))
    DB_MANAGER.write(_w)
    try:
        persist_identity_evidence(devices)
    except Exception:
        pass
    return devices

def update_inventory(devices):
    # An empty discovery result is not sufficient evidence that every known
    # endpoint went offline (capture/interface failure can produce this).
    if not devices:
        return 0, 0, 0
    ts = now_text()
    curr_ips = {d["ip"] for d in devices}
    new = ret = off = 0
    def _w(conn):
        nonlocal new, ret, off
        prev = {r[0]: r[1] for r in
                conn.execute("SELECT ip, status FROM devices").fetchall()}
        for dev in devices:
            ip = dev["ip"]
            old = prev.get(ip)
            if old is None:
                new += 1
                record_event(conn, ip, "NEW_DEVICE", "First discovery", category="discovery")
            elif old in ("OFFLINE", "SUSPECTED_OFFLINE", "INTERMITTENT"):
                ret += 1
                record_event(conn, ip, "DEVICE_RETURNED",
                             f"Device responding again (previous state: {old}).",
                             category="discovery")
            conn.execute("""INSERT INTO devices(ip, mac, manufacturer, hostname,
                first_seen, last_seen, status) VALUES (?, ?, ?, ?, ?, ?, 'ONLINE')
                ON CONFLICT(ip) DO UPDATE SET
                    mac=CASE WHEN excluded.mac IN ('','Unavailable') THEN devices.mac
                             ELSE excluded.mac END,
                    manufacturer=CASE WHEN excluded.manufacturer IN ('','Unknown')
                             THEN devices.manufacturer ELSE excluded.manufacturer END,
                    hostname=CASE WHEN excluded.hostname IN ('','-','Unknown')
                             THEN devices.hostname ELSE excluded.hostname END,
                    last_seen=excluded.last_seen, status='ONLINE', offline_misses=0""",
                (ip, dev["mac"], dev["vendor"], dev["hostname"], ts, ts))
        for ip, status in prev.items():
            if ip not in curr_ips and status in ("ONLINE", "SUSPECTED_OFFLINE", "INTERMITTENT"):
                row = conn.execute("SELECT COALESCE(offline_misses,0) FROM devices WHERE ip=?",
                                   (ip,)).fetchone()
                misses = int(row[0] or 0) + 1 if row else 1
                if misses < DEVICE_OFFLINE_CONFIRM_SCANS:
                    conn.execute("UPDATE devices SET offline_misses=?, status='SUSPECTED_OFFLINE' WHERE ip=?",
                                 (misses, ip))
                    if status == "ONLINE":
                        record_event(conn, ip, "DEVICE_SUSPECTED_OFFLINE",
                                     f"Missed {misses} completed scan(s); device is not yet declared offline.",
                                     category="discovery")
                elif misses >= DEVICE_OFFLINE_CONFIRM_SCANS:
                    off += 1
                    conn.execute("UPDATE devices SET offline_misses=?, status='OFFLINE' WHERE ip=?",
                                 (misses, ip))
                    if status != "OFFLINE":
                        record_event(conn, ip, "DEVICE_OFFLINE",
                                     f"Device absent from {misses} consecutive completed scans.",
                                     category="discovery")
    DB_MANAGER.write(_w)
    return new, ret, off

def audit_arp_cache():
    try:
        bindings = read_arp_cache()
    except Exception:
        return 0
    confirmed = 0
    def _w(conn):
        nonlocal confirmed
        for ip, mac in bindings.items():
            result = observe_arp_binding(conn, ip, mac, source="ARP cache")
            if result == "CONFIRMED":
                confirmed += 1
    DB_MANAGER.write(_w)
    return confirmed

# ============================================================
# EVENTS + ALERTS + THREAT MATCHING
# ============================================================

def record_event(conn, ip, event_type, details, category="general",
                 severity="INFO", device_id=""):
    conn.execute("""INSERT INTO network_events(timestamp, ip, device_id,
        category, event_type, severity, details) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (now_text(), ip or "-", device_id or "", category, event_type,
         severity, details[:1000]))

def record_alert(conn, source, rule_id, severity, title, details,
                 ip="", device_id="", confidence=50, dedup_extra=""):
    key = f"{source}:{rule_id}:{device_id or ip}:{dedup_extra}"
    now = now_text()
    cutoff = (datetime.now() - timedelta(seconds=ALERTS_DEDUP_WINDOW_SECONDS)
              ).strftime("%Y-%m-%d %H:%M:%S")
    row = conn.execute("SELECT id, severity, confidence, occurrence_count "
                       "FROM alerts WHERE dedup_key=? AND last_seen>=? "
                       "ORDER BY id DESC LIMIT 1", (key, cutoff)).fetchone()
    if row:
        aid, old_sev, old_conf, count = row
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        peak = severity if rank.get(severity, 0) > rank.get(old_sev, 0) else old_sev
        conn.execute("""UPDATE alerts SET last_seen=?, occurrence_count=?,
            severity=?, confidence=MAX(confidence,?), title=?, details=?
            WHERE id=?""", (now, int(count or 1) + 1, peak,
                              int(confidence or 0), title, details[:2000], aid))
        return aid, False
    cur = conn.execute("""INSERT INTO alerts(timestamp, device_id, ip, source,
        rule_id, severity, confidence, title, details, dedup_key,
        first_seen, last_seen, occurrence_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
        (now, device_id or "", ip or "", source, rule_id, severity,
         confidence, title, details[:2000], key, now, now))
    return cur.lastrowid, True

def observe_arp_binding(conn, ip, mac, source="arp"):
    try:
        ip_obj = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return "INVALID"
    if ip_obj.is_unspecified:
        # RFC 5227 address-conflict detection commonly uses 0.0.0.0 as the
        # sender protocol address. It must never become a persistent binding.
        return "PROBE"
    if ip_obj.is_multicast or ip_obj.is_loopback:
        return "INVALID"
    mac = str(mac or "").strip().upper().replace("-", ":")
    if not valid_unicast_mac(mac):
        return "INVALID"
    now_dt = datetime.now()
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    row = conn.execute("SELECT mac, candidate_mac, candidate_count, "
                       "candidate_first_seen FROM arp_bindings WHERE ip=?",
                       (str(ip_obj),)).fetchone()
    if not row:
        conn.execute("INSERT INTO arp_bindings(ip,mac,first_seen,last_seen) VALUES(?,?,?,?)",
                     (str(ip_obj), mac, now, now))
        return "BASELINE"
    current, candidate, count, first_seen = row
    if current == mac:
        conn.execute("UPDATE arp_bindings SET last_seen=?, candidate_mac='', "
                     "candidate_count=0, candidate_first_seen='', candidate_last_seen='' WHERE ip=?",
                     (now, str(ip_obj)))
        return "STABLE"
    if candidate == mac and first_seen:
        try:
            age = (now_dt - datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")).total_seconds()
        except ValueError:
            age = 9999
        count = int(count or 0) + 1 if 0 <= age <= 60 else 1
    else:
        count = 1
    if count < 2:
        conn.execute("""UPDATE arp_bindings SET candidate_mac=?, candidate_count=?,
            candidate_first_seen=?, candidate_last_seen=? WHERE ip=?""",
            (mac, count, now, now, str(ip_obj)))
        return "CANDIDATE"
    old = current
    conn.execute("""UPDATE arp_bindings SET mac=?, last_seen=?,
        change_count=change_count+1, candidate_mac='', candidate_count=0,
        candidate_first_seen='', candidate_last_seen='' WHERE ip=?""",
        (mac, now, str(ip_obj)))
    details = (f"Repeated {source} observations confirmed mapping change for "
               f"{ip_obj}: {old} → {mac}. This may be legitimate (DHCP, "
               "adapter replacement or failover); it is not proof of spoofing.")
    conn.execute("""INSERT INTO network_security_events(timestamp,event_type,
        severity,ip,old_value,new_value,details) VALUES(?,?,?,?,?,?,?)""",
        (now, "ARP_MAPPING_CHANGED", "MEDIUM", str(ip_obj), old, mac, details))
    record_event(conn, str(ip_obj), "ARP_MAPPING_CHANGED", details,
                 category="arp", severity="MEDIUM")
    record_alert(conn, "arp", "ARP_MAPPING_CHANGED", "MEDIUM",
                 "ARP mapping change confirmed", details, ip=str(ip_obj), confidence=65)
    return "CONFIRMED"

def match_threats(conn, domain="", observed_ip="", client_ip="",
                  source_event_id=None):
    domain = norm_domain(domain)
    now = now_text()
    rows = conn.execute("""SELECT id, indicator_type, indicator_value, severity,
        confidence, description, expires_at FROM threat_indicators
        WHERE expires_at='' OR expires_at>?""", (now,)).fetchall()
    matched_ids = []
    for (iid, itype, val, sev, conf, desc, _exp) in rows:
        kind = None
        if itype == "DOMAIN" and domain:
            if domain == val:
                kind = "exact"
            elif domain.endswith("." + val):
                kind = "suffix"
        elif itype == "IP" and observed_ip:
            if observed_ip == val:
                kind = "ip"
        if not kind:
            continue
        dedup_field = domain if itype == "DOMAIN" else observed_ip
        existing = conn.execute("""SELECT 1 FROM threat_matches WHERE
            indicator_id=? AND domain=? AND client_ip=?
            AND timestamp >= datetime('now','-1 day')""",
            (iid, dedup_field, client_ip)).fetchone()
        if existing:
            continue
        detail = (f"{kind} match on indicator {val}. "
                  f"Match, not proof of compromise.")
        conn.execute("""INSERT INTO threat_matches(timestamp, indicator_id,
            domain, client_ip, source_event_id, details)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (now, iid, dedup_field, client_ip, source_event_id, detail))
        record_event(conn, client_ip, "THREAT_MATCH", detail,
                     category="threat_intel", severity=sev)
        record_alert(conn, "threat", "IOC_MATCH", sev,
                     f"Threat match: {val}", detail, ip=client_ip,
                     confidence=conf or 60, dedup_extra=f"{val}:{kind}")
        matched_ids.append(iid)
    return matched_ids

# ============================================================
# CAPTURE ENGINES
# ============================================================

def _select_tshark_interface(interfaces, *, preferred="", primary_guid="",
                             primary_name="", primary_description=""):
    """Prefer the exact active Windows adapter, not the first Wi-Fi-looking device."""
    if preferred:
        pref = str(preferred).strip().strip('"')
        for idx, desc in interfaces:
            if pref.casefold() == str(idx).casefold() or pref.casefold() in str(desc).casefold():
                return str(idx)
        if pref.startswith(r"\Device\NPF_"):
            return pref
        raise RuntimeError(
            "Configured NETWORKRADAR_TSHARK_INTERFACE was not found by TShark -D: "
            + pref[:160]
        )

    guid_raw = str(primary_guid or "").strip().strip("{}").replace("-", "").casefold()
    guid = guid_raw if re.fullmatch(r"[0-9a-f]{32}", guid_raw) else ""
    if guid:
        for idx, desc in interfaces:
            desc_guid = re.sub(r"[^0-9a-f]", "", str(desc).casefold())
            if guid in desc_guid:
                return str(idx)

    names = [
        str(x).strip().casefold()
        for x in (primary_name, primary_description)
        if str(x or "").strip()
        and str(x).strip().casefold() not in {"manual override", "no active adapter"}
    ]
    for name in names:
        for idx, desc in interfaces:
            if name in str(desc).casefold():
                return str(idx)

    if names:
        raise RuntimeError(
            "The active Windows network adapter was not found in TShark -D. "
            "Set NETWORKRADAR_TSHARK_INTERFACE to the correct TShark interface; "
            "NetworkRadar will not silently capture another adapter."
        )

    wifi = [(idx, desc) for idx, desc in interfaces
            if re.search(r"\b(wi[ -]?fi|wireless|802\.11)\b", desc, re.IGNORECASE)
            and not re.search(r"loopback|virtualbox|vmware", desc, re.IGNORECASE)]
    if wifi:
        return str(wifi[0][0])
    ethernet = [(idx, desc) for idx, desc in interfaces
                if re.search(r"\bethernet\b", desc, re.IGNORECASE)
                and not re.search(r"loopback|virtualbox|vmware", desc, re.IGNORECASE)]
    if ethernet:
        return str(ethernet[0][0])
    physical = [(idx, desc) for idx, desc in interfaces
                if not re.search(r"loopback|virtualbox|vmware|bluetooth|npcap loopback", desc, re.IGNORECASE)]
    if physical:
        return str(physical[0][0])
    raise RuntimeError(
        "No usable TShark interface found. Check Npcap and set NETWORKRADAR_TSHARK_INTERFACE."
    )


def choose_iface():
    """Select a real TShark interface; prefer the active Wi-Fi adapter.

    NETWORKRADAR_TSHARK_INTERFACE accepts a TShark interface number or a
    case-insensitive substring of its displayed name. If the configured value
    is a native Npcap device path not shown by `tshark -D`, it is passed through.
    """
    r = subprocess.run([str(TSHARK), "-D"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=15)
    if r.returncode != 0:
        detail = re.sub(r"\s+", " ", (r.stderr or r.stdout or "")).strip()[-500:]
        raise RuntimeError(f"TShark interface enumeration failed (exit={r.returncode}): {detail}")
    interfaces = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*(\d+)\.\s*(.*)", line)
        if m:
            interfaces.append((m.group(1), m.group(2).strip()))
    with NET_LOCK:
        primary = dict(NET_CTX)
    return _select_tshark_interface(
        interfaces,
        preferred=PREFERRED_INTERFACE,
        primary_guid=primary.get("interface_guid", ""),
        primary_name=primary.get("interface", ""),
        primary_description=primary.get("interface_description", ""),
    )

def domain_heuristics(domain):
    return []

def repair_dns_domain_classification():
    def _w(conn):
        conn.execute("""UPDATE domain_intel SET risk_score=0,risk_level='INFO'
            WHERE lower(domain) LIKE '%.in-addr.arpa'
               OR lower(domain) LIKE '%.ip6.arpa'
               OR lower(domain) LIKE '%.local'
               OR lower(domain) LIKE '_%._tcp.local'
               OR lower(domain) LIKE '_%._udp.local'""")
    try:
        DB_MANAGER.write(_w)
    except Exception:
        pass

class DNSEngine(threading.Thread):
    def __init__(self):
        super().__init__(name="NR-DNS", daemon=True)
        self.proc = None
        self.iface = "Not selected"
        self.pending = {}
        self.qwin = defaultdict(deque)
        self.q5win = defaultdict(deque)
        self.nxwin = defaultdict(deque)
        self.nx_domains = defaultdict(deque)
        self.tunnel_windows = defaultdict(deque)
        self.cool = {}

    def state(self, **kw):
        with DNS_STATE_LOCK:
            DNS_STATE.update(kw)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=4)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

    def run(self):
        while not STOP_EVENT.is_set():
            try:
                self.iface = choose_iface()
                self.state(status="ONLINE", interface=self.iface, error="")
                self.capture()
                if not STOP_EVENT.is_set():
                    self.state(status="RESTARTING", error="Capture ended; restarting")
                    STOP_EVENT.wait(5)
            except Exception as e:
                self.state(status="DEGRADED", error=str(e))
                STOP_EVENT.wait(10)

    def capture(self):
        fields = ["frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                  "dns.id", "dns.flags.response", "dns.flags.rcode",
                  "dns.qry.name", "dns.qry.type", "dns.time",
                  "dns.a", "dns.aaaa", "dns.cname", "udp.srcport", "udp.dstport"]
        cmd = [str(TSHARK), "-l", "-n", "-i", self.iface,
               "-f", DNS_CAPTURE_FILTER, "-T", "fields",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        for f in fields:
            cmd.extend(["-e", f])
        with open(DNS_LOG, "a", encoding="utf-8", errors="replace") as log:
            log.write(f"\n[{now_text()}] DNS on {self.iface}\n")
            log.flush()
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=log,
                                         text=True, encoding="utf-8",
                                         errors="replace", bufsize=1)
            time.sleep(0.15)
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"TShark DNS capture exited immediately "
                    f"(code={self.proc.returncode}); inspect {DNS_LOG}")
            self.state(status="ONLINE", error="", last_started=now_text())
            try:
                for line in self.proc.stdout:
                    if STOP_EVENT.is_set():
                        break
                    self.handle(line)
                if not STOP_EVENT.is_set():
                    code = self.proc.poll()
                    try:
                        tail = DNS_LOG.read_text(encoding="utf-8", errors="replace")[-1000:]
                    except Exception:
                        tail = ""
                    raise RuntimeError(f"TShark DNS capture exited (code={code}); {tail[-600:]}")
            finally:
                if self.proc and self.proc.poll() is None:
                    try:
                        self.proc.terminate()
                        self.proc.wait(timeout=3)
                    except Exception:
                        try:
                            self.proc.kill()
                            self.proc.wait(timeout=2)
                        except Exception:
                            pass
                self.proc = None

    def handle(self, line):
        try:
            row = next(csv.reader([line.rstrip("\r\n")], delimiter="\t", quotechar='"'))
            row += [""] * (16 - len(row))
            (epoch, s4, s6, d4, d6, did, is_resp, rcode, domain, qtype,
             _t, aa, aaaa, cn, sp, dp) = row[:16]
            domain = norm_domain(domain)
            if not domain:
                return
            src = s4 or s6
            dst = d4 or d6
            if not src or not dst:
                return
            ts = (datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
                  if epoch else now_text())
            resp = is_resp.strip().lower() in {"1", "true", "yes"}
            qt = DNS_TYPE_NAMES.get(qtype.strip(), f"TYPE{qtype}" if qtype else "UNKNOWN")
            svc_port = sp or dp
            if svc_port == "5353":
                qt = "mDNS/" + qt
            elif svc_port == "5355":
                qt = "LLMNR/" + qt
            name_class = classify_name_resolution(domain, qt, src, dst)
            answers = "; ".join(v for v in (aa, aaaa, cn) if v)
            if resp:
                cli, resol = dst, src
                key = (did, domain, resol)
                pending = self.pending.pop(key, None)
                rt = None
                if pending:
                    cli = pending["client"]
                    rt = round((time.monotonic() - pending["t"]) * 1000, 2)
                rc = DNS_RCODE_NAMES.get(rcode.strip(),
                                         f"RCODE{rcode}" if rcode else "UNKNOWN")
                self.store(ts, cli, resol, domain, qt, 1, rc, rt, answers, name_class)
                if rc == "NXDOMAIN" and name_class == "UNICAST_DNS":
                    self.track_nx(cli, domain)
                return
            cli, resol = src, dst
            self.pending[(did, domain, resol)] = {"client": cli, "t": time.monotonic()}
            cutoff = time.monotonic() - 15
            self.pending = {k: v for k, v in self.pending.items() if v["t"] >= cutoff}
            self.store(ts, cli, resol, domain, qt, 0, "", None, "", name_class)
            if name_class == "UNICAST_DNS":
                self.track_rate(cli)
                self.inspect(cli, domain)
        except Exception as e:
            self.state(error=f"DNS parse: {e}")

    def store(self, ts, cli, resol, domain, qt, is_resp, rc, rt, answers,
              name_class="UNICAST_DNS"):
        is_new = False
        event_id = None
        def _w(conn):
            nonlocal is_new, event_id
            existing = (conn.execute("SELECT domain FROM domain_intel WHERE domain=?",
                                     (domain,)).fetchone()
                        if name_class == "UNICAST_DNS" else None)
            if not is_resp and name_class == "UNICAST_DNS":
                is_new = existing is None
                conn.execute("""INSERT INTO domain_intel(domain, first_seen,
                    last_seen, query_count, unique_clients, last_response_code,
                    risk_score, risk_level) VALUES (?, ?, ?, 1, 1, '', 0, 'INFO')
                    ON CONFLICT(domain) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        query_count=domain_intel.query_count+1""",
                    (domain, ts, ts))
                conn.execute("""INSERT INTO dns_client_domains(client_ip, domain,
                    first_seen, last_seen, query_count) VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(client_ip, domain) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        query_count=dns_client_domains.query_count+1""",
                    (cli, domain, ts, ts))
                clients = conn.execute("SELECT COUNT(*) FROM dns_client_domains "
                                       "WHERE domain=?", (domain,)).fetchone()[0]
                conn.execute("UPDATE domain_intel SET unique_clients=? WHERE domain=?",
                             (clients, domain))
            elif rc and name_class == "UNICAST_DNS":
                conn.execute("UPDATE domain_intel SET last_response_code=?, "
                             "last_seen=? WHERE domain=?", (rc, ts, domain))
            cur = conn.execute("""INSERT INTO dns_events(timestamp, client_ip,
                resolver_ip, domain, query_type, is_response, response_code,
                response_time, answers, interface) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, cli, resol, domain, qt, is_resp, rc, rt, answers, self.iface))
            event_id = cur.lastrowid
            if is_new:
                record_event(conn, cli, "DNS_NEW_DOMAIN", f"First observed: {domain}",
                             category="dns")
            if not is_resp and domain and name_class == "UNICAST_DNS":
                match_threats(conn, domain=domain, client_ip=cli,
                              source_event_id=event_id)
                if answers:
                    for ip_ans in [a.strip() for a in answers.split(";") if a.strip()]:
                        try:
                            ipaddress.ip_address(ip_ans)
                        except ValueError:
                            continue
                        match_threats(conn, observed_ip=ip_ans, client_ip=cli,
                                      source_event_id=event_id)
        DB_MANAGER.write(_w)
        with DNS_STATE_LOCK:
            if is_resp:
                DNS_STATE["responses"] += 1
            else:
                DNS_STATE["queries"] += 1
            DNS_STATE["last_event"] = f"{cli} → {domain}"

    def fire_alert(self, cli, domain, rule, sev, score, details):
        key = (cli, rule, "" if rule in {"DNS_QUERY_BURST", "DNS_NXDOMAIN_BURST"} else domain)
        now = time.monotonic()
        cooldown = 900 if rule == "DNS_NXDOMAIN_BURST" else 300
        if now - self.cool.get(key, 0) < cooldown:
            return
        self.cool[key] = now
        def _w(conn):
            stamp = now_text()
            cutoff = (datetime.now() - timedelta(seconds=cooldown)).strftime("%Y-%m-%d %H:%M:%S")
            domain_key = domain if rule == "DNS_TUNNEL_INDICATOR" else ""
            prior = conn.execute("""SELECT id, occurrence_count FROM dns_alerts
                WHERE client_ip=? AND rule_id=?
                  AND (CASE WHEN rule_id IN ('DNS_NXDOMAIN_BURST','DNS_QUERY_BURST')
                            THEN '' ELSE COALESCE(domain,'') END)=?
                  AND COALESCE(last_seen,timestamp)>=?
                ORDER BY id DESC LIMIT 1""", (cli, rule, domain_key, cutoff)).fetchone()
            if prior:
                conn.execute("""UPDATE dns_alerts SET last_seen=?, occurrence_count=?,
                    domain=?, severity=?, score=MAX(score,?), details=? WHERE id=?""",
                    (stamp, int(prior[1] or 1) + 1, domain or "", sev, score,
                     details[:1000], prior[0]))
            else:
                conn.execute("""INSERT INTO dns_alerts(timestamp, client_ip, domain,
                    rule_id, severity, score, details, first_seen, last_seen, occurrence_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (stamp, cli, domain, rule, sev, score, details[:1000], stamp, stamp))
            if not prior:
                record_event(conn, cli, "DNS_ALERT", f"{sev} {rule}: {details}",
                             category="dns", severity=sev)
            record_alert(conn, "dns", rule, sev, f"DNS {rule}", details,
                         ip=cli, confidence=score,
                         dedup_extra=(domain or "") if rule == "DNS_TUNNEL_INDICATOR" else "")
            if domain:
                conn.execute("""UPDATE domain_intel SET risk_score=MAX(risk_score,?),
                    risk_level=CASE WHEN MAX(risk_score,?)>=70 THEN 'HIGH'
                        WHEN MAX(risk_score,?)>=35 THEN 'MEDIUM' ELSE 'INFO' END
                    WHERE domain=?""", (score, score, score, domain))
        try:
            DB_MANAGER.write(_w)
        except Exception:
            pass
        with DNS_STATE_LOCK:
            DNS_STATE["alerts"] += 1
            DNS_STATE["last_event"] = f"ALERT {rule} from {cli}"

    def inspect(self, cli, domain):
        for rule, sev, score, details in domain_heuristics(domain):
            self.fire_alert(cli, domain, rule, sev, score, details)
        labels = [x for x in norm_domain(domain).split(".") if x]
        if len(labels) < 3:
            return
        label = labels[0]
        if len(label) < 24 or shannon(label) < 3.2:
            return
        suffix = ".".join(labels[-2:])
        key = (cli, suffix)
        now = time.monotonic()
        window = self.tunnel_windows[key]
        window.append((now, label))
        while window and window[0][0] < now - DNS_TUNNEL_WINDOW_SECONDS:
            window.popleft()
        unique = {item[1] for item in window}
        if len(unique) >= DNS_TUNNEL_MIN_UNIQUE_LABELS:
            self.fire_alert(
                cli, suffix, "DNS_TUNNEL_INDICATOR", "HIGH", 70,
                f"Observed {len(unique)} distinct long, high-entropy labels under {suffix} "
                f"within {DNS_TUNNEL_WINDOW_SECONDS // 60} minutes. This is a heuristic "
                "indicator requiring endpoint/process and resolver corroboration, not "
                "proof of tunnelling.")

    def track_rate(self, cli):
        now = time.monotonic()
        w = self.qwin[cli]
        w.append(now)
        while w and w[0] < now - 60:
            w.popleft()
        q5 = self.q5win[cli]
        q5.append(now)
        while q5 and q5[0] < now - 300:
            q5.popleft()
        if len(w) >= 300:
            self.fire_alert(cli, "", "DNS_QUERY_BURST", "LOW", 25,
                            f"{len(w)} unicast DNS queries in 60s. Correlate with "
                            "domain diversity, endpoint process and resolver evidence.")

    def track_nx(self, cli, domain):
        now = time.monotonic()
        w = self.nxwin[cli]
        w.append(now)
        dw = self.nx_domains[cli]
        dw.append((now, domain))
        cutoff = now - 300
        while w and w[0] < cutoff:
            w.popleft()
        while dw and dw[0][0] < cutoff:
            dw.popleft()
        queries = self.q5win[cli]
        while queries and queries[0] < cutoff:
            queries.popleft()
        total_queries = len(queries)
        ratio = (len(w) / total_queries) if total_queries else 0.0
        unique_domains = len({d for _, d in dw if d})
        # A raw NXDOMAIN count alone is noisy. Require both a meaningful count
        # and a meaningful ratio when query volume is available.
        ratio_ok = total_queries == 0 or ratio >= 0.25
        if len(w) >= 25 and ratio_ok:
            sev, score = ("MEDIUM", 40) if ratio >= 0.60 and len(w) >= 40 else ("LOW", 25)
            self.fire_alert(cli, "", "DNS_NXDOMAIN_BURST", sev, score,
                            f"{len(w)} NXDOMAIN responses among {total_queries} observed "
                            f"queries in 5 min (ratio={ratio:.1%}; "
                            f"unique_failed_names={unique_domains}; latest={domain}). "
                            "This is a triage signal, not proof of compromise; compare "
                            "with application activity, query diversity and endpoint telemetry.")

class DHCPEngine(threading.Thread):
    def __init__(self):
        super().__init__(name="NR-DHCP", daemon=True)
        self.proc = None
        self.iface = "Not selected"
        self.known = set()
        self.cool = {}

    def state(self, **kw):
        with DHCP_STATE_LOCK:
            DHCP_STATE.update(kw)

    def diagnostic_classification(self):
        """D7 fix: distinguish capture failure from no observed traffic."""
        with DHCP_STATE_LOCK:
            s = dict(DHCP_STATE)
        status = s.get("status", "UNKNOWN")
        if status == "FAILED":
            return {"state": "CAPTURE_UNAVAILABLE",
                    "reason": s.get("last_error") or "capture failed"}
        if status == "DEGRADED":
            return {"state": "CAPTURE_DEGRADED",
                    "reason": s.get("last_error") or "capture restarting"}
        if status in ("STARTING", "RESTARTING"):
            return {"state": "CAPTURE_STARTING",
                    "reason": "capture engine is (re)starting"}
        if status in ("ONLINE", "RUNNING"):
            messages = int(s.get("messages", 0))
            if messages == 0:
                return {"state": "TRAFFIC_NOT_OBSERVED",
                        "reason": ("Capture is running but zero DHCP packets have "
                                   "been observed. Possible causes: wrong interface, "
                                   "switched segment, static IPs, or no DHCP "
                                   "activity in observation window.")}
            return {"state": "OBSERVING",
                    "reason": f"{messages} DHCP messages observed"}
        return {"state": "UNKNOWN", "reason": s.get("error") or "state unknown"}

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=4)
            except Exception:
                pass

    def run(self):
        while not STOP_EVENT.is_set():
            try:
                self.state(status="STARTING", error="")
                self.iface = choose_iface()
                if not self.iface:
                    raise RuntimeError("No capture interface selected.")
                self.state(status="RUNNING", interface=self.iface, error="",
                           last_started=now_text())
                self.capture()
                if not STOP_EVENT.is_set():
                    with DHCP_STATE_LOCK:
                        DHCP_STATE["restart_count"] += 1
                        DHCP_STATE["last_exit"] = now_text()
                        DHCP_STATE["status"] = "RESTARTING"
                        DHCP_STATE["error"] = "Capture process ended; retrying."
                    STOP_EVENT.wait(5)
            except Exception as e:
                message = _clean(e, 500)
                with DHCP_STATE_LOCK:
                    DHCP_STATE["restart_count"] += 1
                    DHCP_STATE["failure_streak"] = int(DHCP_STATE.get("failure_streak", 0)) + 1
                    streak = DHCP_STATE["failure_streak"]
                    DHCP_STATE["status"] = "FAILED" if streak >= 3 else "DEGRADED"
                    DHCP_STATE["error"] = message
                    DHCP_STATE["last_error"] = message
                    DHCP_STATE["last_exit"] = now_text()
                if not STOP_EVENT.is_set():
                    STOP_EVENT.wait(min(30, 5 + streak * 5))
        self.state(status="STOPPED", error="")

    def capture(self):
        fields = ["frame.time_epoch", "ip.src", "ip.dst", "dhcp.option.dhcp",
                  "dhcp.hw.mac_addr", "dhcp.ip.your", "dhcp.option.hostname",
                  "dhcp.option.dhcp_server_id", "dhcp.option.requested_ip_address",
                  "dhcp.option.router", "dhcp.option.domain_name_server",
                  "dhcp.option.subnet_mask", "dhcp.option.lease_time",
                  "dhcp.option.vendor_class_id", "dhcp.option.request_list_item",
                  "dhcp.option.client_id"]
        cmd = [str(TSHARK), "-l", "-n", "-i", self.iface,
               "-f", DHCP_CAPTURE_FILTER, "-T", "fields",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        for f in fields:
            cmd.extend(["-e", f])
        with open(DHCP_LOG, "a", encoding="utf-8", errors="replace") as log:
            log.write(f"\n[{now_text()}] DHCP on {self.iface}\n")
            log.flush()
            attempt_offset = log.tell()
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=log,
                                         text=True, encoding="utf-8",
                                         errors="replace", bufsize=1)
            time.sleep(0.15)
            if self.proc.poll() is not None:
                try:
                    with open(DHCP_LOG, "r", encoding="utf-8", errors="replace") as diag:
                        diag.seek(attempt_offset)
                        tail = diag.read()[-1600:]
                except Exception:
                    tail = ""
                tail = re.sub(r"\s+", " ", tail).strip()[-700:]
                with DHCP_STATE_LOCK:
                    DHCP_STATE["last_exit_code"] = self.proc.returncode
                    DHCP_STATE["last_stderr"] = tail[-700:]
                    DHCP_STATE["last_command"] = " ".join(cmd[:12])
                diagnostic = (tail or
                    "No diagnostic output captured. Check Npcap, "
                    "interface selection and capture permissions.")
                raise RuntimeError(
                    f"TShark DHCP startup failed; executable={TSHARK}; "
                    f"interface={self.iface}; exit_code={self.proc.returncode}; "
                    f"stderr={diagnostic}")
            self.state(status="ONLINE", error="", last_error="", failure_streak=0,
                       last_started=now_text())
            try:
                for line in self.proc.stdout:
                    if STOP_EVENT.is_set():
                        break
                    self.handle(line)
                if not STOP_EVENT.is_set():
                    try:
                        code = self.proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.proc.terminate()
                        try:
                            code = self.proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            self.proc.kill()
                            code = self.proc.wait(timeout=2)
                    try:
                        with open(DHCP_LOG, "r", encoding="utf-8", errors="replace") as diag:
                            diag.seek(attempt_offset)
                            tail = diag.read()[-1200:]
                    except Exception:
                        tail = ""
                    tail = re.sub(r"\s+", " ", tail).strip()
                    detail = tail[-700:] if tail else "No stderr captured. Check Npcap, interface selection, capture permissions and filter validity."
                    if code is None:
                        code = self.proc.returncode if self.proc else "unknown"
                    with DHCP_STATE_LOCK:
                        DHCP_STATE["last_exit_code"] = code
                        DHCP_STATE["last_stderr"] = detail[-700:]
                        DHCP_STATE["last_command"] = " ".join(cmd[:12])
                    raise RuntimeError(f"TShark DHCP capture exited; executable={TSHARK}; exit_code={code}; interface={self.iface}; filter={DHCP_CAPTURE_FILTER}; stderr={detail}")
            finally:
                if self.proc and self.proc.poll() is None:
                    try:
                        self.proc.terminate()
                        self.proc.wait(timeout=3)
                    except Exception:
                        try:
                            self.proc.kill()
                            self.proc.wait(timeout=2)
                        except Exception:
                            pass
                self.proc = None

    def handle(self, line):
        try:
            row = next(csv.reader([line.rstrip("\r\n")], delimiter="\t", quotechar='"'))
            row += [""] * (16 - len(row))
            (epoch, sip, dip, mt, cmac, yip, hn, sid, rip, ro, do,
             sm, lease, vc, prl, client_id) = row[:16]
            if not cmac:
                return
            ts = (datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
                  if epoch else now_text())
            mtname = DHCP_TYPE_NAMES.get(mt.strip(), f"TYPE{mt}" if mt else "UNKNOWN")
            cmac = cmac.upper()
            rogue = 0
            if mtname == "OFFER" and sid:
                rogue = self.detect_rogue(sid)
            elif mtname == "ACK" and sid:
                self.known.add(sid)
            def _w(conn):
                conn.execute("""INSERT INTO dhcp_events(timestamp, msg_type,
                    client_mac, client_ip, server_ip, requested_ip, hostname,
                    vendor_class, router_opt, dns_opt, subnet_mask, lease_seconds,
                    network, interface, is_rogue, details, parameter_request_list,
                    client_identifier, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ts, mtname, cmac, yip or "", sid or sip, rip or "",
                     hn or "", vc or "", ro or "", do or "", sm or "",
                     int(lease) if lease.isdigit() else None,
                     current_network(), self.iface, rogue,
                     f"src={sip} dst={dip}", _clean(prl, 300),
                     _clean(client_id, 160), dhcp_fingerprint(vc, prl)))
                record_event(conn, yip or sip or cmac, f"DHCP_{mtname}",
                             f"MAC={cmac} host={hn or '-'} server={sid or sip or '-'}",
                             category="dhcp",
                             severity="HIGH" if rogue else "INFO")
                if rogue:
                    record_alert(conn, "dhcp", "ROGUE_DHCP_OFFER", "HIGH",
                                 "DHCP from unexpected server",
                                 f"server={sid} client={cmac}",
                                 ip=yip or "", confidence=60)
            DB_MANAGER.write(_w)
            with DHCP_STATE_LOCK:
                DHCP_STATE["messages"] += 1
                if mtname == "OFFER":
                    DHCP_STATE["offers"] += 1
                elif mtname == "ACK":
                    DHCP_STATE["acks"] += 1
                if rogue:
                    DHCP_STATE["rogue"] += 1
                DHCP_STATE["last_event"] = f"{mtname} from {cmac}"
        except Exception as e:
            self.state(error=f"DHCP parse: {e}")

    def detect_rogue(self, sid):
        with NET_LOCK:
            gw = NET_CTX.get("gateway", "")
        if not sid or sid == gw or sid in self.known:
            return 0
        key = ("rogue", sid)
        now = time.monotonic()
        if now - self.cool.get(key, 0) < 600:
            return 1
        self.cool[key] = now
        return 1

class ARPEngine(threading.Thread):
    def __init__(self):
        super().__init__(name="NR-ARP", daemon=True)
        self.proc = None
        self.iface = "Not selected"
        self.last_mac = {}

    def state(self, **kw):
        with ARP_STATE_LOCK:
            ARP_STATE.update(kw)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=4)
            except Exception:
                pass

    def run(self):
        while not STOP_EVENT.is_set():
            try:
                self.iface = choose_iface()
                self.state(status="ONLINE", interface=self.iface, error="")
                self.capture()
                if not STOP_EVENT.is_set():
                    self.state(status="RESTARTING", error="ARP ended; restarting")
                    STOP_EVENT.wait(5)
            except Exception as e:
                self.state(status="DEGRADED", error=str(e))
                STOP_EVENT.wait(10)

    def capture(self):
        fields = ["frame.time_epoch", "arp.opcode", "arp.src.hw_mac",
                  "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4"]
        cmd = [str(TSHARK), "-l", "-n", "-i", self.iface,
               "-f", ARP_CAPTURE_FILTER, "-T", "fields",
               "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
        for f in fields:
            cmd.extend(["-e", f])
        with open(ARP_LOG, "a", encoding="utf-8", errors="replace") as log:
            log.write(f"\n[{now_text()}] ARP on {self.iface}\n")
            log.flush()
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=log,
                                         text=True, encoding="utf-8",
                                         errors="replace", bufsize=1)
            time.sleep(0.15)
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"TShark ARP capture exited immediately "
                    f"(code={self.proc.returncode}); inspect {ARP_LOG}")
            self.state(status="ONLINE", error="", last_started=now_text())
            try:
                for line in self.proc.stdout:
                    if STOP_EVENT.is_set():
                        break
                    self.handle(line)
                if not STOP_EVENT.is_set():
                    code = self.proc.poll()
                    try:
                        tail = ARP_LOG.read_text(encoding="utf-8", errors="replace")[-1000:]
                    except Exception:
                        tail = ""
                    raise RuntimeError(f"TShark ARP capture exited (code={code}); {tail[-600:]}")
            finally:
                if self.proc and self.proc.poll() is None:
                    try:
                        self.proc.terminate()
                        self.proc.wait(timeout=3)
                    except Exception:
                        try:
                            self.proc.kill()
                            self.proc.wait(timeout=2)
                        except Exception:
                            pass
                self.proc = None

    def handle(self, line):
        try:
            row = next(csv.reader([line.rstrip("\r\n")], delimiter="\t", quotechar='"'))
            row += [""] * (6 - len(row))
            epoch, op, smac, sip, dmac, dip = row[:6]
            if not smac or not sip:
                return
            ts = (datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S")
                  if epoch else now_text())
            opname = ("REQUEST" if op.strip() == "1"
                      else "REPLY" if op.strip() == "2" else f"OP{op}")
            grat = 1 if (sip == dip or dip in ("0.0.0.0", "")) else 0
            self.last_mac[sip] = smac.upper()
            def _w(conn):
                mapping_state = observe_arp_binding(conn, sip, smac, source="passive ARP")
                conn.execute("""INSERT INTO arp_observations(timestamp, opcode,
                    sender_mac, sender_ip, target_mac, target_ip, interface,
                    is_gratuitous, change_type, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ts, opname, smac.upper(), sip,
                     dmac.upper() if dmac else "", dip, self.iface, grat,
                     mapping_state if mapping_state in ("CANDIDATE", "CONFIRMED", "PROBE") else "",
                     ""))
                return mapping_state
            mapping_state = DB_MANAGER.write(_w)
            change = mapping_state == "CONFIRMED"
            with ARP_STATE_LOCK:
                ARP_STATE["observations"] += 1
                if grat:
                    ARP_STATE["gratuitous"] += 1
                if change:
                    ARP_STATE["changes"] += 1
                ARP_STATE["last_event"] = f"{opname} {sip} → {smac}"
        except Exception as e:
            self.state(error=f"ARP parse: {e}")
# ============================================================
# PHANTOM TRACK 2.0 — weighted identity matching + presence
# ============================================================

PHANTOM_OUTCOMES = ("CONFIRMED_MATCH", "STRONG_MATCH", "POSSIBLE_MATCH",
                    "WEAK_MATCH", "CONFLICTING_IDENTITY", "NEW_IDENTITY", "UNKNOWN")
PHANTOM_THRESHOLDS = {"CONFIRMED_MATCH": 0.85, "STRONG_MATCH": 0.70,
                      "POSSIBLE_MATCH": 0.50, "WEAK_MATCH": 0.30}
PHANTOM_HALF_LIFE_DAYS = 30.0
PHANTOM_GROUP_CAP = 0.45
PHANTOM_AUTO_MERGE = {"CONFIRMED_MATCH"}
PHANTOM_CONFLICT_KINDS = {"hostname", "client_id", "oui_global"}
PHANTOM_LOCAL_GROUP = "oui_local"

def _phantom_freshness(observed_at, now):
    days = max(0.0, (now - observed_at).total_seconds() / 86400.0)
    return 0.5 ** (days / PHANTOM_HALF_LIFE_DAYS)

def phantom_score(candidate):
    """Delegate PHANTOM TRACK scoring to the modular identity engine."""
    return _score_identity_evidence(
        candidate,
        thresholds=PHANTOM_THRESHOLDS,
        half_life_days=PHANTOM_HALF_LIFE_DAYS,
        group_cap=PHANTOM_GROUP_CAP,
        auto_merge=frozenset(PHANTOM_AUTO_MERGE),
        conflict_kinds=frozenset(PHANTOM_CONFLICT_KINDS),
        local_group=PHANTOM_LOCAL_GROUP,
    )

def _evidence_for_continuity(conn, continuity_id):
    """Convert stored identity observations to scoring Evidence dicts."""
    rows = conn.execute("""
        SELECT source, hostname, vendor_class, mac_class, timestamp, confidence
        FROM identity_continuity_observations WHERE continuity_id=?
        ORDER BY timestamp DESC LIMIT 200""", (continuity_id,)).fetchall()
    out = []
    for source, hostname, vclass, mac_class, ts, conf in rows:
        try:
            when = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
        strength = max(0.0, min(1.0, float(conf or 0) / 100.0))
        if hostname:
            out.append({"source": source or "inventory", "kind": "hostname",
                        "value": hostname, "strength": strength,
                        "independence_group": "hostname", "observed_at": when})
        if vclass:
            out.append({"source": source or "inventory", "kind": "vendor_class",
                        "value": vclass, "strength": strength * 0.7,
                        "independence_group": "dhcp", "observed_at": when})
        if mac_class == "GLOBAL_UNICAST":
            out.append({"source": "arp", "kind": "oui_global", "value": mac_class,
                        "strength": 0.35, "independence_group": "oui_global",
                        "observed_at": when})
        elif mac_class == "RANDOMISED_OR_LOCAL":
            out.append({"source": "arp", "kind": "oui_local", "value": mac_class,
                        "strength": 0.05, "independence_group": "oui_local",
                        "observed_at": when})
    return out

def assess_identity_candidates(conn):
    """Conservative continuity review.

    A match requires a shared, independently sourced, unique hardware/device
    identifier. The current observation schema does not store a validated
    serial, device UUID, certificate identity or equivalent cross-IP key.
    Therefore this release deliberately creates no cross-anchor candidates.
    Legacy candidates from the former union-scoring defect are retained for
    audit but suppressed from the active review queue.
    """
    # These old pending rows were generated by the faulty 85%-constant scorer.
    # Keep them in the database for auditability; never present them as valid.
    conn.execute("""UPDATE identity_candidates
        SET status='SUPPRESSED', reviewed_at=?, reviewer='8.6.0-safety-migration'
        WHERE status='PENDING'""", (now_text(),))
    return 0

# ------------------------------------------------------------
# Presence engine (D13)
# ------------------------------------------------------------

PRESENCE_ONLINE_WINDOW_MIN = 30
PRESENCE_SUSPECTED_AFTER_MISSED = 1
PRESENCE_OFFLINE_AFTER_MISSED = DEVICE_OFFLINE_CONFIRM_SCANS  # =3 consecutive completed scans
PRESENCE_INTERMITTENT_TOGGLES = 4
PRESENCE_INTERMITTENT_WINDOW_H = 24

def evaluate_presence(observation_times, completed_scan_times,
                      prior_state, now=None):
    """Return (state, evidence dict). One missed scan NEVER marks OFFLINE."""
    now = now or datetime.now(timezone.utc)
    evidence = {"observations": len(observation_times),
                "completed_scans": len(completed_scan_times)}
    if not observation_times and not completed_scan_times:
        return "UNKNOWN", {**evidence, "reason": "no data"}
    if not observation_times:
        return "UNVERIFIED", {**evidence,
                              "reason": "scans ran, device never observed"}
    last_obs = max(observation_times)
    if now - last_obs <= timedelta(minutes=PRESENCE_ONLINE_WINDOW_MIN):
        state = ("RETURNED" if prior_state in ("OFFLINE", "SUSPECTED_OFFLINE")
                 else "ONLINE")
        return state, {**evidence, "last_observed": last_obs.isoformat()}
    missed = sum(1 for s in completed_scan_times if s > last_obs)
    if missed >= PRESENCE_OFFLINE_AFTER_MISSED:
        base = "OFFLINE"
    elif missed >= PRESENCE_SUSPECTED_AFTER_MISSED:
        base = "SUSPECTED_OFFLINE"
    else:
        base = "UNVERIFIED"
    window = [t for t in observation_times
              if now - t <= timedelta(hours=PRESENCE_INTERMITTENT_WINDOW_H)]
    toggles = sum(1 for a, b in zip(window, window[1:])
                  if (b - a) > timedelta(minutes=PRESENCE_ONLINE_WINDOW_MIN * 3))
    if toggles >= PRESENCE_INTERMITTENT_TOGGLES:
        return "INTERMITTENT", {**evidence, "missed": missed, "toggles": toggles}
    return base, {**evidence, "missed": missed}

def evaluate_presence_for_device(conn, device_id, prior_state=None):
    obs_rows = conn.execute(
        "SELECT timestamp FROM network_events WHERE device_id=? "
        "AND event_type IN ('DEVICE_FINGERPRINTED','NEW_DEVICE','DEVICE_RETURNED') "
        "AND timestamp >= datetime('now','-7 days') "
        "ORDER BY timestamp DESC LIMIT 500", (device_id,)).fetchall()
    scan_rows = conn.execute(
        "SELECT timestamp FROM scans WHERE timestamp >= datetime('now','-7 days') "
        "ORDER BY timestamp DESC LIMIT 500").fetchall()
    def _parse(ts):
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
    obs = [t for t in (_parse(r[0]) for r in obs_rows) if t]
    scans = [t for t in (_parse(r[0]) for r in scan_rows) if t]
    state, evidence = evaluate_presence(obs, scans, prior_state)
    if state != prior_state:
        try:
            conf = 0.5 if evidence.get("missed", 0) > 0 else 0.85
            conn.execute("""INSERT INTO device_presence_events(
                timestamp, device_id, state, prior_state, confidence, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (now_text(), device_id, state, prior_state or "",
                 conf, json.dumps(evidence)))
        except Exception:
            pass
    return {"state": state, "evidence": evidence}

# ============================================================
# BEHAVIOUR, CORRELATION, RISK
# ============================================================

def behaviour_snapshot():
    now = datetime.now()
    now_s = now.strftime("%Y-%m-%d %H:%M:%S")
    win = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    def _w(conn):
        devices = conn.execute("SELECT ip, COALESCE(NULLIF(device_id,''),"
                               "'ip:'||ip) FROM devices WHERE status='ONLINE'").fetchall()
        for ip, did in devices:
            prev = conn.execute("SELECT last_sample_at FROM "
                                "device_behavior_baselines WHERE device_id=?",
                                (did,)).fetchone()
            if prev and prev[0]:
                try:
                    if (now - datetime.strptime(prev[0], "%Y-%m-%d %H:%M:%S")
                            ).total_seconds() < 285:
                        continue
                except ValueError:
                    pass
            q, u, nx = conn.execute("""
                SELECT (SELECT COUNT(*) FROM dns_events WHERE client_ip=? AND
                        is_response=0 AND timestamp>=?),
                       (SELECT COUNT(DISTINCT domain) FROM dns_events WHERE
                        client_ip=? AND is_response=0 AND timestamp>=?),
                       (SELECT COUNT(*) FROM dns_events WHERE client_ip=? AND
                        response_code='NXDOMAIN' AND timestamp>=?)""",
                (ip, win, ip, win, ip, win)).fetchone()
            row = conn.execute("""SELECT sample_count, mean_dns_queries,
                m2_dns_queries, mean_unique_domains, m2_unique_domains
                FROM device_behavior_baselines WHERE device_id=?""", (did,)).fetchone()
            n, mq, m2q, md, m2d = row if row else (0, 0.0, 0.0, 0.0, 0.0)
            if n >= 12:
                sq = math.sqrt(max(0.0, m2q / max(1, n - 1)))
                sd = math.sqrt(max(0.0, m2d / max(1, n - 1)))
                checks = []
                if q >= max(40, mq * 2.5, mq + 3 * sq):
                    checks.append(("DNS_QUERY_VOLUME", float(q), float(mq),
                                   "DNS volume unusually high for this device"))
                if u >= max(20, md * 2.5, md + 3 * sd):
                    checks.append(("DNS_DOMAIN_DIVERSITY", float(u), float(md),
                                   "Domain diversity unusually high"))
                for metric, obs, base, explain in checks:
                    recent = conn.execute("""SELECT 1 FROM behavior_alerts
                        WHERE device_id=? AND metric=? AND timestamp>=datetime('now','-1 hour')
                        LIMIT 1""", (did, metric)).fetchone()
                    if recent:
                        continue
                    sev = "HIGH" if obs >= max(100, base * 5) else "MEDIUM"
                    details = (f"{explain}. Observed {obs:g}, baseline {base:.1f} "
                               f"over 5 min.")
                    conn.execute("""INSERT INTO behavior_alerts(timestamp, device_id,
                        ip, metric, observed, baseline, severity, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (now_s, did, ip, metric, obs, base, sev, details))
                    record_event(conn, ip, "BEHAVIOUR_ALERT", details,
                                 category="behaviour", severity=sev, device_id=did)
                    record_alert(conn, "behaviour", metric, sev,
                                 f"Behaviour {metric}", details, ip=ip,
                                 device_id=did, confidence=60)
            nn = n + 1
            dq = q - mq
            nmq = mq + dq / nn
            nm2q = m2q + dq * (q - nmq)
            dd = u - md
            nmd = md + dd / nn
            nm2d = m2d + dd * (u - nmd)
            conn.execute("""INSERT INTO device_behavior_baselines(device_id,
                sample_count, mean_dns_queries, m2_dns_queries,
                mean_unique_domains, m2_unique_domains, last_sample_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    sample_count=excluded.sample_count,
                    mean_dns_queries=excluded.mean_dns_queries,
                    m2_dns_queries=excluded.m2_dns_queries,
                    mean_unique_domains=excluded.mean_unique_domains,
                    m2_unique_domains=excluded.m2_unique_domains,
                    last_sample_at=excluded.last_sample_at""",
                (did, nn, nmq, nm2q, nmd, nm2d, now_s))
            conn.execute("""INSERT INTO device_behavior_samples(timestamp,
                device_id, ip, dns_queries, unique_domains, nxdomain_count)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (now_s, did, ip, q or 0, u or 0, nx or 0))
    DB_MANAGER.write(_w)

def behaviour_diagnostics(conn=None):
    own = conn is None
    ctx = None
    if own:
        ctx = DB_MANAGER.read()
        conn = ctx.__enter__()
    try:
        online = conn.execute("SELECT COUNT(*) FROM devices WHERE status='ONLINE'").fetchone()[0]
        total, mature, recent = conn.execute("""SELECT COUNT(*),
            SUM(CASE WHEN sample_count>=12 THEN 1 ELSE 0 END),
            SUM(CASE WHEN last_sample_at>=datetime('now','-24 hours') THEN 1 ELSE 0 END)
            FROM device_behavior_baselines""").fetchone()
        alerts = conn.execute("SELECT COUNT(*) FROM behavior_alerts WHERE timestamp>=datetime('now','-24 hours')").fetchone()[0]
        total = int(total or 0); mature = int(mature or 0); recent = int(recent or 0)
        if online == 0:
            state, message = "NO_ONLINE_DEVICES", "No online devices are available for behaviour sampling."
        elif total == 0:
            state, message = "COLLECTING", "No baseline samples yet."
        elif mature == 0:
            state, message = "BUILDING_BASELINES", f"Baselines building: {total} device(s) sampled; 12 samples required."
        else:
            state, message = "MONITORING", f"Monitoring {mature} mature baseline(s); {recent} sampled in the last 24 hours."
        return {"state": state, "message": message, "online_devices": int(online or 0),
                "baseline_devices": total, "mature_baselines": mature,
                "recent_baselines": recent, "alerts_24h": int(alerts or 0),
                "minimum_samples": 12}
    finally:
        if own and ctx is not None:
            ctx.__exit__(None, None, None)

def scan_quality_report(conn=None):
    own = conn is None
    ctx = None
    if own:
        ctx = DB_MANAGER.read()
        conn = ctx.__enter__()
    try:
        scan = conn.execute("SELECT timestamp,network,hosts_up,duration FROM scans "
                            "ORDER BY id DESC LIMIT 1").fetchone()
        with NET_LOCK:
            net = dict(NET_CTX)
        with DHCP_STATE_LOCK:
            dhcp = dict(DHCP_STATE)
        with DNS_STATE_LOCK:
            dns = dict(DNS_STATE)
        with ARP_STATE_LOCK:
            arp = dict(ARP_STATE)
        score = 0; reasons = []
        if scan:
            score += 30
            if int(scan[2] or 0) > 0:
                score += 15
            else:
                reasons.append("Latest scan reported zero hosts.")
        else:
            reasons.append("No completed scan is recorded.")
        if net.get("network") and net.get("ip"):
            score += 15
        else:
            reasons.append("Network context is incomplete.")
        if net.get("gateway"):
            score += 10
        else:
            reasons.append("Default gateway is unknown.")
        if net.get("authorized"):
            score += 10
        else:
            reasons.append("Active discovery is not authorised on this network.")
        if dns.get("status") == "ONLINE":
            score += 5
        else:
            reasons.append("DNS capture is not online.")
        if dhcp.get("status") in {"ONLINE", "RUNNING"}:
            score += 5
        else:
            detail = dhcp.get("last_error") or dhcp.get("error") or "No diagnostic detail available."
            reasons.append(f"DHCP capture state: {dhcp.get('status', 'UNKNOWN')}. {detail}")
        if arp.get("status") == "ONLINE":
            score += 5
        else:
            reasons.append(f"ARP capture state: {arp.get('status', 'UNKNOWN')}.")
        score = min(100, score)
        band = "HIGH" if score >= 85 else "MODERATE" if score >= 65 else "LOW"
        return {"score": score, "band": band, "latest_scan": scan[0] if scan else "",
                "network": scan[1] if scan else "", "hosts_up": int(scan[2] or 0) if scan else 0,
                "duration_seconds": float(scan[3] or 0) if scan else 0,
                "reasons": reasons}
    finally:
        if own and ctx is not None:
            ctx.__exit__(None, None, None)

def store_evidence(conn, inv_id, ev_type, content, source_ref="",
                   created_by="system", notes=""):
    if isinstance(content, (dict, list)):
        payload = json.dumps(content, sort_keys=True, ensure_ascii=False, default=str)
    else:
        payload = str(content)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    cur = conn.execute("""INSERT INTO evidence(investigation_id, timestamp,
        evidence_type, source_ref, content, content_sha256, created_by, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (inv_id, now_text(), ev_type, source_ref, payload, digest,
         created_by, notes))
    return cur.lastrowid, digest

def verify_evidence(eid):
    with DB_MANAGER.read() as conn:
        row = conn.execute("SELECT content, content_sha256 FROM evidence "
                           "WHERE id=?", (eid,)).fetchone()
    if not row:
        return {"valid": False, "reason": "not found"}
    computed = hashlib.sha256(row[0].encode("utf-8")).hexdigest()
    return {"valid": computed == row[1], "stored": row[1], "computed": computed}

def correlate():
    cutoff = (datetime.now() - timedelta(minutes=15)
              ).strftime("%Y-%m-%d %H:%M:%S")
    created = 0
    def _w(conn):
        nonlocal created
        pending = conn.execute("""SELECT id, timestamp, device_id, ip, source,
            rule_id, severity, title, details FROM alerts
            WHERE investigation_id IS NULL AND COALESCE(NULLIF(last_seen,''),timestamp)>=?
            ORDER BY id ASC""", (cutoff,)).fetchall()
        buckets = defaultdict(list)
        for r in pending:
            buckets[r[2] or ("ip:" + (r[3] or ""))].append(r)
        for key, rows in buckets.items():
            if not rows:
                continue
            sevs = {r[6] for r in rows}
            qualifies = (sevs & {"HIGH", "CRITICAL"}) or len(rows) >= 2
            if not qualifies:
                continue
            worst = max(rows, key=lambda r: {"CRITICAL": 4, "HIGH": 3,
                                              "MEDIUM": 2, "LOW": 1}.get(r[6], 0))
            did = worst[2] or ""
            ip = worst[3] or ""
            title = f"{worst[6]} {worst[4]} cluster on {did or ip}"
            desc = " | ".join(r[7] for r in rows)[:800]
            conf = min(90, 40 + 15 * len(rows))
            existing = conn.execute("""SELECT id, description, severity, confidence
                FROM investigations
                WHERE COALESCE(affected_device_id,'')=? AND COALESCE(affected_ip,'')=?
                  AND status IN ('OPEN','INVESTIGATING')
                ORDER BY updated_at DESC LIMIT 1""",
                (did, ip)).fetchone()
            if existing:
                iid, old_desc, old_sev, old_conf = existing
                severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                merged_sev = (worst[6] if severity_rank.get(worst[6], 0) >
                              severity_rank.get(old_sev, 0) else old_sev)
                merged_desc = ((old_desc or "") + " | " + desc).strip(" |")[-4000:]
                conn.execute("""UPDATE investigations SET updated_at=?,
                    description=?, severity=?, confidence=MAX(confidence,?)
                    WHERE id=?""",
                    (now_text(), merged_desc, merged_sev, conf, iid))
            else:
                cur = conn.execute("""INSERT INTO investigations(timestamp,
                    updated_at, title, description, severity, confidence, status,
                    affected_device_id, affected_ip)
                    VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)""",
                    (worst[1], now_text(), title, desc, worst[6], conf, did, ip))
                iid = cur.lastrowid
                created += 1
            for r in rows:
                conn.execute("UPDATE alerts SET investigation_id=?, status='LINKED' "
                             "WHERE id=?", (iid, r[0]))
                conn.execute("INSERT OR IGNORE INTO alert_investigations"
                             "(alert_id, investigation_id) VALUES (?, ?)", (r[0], iid))
            store_evidence(conn, iid, "alert_cluster",
                           {"investigation_id": iid, "cluster_size": len(rows),
                            "alerts": [{"id": r[0], "timestamp": r[1],
                                        "device_id": r[2], "ip": r[3],
                                        "source": r[4], "rule_id": r[5],
                                        "severity": r[6], "title": r[7],
                                        "details": r[8]} for r in rows]},
                           source_ref=f"alerts[{','.join(str(r[0]) for r in rows)}]")
    DB_MANAGER.write(_w)
    return created

def compute_risk():
    now_ts = time.time()
    def _w(conn):
        devices = conn.execute("""SELECT ip, COALESCE(NULLIF(device_id,''),
            'ip:'||ip), identification_confidence, identity_basis, trust_state
            FROM devices WHERE status='ONLINE'""").fetchall()
        for ip, did, id_conf, basis, trust in devices:
            tp = 0.0; hp = 0.0; contribs = []
            def age(ts):
                try:
                    return now_ts - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    return 0
            for (ts,) in conn.execute("SELECT timestamp FROM threat_matches "
                                      "WHERE client_ip=? AND timestamp>=datetime('now','-7 days')",
                                      (ip,)).fetchall():
                w = 25.0 * _decay(age(ts))
                tp += w
                contribs.append({"axis": "threat", "reason": "IOC match",
                                 "timestamp": ts, "points": round(w, 1)})
            dns_signal = 0.0
            dns_rows = conn.execute("""SELECT MAX(timestamp), severity, rule_id
                FROM dns_alerts WHERE client_ip=?
                AND timestamp>=datetime('now','-7 days')
                GROUP BY rule_id, COALESCE(domain,'')""", (ip,)).fetchall()
            dns_contribs = []
            for ts, sev, rule in dns_rows:
                base = 5.0 if sev == "HIGH" else 2.0 if sev == "MEDIUM" else 1.0
                w = base * _decay(age(ts))
                dns_signal += w
                dns_contribs.append({"axis": "threat_signal",
                                     "reason": f"DNS anomaly ({rule}, {sev})",
                                     "timestamp": ts, "raw_points": w})
            dns_applied = min(12.0, dns_signal)
            scale = (dns_applied / dns_signal) if dns_signal > 0 else 0.0
            for item in dns_contribs:
                contribs.append({"axis": item["axis"], "reason": item["reason"],
                                 "timestamp": item["timestamp"],
                                 "points": round(item["raw_points"] * scale, 1)})
            tp += dns_applied
            for (ts, sev) in conn.execute("SELECT timestamp, severity FROM behavior_alerts "
                                          "WHERE ip=? AND timestamp>=datetime('now','-7 days')",
                                          (ip,)).fetchall():
                w = (6.0 if sev == "HIGH" else 3.0) * _decay(age(ts))
                hp += w
                contribs.append({"axis": "health", "reason": f"Behaviour ({sev})",
                                 "timestamp": ts, "points": round(w, 1)})
            for (ts,) in conn.execute("SELECT timestamp FROM arp_observations "
                                      "WHERE sender_ip=? AND change_type!='' "
                                      "AND timestamp>=datetime('now','-7 days')",
                                      (ip,)).fetchall():
                w = 12.0 * _decay(age(ts))
                tp += w
                contribs.append({"axis": "threat", "reason": "ARP change",
                                 "timestamp": ts, "points": round(w, 1)})
            ident = 0.0
            if (basis or "").startswith("IP fallback"):
                ident += 40.0
                contribs.append({"axis": "identification",
                                 "reason": "IP-only identity", "points": 40.0})
            if (id_conf or 0) < 20:
                ident += 20.0
                contribs.append({"axis": "identification",
                                 "reason": f"ID confidence {id_conf or 0}%",
                                 "points": 20.0})
            if trust == "TRUSTED":
                ident *= 0.3
            threat = min(100, int(round(tp)))
            health = min(100, int(round(hp)))
            ident_i = min(100, int(round(ident)))
            overall = max(threat, int(ident_i * 0.15), int(health * 0.5))
            band = ("LOW" if overall < 30 else "MEDIUM" if overall < 60
                    else "HIGH" if overall < 85 else "CRITICAL")
            conn.execute("""INSERT INTO device_risk_scores(device_id, timestamp,
                score, band, explanation, threat_risk,
                identification_uncertainty, operational_health, explanation_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    timestamp=excluded.timestamp, score=excluded.score,
                    band=excluded.band, explanation=excluded.explanation,
                    threat_risk=excluded.threat_risk,
                    identification_uncertainty=excluded.identification_uncertainty,
                    operational_health=excluded.operational_health,
                    explanation_json=excluded.explanation_json""",
                (did, now_text(), overall, band,
                 "; ".join(f"{c['reason']} (+{c['points']})"
                           for c in contribs[:8]) or "No contributing evidence.",
                 threat, ident_i, health, json.dumps(contribs[:20])))
            conn.execute("UPDATE devices SET risk_score=?, risk_band=? WHERE ip=?",
                         (overall, band, ip))
    DB_MANAGER.write(_w)

# ============================================================
# CHANGES, CONFIG AUDIT
# ============================================================

def record_change(conn, change_type, category, details, ip="", did="",
                  severity="INFO"):
    fp = current_fingerprint()
    conn.execute("""INSERT INTO network_changes(timestamp, network_fp,
        device_id, ip, change_type, category, severity, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (now_text(), fp, did, ip, change_type, category, severity, details[:1000]))

def _valid_port_fingerprint(value):
    text = str(value or "").strip()
    return bool(text and text.lower() not in {
        "unavailable", "unknown", "not fingerprinted",
        "no common tcp ports found", "none", "—", "-"})

def detect_changes(prev, curr, ports_complete=False):
    def _w(conn):
        for ip in set(curr) - set(prev):
            record_change(conn, "NEW_DEVICE", "discovery",
                          f"New device at {ip}", ip=ip)
        for ip in set(prev) - set(curr):
            record_change(conn, "DEVICE_OFFLINE", "discovery",
                          f"{ip} no longer responding", ip=ip)
        for ip in set(prev) & set(curr):
            p, c = prev[ip], curr[ip]
            if (valid_unicast_mac(p.get("mac")) and valid_unicast_mac(c.get("mac"))
                    and p["mac"].replace("-", ":").upper() != c["mac"].replace("-", ":").upper()):
                record_change(conn, "MAC_CHANGED", "identity",
                              f"{ip}: {p['mac']} → {c['mac']}", ip=ip, severity="MEDIUM")
            if p.get("hostname") and c.get("hostname") and p["hostname"] != c["hostname"]:
                record_change(conn, "HOSTNAME_CHANGED", "identity",
                              f"{ip}: {p['hostname']} → {c['hostname']}", ip=ip)
            old_ports, new_ports = p.get("open_ports"), c.get("open_ports")
            host_ports_complete = bool(ports_complete and c.get("_ports_complete", ports_complete))
            if (host_ports_complete and _valid_port_fingerprint(old_ports)
                    and _valid_port_fingerprint(new_ports) and old_ports != new_ports):
                record_change(conn, "PORTS_CHANGED", "services",
                              f"{ip}: {old_ports} → {new_ports}",
                              ip=ip, severity="MEDIUM")
    DB_MANAGER.write(_w)

def audit_config():
    findings = []
    fp = current_fingerprint()
    with NET_LOCK:
        ctx = dict(NET_CTX)
    def _w(conn):
        def upsert(key, title, desc, sev, conf, ev, rec):
            row = conn.execute("SELECT first_seen FROM config_findings "
                               "WHERE finding_key=?", (key,)).fetchone()
            if row:
                conn.execute("""UPDATE config_findings SET last_seen=?,
                    description=?, severity=?, confidence=?, evidence=?,
                    recommendation=? WHERE finding_key=?""",
                    (now_text(), desc, sev, conf, ev, rec, key))
            else:
                conn.execute("""INSERT INTO config_findings(timestamp, network_fp,
                    finding_key, title, description, severity, confidence,
                    evidence, recommendation, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (now_text(), fp, key, title, desc, sev, conf, ev, rec,
                     now_text(), now_text()))
            findings.append({"key": key, "title": title, "severity": sev})
        servers = conn.execute("""SELECT server_ip, COUNT(*) FROM dhcp_events
            WHERE msg_type IN ('OFFER','ACK') AND server_ip!=''
            AND timestamp>=datetime('now','-24 hours') GROUP BY server_ip""").fetchall()
        if len(servers) > 1:
            upsert("MULTIPLE_DHCP_SERVERS", "Multiple DHCP servers",
                   f"{len(servers)} servers issuing OFFER/ACK in 24h",
                   "MEDIUM", 70,
                   ", ".join(f"{s[0]}({s[1]})" for s in servers),
                   "Identify the legitimate server.")
        rogue = conn.execute("""SELECT COUNT(*), GROUP_CONCAT(DISTINCT server_ip)
            FROM dhcp_events WHERE is_rogue=1 AND timestamp>=datetime('now','-24 hours')""").fetchone()
        if rogue[0]:
            upsert("ROGUE_DHCP_OFFERS", "DHCP from unexpected servers",
                   f"{rogue[0]} rogue-flagged DHCP offers", "HIGH", 60,
                   rogue[1] or "", "Investigate source of unexpected DHCP offers.")
        dups = conn.execute("""SELECT sender_ip, COUNT(DISTINCT sender_mac)
            FROM arp_observations WHERE timestamp>=datetime('now','-1 hour')
              AND sender_ip NOT IN ('0.0.0.0','') AND COALESCE(change_type,'')!='PROBE'
            GROUP BY sender_ip HAVING COUNT(DISTINCT sender_mac)>1""").fetchall()
        for ip, n in dups:
            upsert(f"DUP_IP_{ip}", f"Multiple MACs for {ip}",
                   f"{n} distinct MACs answered in last hour", "MEDIUM", 65,
                   f"ip={ip} macs={n}", "Check for IP conflict or ARP spoofing.")
        risky = conn.execute("""SELECT ip, open_ports FROM devices
            WHERE status='ONLINE' AND open_ports!='' AND (
                open_ports LIKE '%:21,%' OR open_ports LIKE '21,%' OR
                open_ports LIKE '%:23,%' OR open_ports LIKE '23,%' OR
                open_ports LIKE '%3389%' OR open_ports LIKE '%445%')""").fetchall()
        if risky:
            upsert("RISKY_EXPOSED_SERVICES", "High-risk ports exposed",
                   f"{len(risky)} device(s) expose FTP/Telnet/RDP/SMB", "MEDIUM", 75,
                   ", ".join(f"{r[0]}:{r[1]}" for r in risky[:6]),
                   "Confirm these services should be reachable.")
        if ctx.get("gateway") and not ctx.get("gateway_mac"):
            upsert("GATEWAY_MAC_UNKNOWN", "Gateway MAC not observed",
                   f"Gateway {ctx['gateway']} not in ARP/neighbor table", "LOW", 40,
                   f"gateway={ctx['gateway']}",
                   "Not necessarily a problem — may indicate no recent traffic.")
        if (ctx.get("dns_servers") and ctx.get("gateway")
                and ctx["gateway"] not in ctx["dns_servers"]):
            upsert("DNS_NOT_GATEWAY", "DNS servers differ from gateway",
                   f"DNS: {ctx['dns_servers']}, gateway: {ctx['gateway']}",
                   "INFO", 50,
                   f"dns={ctx['dns_servers']} gateway={ctx['gateway']}",
                   "Normal with public DNS.")
    DB_MANAGER.write(_w)
    return findings

# ============================================================
# HUNT TEMPLATES + REPORTS
# ============================================================

HUNT_TEMPLATES = {
    "new_devices_24h": {
        "title": "Devices discovered in last 24h",
        "sql": "SELECT ip, device_name, device_type, first_seen FROM devices "
               "WHERE first_seen >= datetime('now','-24 hours') "
               "ORDER BY first_seen DESC LIMIT 500",
        "columns": ["ip", "device_name", "device_type", "first_seen"]},
    "ip_changes_24h": {
        "title": "Devices that changed IP in last 24h",
        "sql": "SELECT d.ip, d.device_name, h.ip AS previous_ip, "
               "h.last_seen AS last_seen_on_old_ip FROM devices d "
               "JOIN device_ip_history h ON h.device_id=d.device_id "
               "WHERE h.last_seen >= datetime('now','-24 hours') "
               "AND h.ip != d.ip ORDER BY h.last_seen DESC LIMIT 500",
        "columns": ["ip", "device_name", "previous_ip", "last_seen_on_old_ip"]},
    "behavior_alerting_devices": {
        "title": "Devices with behaviour alerts (7 days)",
        "sql": "SELECT d.ip, d.device_name, COUNT(b.id) AS alerts "
               "FROM behavior_alerts b LEFT JOIN devices d ON d.ip=b.ip "
               "WHERE b.timestamp >= datetime('now','-7 days') "
               "GROUP BY b.ip ORDER BY alerts DESC LIMIT 500",
        "columns": ["ip", "device_name", "alerts"]},
    "threat_matched_devices": {
        "title": "Devices with threat indicator matches",
        "sql": "SELECT ip, device_name, risk_score, risk_band FROM devices "
               "WHERE ip IN (SELECT DISTINCT client_ip FROM threat_matches "
               "WHERE timestamp >= datetime('now','-7 days')) "
               "ORDER BY risk_score DESC LIMIT 500",
        "columns": ["ip", "device_name", "risk_score", "risk_band"]},
    "threat_matches_all": {
        "title": "All threat indicator matches (7 days)",
        "sql": "SELECT timestamp, domain, client_ip, details FROM threat_matches "
               "WHERE timestamp >= datetime('now','-7 days') "
               "ORDER BY id DESC LIMIT 500",
        "columns": ["timestamp", "domain", "client_ip", "details"]},
    "unusual_services": {
        "title": "Devices with unusual ports",
        "sql": "SELECT ip, device_name, open_ports, device_type FROM devices "
               "WHERE open_ports!='' AND (open_ports LIKE '%9999%' "
               "OR open_ports LIKE '%6667%' OR open_ports LIKE '%4444%') LIMIT 500",
        "columns": ["ip", "device_name", "open_ports", "device_type"]},
    "top_risk": {
        "title": "Highest risk devices",
        "sql": "SELECT ip, device_name, device_type, risk_band, risk_score "
               "FROM devices WHERE status='ONLINE' "
               "ORDER BY risk_score DESC LIMIT 50",
        "columns": ["ip", "device_name", "device_type", "risk_band", "risk_score"]},
    "unresolved_investigations": {
        "title": "Unresolved investigations",
        "sql": "SELECT id, timestamp, title, severity, status FROM investigations "
               "WHERE status IN ('OPEN','INVESTIGATING') "
               "ORDER BY timestamp DESC LIMIT 200",
        "columns": ["id", "timestamp", "title", "severity", "status"]},
    "dhcp_24h": {
        "title": "DHCP activity (24h)",
        "sql": "SELECT timestamp, msg_type, client_mac, client_ip, server_ip, "
               "hostname FROM dhcp_events "
               "WHERE timestamp >= datetime('now','-24 hours') "
               "ORDER BY id DESC LIMIT 500",
        "columns": ["timestamp", "msg_type", "client_mac", "client_ip",
                    "server_ip", "hostname"]},
    "arp_changes_24h": {
        "title": "ARP mapping changes (24h)",
        "sql": "SELECT timestamp, sender_ip, sender_mac, change_type "
               "FROM arp_observations WHERE change_type!='' "
               "AND timestamp >= datetime('now','-24 hours') "
               "ORDER BY id DESC LIMIT 500",
        "columns": ["timestamp", "sender_ip", "sender_mac", "change_type"]},
    "config_findings_open": {
        "title": "Open configuration findings",
        "sql": "SELECT timestamp, title, severity, recommendation "
               "FROM config_findings WHERE status='OPEN' "
               "ORDER BY severity DESC LIMIT 200",
        "columns": ["timestamp", "title", "severity", "recommendation"]},
}

def run_hunt(key, filters=None):
    t = HUNT_TEMPLATES.get(key)
    if not t:
        return {"error": "unknown template", "results": [], "columns": []}
    sql = t["sql"]
    params = []
    f = filters or {}
    if f.get("ip"):
        sql = f"SELECT * FROM ({sql}) WHERE ip = ?"
        params.append(f["ip"])
    if f.get("severity"):
        sql = f"SELECT * FROM ({sql}) WHERE severity = ?"
        params.append(f["severity"])
    try:
        with DB_MANAGER.read() as conn:
            rows = conn.execute(sql, params).fetchall()
    except sqlite3.Error as e:
        return {"error": _clean(e, 200), "results": [], "columns": t["columns"]}
    return {"template": key, "title": t["title"], "columns": t["columns"],
            "results": [dict(zip(t["columns"], r)) for r in rows],
            "count": len(rows)}

def generate_report(rtype, fmt="json"):
    data = {"generated_at": now_text(), "report_type": rtype,
            "version": APP_VERSION}
    with DB_MANAGER.read() as conn:
        if rtype == "daily":
            data["period"] = "last 24 hours"
            data["devices_online"] = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status='ONLINE'").fetchone()[0]
            data["devices_new"] = conn.execute("SELECT COUNT(*) FROM devices "
                                               "WHERE first_seen>=datetime('now','-24 hours')"
                                               ).fetchone()[0]
            data["investigations"] = [dict(r) for r in conn.execute(
                "SELECT id, timestamp, title, severity, status FROM investigations "
                "WHERE timestamp>=datetime('now','-24 hours')").fetchall()]
            data["alerts"] = [dict(r) for r in conn.execute(
                "SELECT timestamp, ip, source, rule_id, severity, title FROM alerts "
                "WHERE timestamp>=datetime('now','-24 hours') "
                "ORDER BY id DESC LIMIT 200").fetchall()]
        elif rtype == "devices":
            data["period"] = "all time"
            data["devices"] = [dict(r) for r in conn.execute(
                "SELECT ip, device_name, device_type, manufacturer, mac, os_guess, "
                "open_ports, status, trust_state, risk_band, risk_score, "
                "first_seen, last_seen FROM devices ORDER BY ip LIMIT 5000").fetchall()]
        elif rtype == "investigations":
            data["period"] = "all time"
            data["investigations"] = [dict(r) for r in conn.execute(
                "SELECT id, timestamp, updated_at, title, severity, confidence, "
                "status, affected_ip FROM investigations ORDER BY id DESC LIMIT 2000"
            ).fetchall()]
        elif rtype == "changes":
            data["period"] = "last 7 days"
            data["changes"] = [dict(r) for r in conn.execute(
                "SELECT timestamp, change_type, category, severity, ip, details "
                "FROM network_changes WHERE timestamp>=datetime('now','-7 days') "
                "ORDER BY id DESC LIMIT 2000").fetchall()]
        elif rtype == "threats":
            data["period"] = "last 7 days"
            data["matches"] = [dict(r) for r in conn.execute(
                "SELECT timestamp, domain, client_ip, details FROM threat_matches "
                "WHERE timestamp>=datetime('now','-7 days') "
                "ORDER BY id DESC LIMIT 2000").fetchall()]
        elif rtype == "health":
            data["period"] = "last 24 hours"
            data["samples"] = [dict(r) for r in conn.execute(
                "SELECT timestamp, gateway_latency_ms, dns_resolution_ms, "
                "internet_status, notes FROM network_health_samples "
                "WHERE timestamp>=datetime('now','-24 hours') "
                "ORDER BY id DESC LIMIT 500").fetchall()]
        elif rtype == "config":
            data["period"] = "current"
            data["findings"] = [dict(r) for r in conn.execute(
                "SELECT timestamp, title, description, severity, confidence, "
                "evidence, recommendation, first_seen, last_seen, status "
                "FROM config_findings ORDER BY severity DESC LIMIT 500").fetchall()]
        else:
            return (json.dumps({"error": "unknown type"}).encode(),
                    "application/json", "err.json")

    data = json.loads(json.dumps(data, default=str))
    base = f"nr_{rtype}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "json":
        return (json.dumps(data, indent=2, default=str).encode(),
                "application/json", base + ".json")
    if fmt == "csv":
        rows = next((v for v in data.values() if isinstance(v, list) and v), [])
        if not rows:
            return b"no rows\n", "text/csv", base + ".csv"
        header = list(rows[0].keys())
        lines = [",".join(header)]
        for row in rows:
            lines.append(",".join(
                f'"{str(row.get(h, "")).replace(chr(34), chr(34)*2)}"'
                for h in header))
        return ("\n".join(lines) + "\n").encode(), "text/csv", base + ".csv"
    if fmt == "html":
        parts = [f"<h1>NetworkRadar {rtype}</h1>",
                 f"<p>Generated {data['generated_at']} · v{APP_VERSION}</p>"]
        for k, v in data.items():
            if isinstance(v, list) and v:
                parts.append(f"<h2>{k} ({len(v)} rows)</h2>")
                headers = list(v[0].keys())
                parts.append("<table border=1 cellpadding=4><tr>"
                             + "".join(f"<th>{h}</th>" for h in headers) + "</tr>")
                for row in v[:1000]:
                    parts.append("<tr>"
                                 + "".join(f"<td>{row.get(h,'')}</td>" for h in headers)
                                 + "</tr>")
                parts.append("</table>")
        html = ("<html><head><title>NR</title><style>body{font-family:sans-serif;"
                "max-width:1200px;margin:2em auto;padding:0 1em}table{border-collapse:"
                "collapse;font-size:12px;width:100%}td,th{border:1px solid #ccc;"
                "padding:4px}</style></head><body>" + "".join(parts)
                + "</body></html>")
        return html.encode(), "text/html", base + ".html"
    return b"unsupported", "text/plain", "err.txt"

def topology_payload():
    with DB_MANAGER.read() as conn:
        nodes = {}
        for r in conn.execute("""SELECT ip, COALESCE(NULLIF(manual_name,''),
            NULLIF(device_name,''),hostname), manufacturer, device_type, status,
            trust_state, risk_band FROM devices""").fetchall():
            ip, name, vendor, dt, st, trust, band = r
            nodes[ip] = {"id": ip, "label": name or ip, "kind": "device",
                         "vendor": vendor or "Unknown",
                         "device_type": dt or "Unclassified",
                         "status": st or "UNKNOWN",
                         "trust": trust or "UNREVIEWED",
                         "risk_band": band or "UNKNOWN"}
        edges = []
        for client, resol, qtype, domain, cnt, ls in conn.execute("""SELECT client_ip,
            resolver_ip, query_type, domain, COUNT(*), MAX(timestamp) FROM dns_events
            WHERE is_response=0 AND resolver_ip!=''
            AND timestamp>=datetime('now','-24 hours')
            GROUP BY client_ip, resolver_ip, query_type, domain
            ORDER BY COUNT(*) DESC LIMIT 500""").fetchall():
            qt = (qtype or "").upper()
            dm = norm_domain(domain or "")
            if qt.startswith("PTR") or dm.endswith(".in-addr.arpa") or dm.endswith(".ip6.arpa"):
                continue
            if resol in {"224.0.0.251", "ff02::fb"} or qt.startswith("MDNS/") or dm.endswith(".local"):
                edge_type = "MDNS_DISCOVERY"
            elif resol in {"224.0.0.252", "ff02::1:3"} or qt.startswith("LLMNR/"):
                edge_type = "LLMNR_DISCOVERY"
            else:
                try:
                    if ipaddress.ip_address(resol).is_multicast:
                        continue
                except ValueError:
                    continue
                edge_type = "DNS_RESOLUTION"
            if client not in nodes:
                nodes[client] = {"id": client, "label": client, "kind": "observed",
                                 "vendor": "Unknown", "device_type": "Not in inventory",
                                 "status": "OBSERVED", "trust": "UNREVIEWED",
                                 "risk_band": "UNKNOWN"}
            if resol not in nodes:
                nodes[resol] = {"id": resol, "label": resol,
                                "kind": "multicast" if "DISCOVERY" in edge_type else "resolver",
                                "vendor": "Unknown",
                                "device_type": "Local discovery multicast" if "DISCOVERY" in edge_type else "DNS resolver",
                                "status": "OBSERVED", "trust": "N/A",
                                "risk_band": "UNKNOWN"}
            edges.append({"source": client, "target": resol, "type": edge_type,
                          "count": cnt, "last_seen": ls,
                          "evidence": "Observed name-resolution traffic; not a physical link."})
        for client, server, cnt, ls in conn.execute("""SELECT client_mac,
            server_ip, COUNT(*), MAX(timestamp) FROM dhcp_events
            WHERE msg_type IN ('OFFER','ACK') AND server_ip!=''
            AND timestamp>=datetime('now','-24 hours')
            GROUP BY client_mac, server_ip ORDER BY COUNT(*) DESC LIMIT 100""").fetchall():
            if server and server not in nodes:
                nodes[server] = {"id": server, "label": server,
                                 "kind": "dhcp_server", "vendor": "Unknown",
                                 "device_type": "DHCP server", "status": "OBSERVED",
                                 "trust": "N/A", "risk_band": "UNKNOWN"}
            edges.append({"source": client, "target": server, "type": "DHCP",
                          "count": cnt, "last_seen": ls})
        return {"nodes": list(nodes.values()), "edges": edges,
                "note": "Edges are observed traffic only, not physical topology."}

def analyze_pcap(path, filename):
    cmd = [str(TSHARK), "-r", str(path), "-T", "fields", "-E",
           "separator=\t", "-e", "frame.number", "-e", "ip.src",
           "-e", "ip.dst", "-e", "dns.qry.name", "-e", "arp.opcode",
           "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac"]
    pc = dc = ac = 0
    domains, clients = set(), set()
    timed_out = threading.Event()
    proc = None
    try:
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8",
                                    errors="replace") as err_file:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=err_file,
                text=True, encoding="utf-8", errors="replace", bufsize=1)
            timer = threading.Timer(180, lambda: (timed_out.set(), proc.kill()))
            timer.daemon = True
            timer.start()
            try:
                for line in proc.stdout:
                    parts = line.rstrip("\r\n").split("\t")
                    if parts and parts[0].strip():
                        pc += 1
                    if len(parts) > 3 and parts[3].strip():
                        dc += 1
                        if len(domains) < 10000:
                            domains.add(parts[3].strip().lower())
                        if len(parts) > 1 and parts[1].strip() and len(clients) < 10000:
                            clients.add(parts[1].strip())
                    if len(parts) > 4 and parts[4].strip():
                        ac += 1
                    if pc >= 5_000_000:
                        proc.kill()
                        break
            finally:
                if proc.stdout:
                    proc.stdout.close()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
                timer.cancel()
            err_file.seek(0)
            stderr_text = err_file.read()[-2000:]
        if timed_out.is_set():
            return {"error": "PCAP analysis exceeded the 180-second time limit."}
        if pc >= 5_000_000:
            return {"error": "PCAP analysis reached the 5-million-record safety limit."}
        if proc.returncode != 0:
            return {"error": _clean(stderr_text, 300)}
    except Exception as exc:
        if proc and proc.poll() is None:
            proc.kill()
        return {"error": _clean(exc, 300)}

    summary = (f"Parsed {pc} records; DNS names: {dc}; unique domains: "
               f"{len(domains)}; source IPs: {len(clients)}; ARP: {ac}.")
    def _w(conn):
        conn.execute("""INSERT INTO pcap_imports(timestamp, file_name, packet_count,
            dns_queries, status, summary) VALUES (?, ?, ?, ?, ?, ?)""",
            (now_text(), filename, pc, dc, "COMPLETED", summary))
        record_event(conn, "-", "PCAP_ANALYSIS", summary, category="forensics")
    DB_MANAGER.write(_w)
    return {"file_name": filename, "packet_count": pc, "dns_queries": dc,
            "unique_domains": len(domains), "arp_packets": ac,
            "source_ips": len(clients), "domains": sorted(domains)[:100],
            "summary": summary}

# ============================================================
# IDENTITY CONTINUITY (PHANTOM TRACK) — dedupe patched for D6
# ============================================================

def _mac_kind(value):
    mac = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).lower()
    if len(mac) != 12 or not re.fullmatch(r"[0-9a-f]{12}", mac):
        return "UNKNOWN"
    first = int(mac[:2], 16)
    if first & 1:
        return "MULTICAST"
    if first & 2:
        return "RANDOMISED_OR_LOCAL"
    if mac == "000000000000":
        return "ZERO"
    return "GLOBAL_UNICAST"

def run_identity_continuity():
    ts = now_text()
    result = {"observed": 0, "stable_anchors": 0, "randomised": 0,
              "candidate_groups": 0, "events": 0}
    def _w(conn):
        rows = conn.execute("""SELECT ip,COALESCE(mac,''),COALESCE(hostname,''),
            COALESCE(device_type,''),COALESCE(status,'UNKNOWN'),COALESCE(device_id,'')
            FROM devices WHERE status='ONLINE' ORDER BY last_seen DESC""").fetchall()
        conn.execute("""UPDATE identity_continuity_registry SET status='HISTORICAL'
            WHERE current_ip IN (SELECT ip FROM devices WHERE status='OFFLINE')""")
        for ip, mac, hostname, dtype, status, existing_id in rows:
            if not ip:
                continue
            kind = _mac_kind(mac)
            dh = conn.execute("""SELECT vendor_class,client_mac,hostname,timestamp
                FROM dhcp_events WHERE client_ip=? ORDER BY id DESC LIMIT 1""",
                (ip,)).fetchone()
            vendor_class = (dh[0] or "") if dh else ""
            if dh and dh[2] and not hostname:
                hostname = dh[2]
            if kind == "GLOBAL_UNICAST":
                anchor_type = "GLOBAL_MAC"
                anchor = "mac:" + re.sub(r"[^0-9a-f]", "", mac.lower())
                confidence = 92
                result["stable_anchors"] += 1
            else:
                anchor_type = "IP_MAC_SCOPED_OBSERVATION"
                anchor = "ipmac:" + ip + ":" + re.sub(r"[^0-9a-f]", "", mac.lower())
                confidence = 38 if kind == "RANDOMISED_OR_LOCAL" else 25
                if kind == "RANDOMISED_OR_LOCAL":
                    result["randomised"] += 1
            anchor_hash = hashlib.sha256(anchor.encode("utf-8")).hexdigest()
            identity_key = anchor_type + ":" + anchor_hash[:24]
            continuity_id = "phantom-" + anchor_hash[:20]
            old = conn.execute(
                "SELECT current_mac,current_ip,hostname,vendor_class "
                "FROM identity_continuity_registry WHERE continuity_id=?",
                (continuity_id,)).fetchone()
            if not old:
                conn.execute("""INSERT INTO identity_continuity_registry
                    (continuity_id,identity_key,anchor_type,anchor_hash,first_seen,last_seen,
                     current_ip,current_mac,hostname,vendor_class,device_type,confidence,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (continuity_id, identity_key, anchor_type, anchor_hash, ts, ts,
                     ip, mac, hostname, vendor_class, dtype, confidence, "OBSERVED"))
                if kind == "GLOBAL_UNICAST":
                    conn.execute("""INSERT INTO identity_continuity_events(timestamp,continuity_id,event_type,severity,ip,new_value,confidence,details)
                        VALUES(?,?,?,?,?,?,?,?)""",
                        (ts, continuity_id, "IDENTITY_ANCHOR_CREATED", "INFO", ip,
                         mac, confidence, "Stable globally administered MAC anchor created."))
                    result["events"] += 1
            else:
                prev_mac, prev_ip, prev_host, prev_vclass = old
                conn.execute("""UPDATE identity_continuity_registry SET last_seen=?,current_ip=?,current_mac=?,
                    hostname=CASE WHEN ?<>'' THEN ? ELSE hostname END,
                    vendor_class=CASE WHEN ?<>'' THEN ? ELSE vendor_class END,
                    device_type=CASE WHEN ?<>'' THEN ? ELSE device_type END,
                    confidence=MAX(confidence,?),status='OBSERVED' WHERE continuity_id=?""",
                    (ts, ip, mac, hostname, hostname, vendor_class, vendor_class,
                     dtype, dtype, confidence, continuity_id))
                if prev_ip != ip:
                    conn.execute("""INSERT INTO identity_continuity_events(timestamp,continuity_id,event_type,severity,ip,old_value,new_value,confidence,details)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                        (ts, continuity_id, "IP_ADDRESS_CHANGED", "INFO", ip,
                         prev_ip, ip, confidence,
                         "Same stable interface anchor observed at a different IP."))
                    result["events"] += 1
                if prev_mac and mac and prev_mac.lower() != mac.lower():
                    conn.execute("""INSERT INTO identity_continuity_events(timestamp,continuity_id,event_type,severity,ip,old_value,new_value,confidence,details)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                        (ts, continuity_id, "MAC_CHANGED", "MEDIUM", ip,
                         prev_mac, mac, confidence,
                         "MAC changed for this anchor; verify whether interface or identity changed."))
                    result["events"] += 1
            fingerprint = "|".join([hostname.strip().lower(),
                                    vendor_class.strip().lower(),
                                    dtype.strip().lower()])
            fp_hash = (hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
                       if fingerprint.strip("|") else "")
            # D6: dedupe within 10-minute window
            existing_obs = conn.execute("""
                SELECT 1 FROM identity_continuity_observations
                WHERE continuity_id=? AND ip=? AND mac=? AND mac_class=?
                  AND timestamp >= datetime('now','-10 minutes')
                LIMIT 1""", (continuity_id, ip, mac, kind)).fetchone()
            if not existing_obs:
                conn.execute("""INSERT INTO identity_continuity_observations
                    (continuity_id,timestamp,ip,mac,hostname,vendor_class,source,fingerprint_hash,mac_class,confidence,details)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (continuity_id, ts, ip, mac, hostname, vendor_class,
                     "DEVICE_INVENTORY+DHCP" if dh else "DEVICE_INVENTORY",
                     fp_hash, kind, confidence,
                     "No automatic cross-device merge; evidence retained as an observation."))
                result["observed"] += 1
        groups = conn.execute("""SELECT lower(hostname),lower(vendor_class),COUNT(DISTINCT continuity_id)
            FROM identity_continuity_registry WHERE hostname<>'' AND vendor_class<>''
            GROUP BY lower(hostname),lower(vendor_class) HAVING COUNT(DISTINCT continuity_id)>1""").fetchall()
        result["candidate_groups"] = len(groups)
        for host, vclass, count in groups:
            details = (f"Shared hostname/vendor-class candidate: {host} / {vclass} "
                       f"({count} separate anchors). Not auto-merged.")
            conn.execute("""INSERT INTO identity_continuity_events(timestamp,event_type,severity,ip,confidence,details)
                SELECT ?, 'POSSIBLE_IDENTITY_CONTINUITY', 'LOW', '', 35, ?
                WHERE NOT EXISTS (SELECT 1 FROM identity_continuity_events
                  WHERE event_type='POSSIBLE_IDENTITY_CONTINUITY'
                    AND details=? AND timestamp>=datetime('now','-1 day'))""",
                (ts, details, details))
        conn.execute("""INSERT INTO identity_integration_registry(integration_id,integration_type,display_name,status,notes,created_at,updated_at)
            VALUES('router-ap','NETWORK_CONTROLLER','Router / Wi-Fi AP telemetry','NOT_CONFIGURED',?,?,?)
            ON CONFLICT(integration_id) DO NOTHING""",
            ("Requires router/AP make, model and supported local API or exported association logs.", ts, ts))
        conn.execute("""INSERT INTO identity_integration_registry(integration_id,integration_type,display_name,status,notes,created_at,updated_at)
            VALUES('radius','RADIUS_8021X','RADIUS / 802.1X identity','NOT_CONFIGURED',?,?,?)
            ON CONFLICT(integration_id) DO NOTHING""",
            ("Can ingest authorised authentication/accounting exports.", ts, ts))
        conn.execute("""INSERT INTO identity_integration_registry(integration_id,integration_type,display_name,status,notes,created_at,updated_at)
            VALUES('endpoint-agent','ENDPOINT_AGENT','Enrolled endpoint identity agent','NOT_CONFIGURED',?,?,?)
            ON CONFLICT(integration_id) DO NOTHING""",
            ("Optional signed/enrolled agent for authenticated hardware/OS inventory.", ts, ts))
        # New in 8.2.0: run candidate assessment after observations are recorded
        try:
            assess_identity_candidates(conn)
        except Exception:
            pass
    DB_MANAGER.write(_w)
    return result

# ============================================================
# WEB DASHBOARD
# ============================================================

# ============================================================
# 9.0.0 PHANTOM INTELLIGENCE ENGINES
# ============================================================

def collect_ipv6_neighbours():
    """Read usable IPv6 neighbour-cache entries and record collection health."""
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        _record_engine_health("IPv6", "UNAVAILABLE", "PowerShell executable not found", {})
        return []
    command = ("Get-NetNeighbor -AddressFamily IPv6 -ErrorAction Stop | "
               "Select-Object IPAddress,LinkLayerAddress,InterfaceIndex,InterfaceAlias,State "
               "| ConvertTo-Json -Compress")
    try:
        proc = subprocess.run([exe,"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass",
                               "-Command",command],capture_output=True,text=True,timeout=15,
                              encoding="utf-8",errors="replace")
        if proc.returncode != 0:
            _record_engine_health("IPv6","ERROR",_clean(proc.stderr or proc.stdout or "PowerShell command failed",300),{})
            return []
        raw = (proc.stdout or "").strip()
        if not raw:
            _record_engine_health("IPv6","NO_DATA","Neighbour cache returned no entries",{})
            return []
        parsed = json.loads(raw)
        rows = parsed if isinstance(parsed,list) else [parsed]
    except subprocess.TimeoutExpired:
        _record_engine_health("IPv6","TIMEOUT","Neighbour cache query exceeded 15 seconds",{})
        return []
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        _record_engine_health("IPv6","ERROR",_clean(exc,300),{})
        return []
    out = []
    for row in rows:
        try:
            raw_ip = str(row.get("IPAddress", "")).split("%", 1)[0]
            addr = ipaddress.ip_address(raw_ip)
            if addr.version != 6 or addr.is_multicast or addr.is_unspecified or addr.is_loopback:
                continue
            state = str(row.get("State", "UNKNOWN")).upper()
            if state not in {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}:
                continue
            mac = _normalise_mac(str(row.get("LinkLayerAddress", "")))
            if mac and not valid_unicast_mac(mac): mac = ""
            out.append({"ipv6":str(addr),"mac":mac,
                "interface_index":int(row.get("InterfaceIndex") or 0),
                "interface_alias":_clean(row.get("InterfaceAlias", ""),100),
                "state":state,"source":"Windows IPv6 neighbour table"})
        except (ValueError,TypeError,AttributeError):
            continue
    _record_engine_health("IPv6","ONLINE" if out else "NO_DATA",
        "Usable neighbour entries collected" if out else "No usable neighbour entries after filtering",
        {"observations":len(out)})
    return out


def _record_engine_health(engine,state,reason,detail):
    try:
        DB_MANAGER.write(lambda conn: conn.execute(
            "INSERT INTO engine_health_events(timestamp,engine,state,reason,detail) VALUES(?,?,?,?,?)",
            (now_text(),engine,state,_clean(reason,500),json.dumps(detail or {}))))
    except Exception:
        pass


def persist_ipv6_observations(rows):
    """Keep a latest-state table plus append-only history; correlate only exact MAC matches."""
    added = 0
    ts = now_text()
    def _w(conn):
        nonlocal added
        for item in rows:
            mac = item.get("mac", "")
            linked = ""
            if mac:
                match = conn.execute("SELECT device_id,ip FROM devices WHERE lower(mac)=lower(?) "
                                     "ORDER BY last_seen DESC LIMIT 1", (mac,)).fetchone()
                if match:
                    linked = match[0] or ""
                    # Attach IPv6 to the IPv4 inventory record only when the neighbour MAC matches exactly.
                    _add_identity_evidence(conn,{"device_id":linked,"ip":match[1]},
                        "Windows IPv6 neighbour table","IPv6 address",item["ipv6"],90,
                        "OBSERVED",APP_VERSION)
            conn.execute("""INSERT INTO ipv6_observations(
                timestamp,ipv6,mac,interface_index,interface_alias,state,source)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(ipv6,mac,interface_index)
                DO UPDATE SET timestamp=excluded.timestamp,
                interface_alias=excluded.interface_alias,state=excluded.state,source=excluded.source""",
                (ts,item["ipv6"],mac,item.get("interface_index",0),
                 item.get("interface_alias",""),item.get("state","UNKNOWN"),
                 item.get("source","Windows IPv6 neighbour table")))
            conn.execute("""INSERT INTO ipv6_observation_events(
                timestamp,ipv6,mac,interface_index,interface_alias,state,source,linked_device_id)
                VALUES(?,?,?,?,?,?,?,?)""",
                (ts,item["ipv6"],mac,item.get("interface_index",0),
                 item.get("interface_alias",""),item.get("state","UNKNOWN"),
                 item.get("source","Windows IPv6 neighbour table"),linked))
            added += 1
    DB_MANAGER.write(_w)
    return added


EXPOSURE_RULES = {
    21: ("HIGH", "FTP service observed", "Confirm that FTP is required; prefer SFTP or FTPS."),
    23: ("HIGH", "Telnet service observed", "Disable Telnet and use an encrypted administration protocol."),
    445: ("MEDIUM", "SMB service observed", "Restrict SMB to trusted network segments and review sharing configuration."),
    3389: ("HIGH", "Remote Desktop service observed", "Restrict RDP to trusted hosts or VPN; require strong authentication."),
    5900: ("HIGH", "VNC service observed", "Restrict remote-control access and require secure authentication."),
    8080: ("LOW", "Alternate HTTP service observed", "Verify whether the web interface requires network-wide access."),
    80: ("LOW", "HTTP service observed", "Check whether the management interface should use HTTPS."),
    161: ("MEDIUM", "SNMP service observed", "Prefer SNMPv3 and restrict management access."),
}


def refresh_exposure_intelligence():
    """Process each new scan result once. Incomplete/missing results never close findings."""
    now = now_text()
    stats = {"observations_upserted": 0, "resolved": 0, "completed_scans": 0, "incomplete_scans": 0}
    def _w(conn):
        row = conn.execute("SELECT last_id FROM intelligence_cursors WHERE cursor_name='exposure' ").fetchone()
        cursor = int(row[0]) if row else 0
        conn.execute("UPDATE exposure_findings SET status='STALE' WHERE status='OPEN' AND last_seen < datetime('now','-30 days')")
        latest_id = conn.execute("SELECT COALESCE(MAX(id),?) FROM port_scan_observations", (cursor,)).fetchone()[0]
        if latest_id <= cursor: return
        # Last result for each IP in this batch wins; if it is incomplete, do not infer closure.
        scans = conn.execute("""SELECT p.id,p.ip,p.device_id,p.open_ports,p.completed,p.timestamp
            FROM port_scan_observations p JOIN (
              SELECT ip,MAX(id) AS max_id FROM port_scan_observations
              WHERE id>? AND id<=? GROUP BY ip
            ) latest ON latest.max_id=p.id""", (cursor,latest_id)).fetchall()
        completed_by_ip = {}
        for sid,ip,did,raw,complete,scan_ts in scans:
            if not complete:
                stats["incomplete_scans"] += 1
                continue
            stats["completed_scans"] += 1
            if not did:
                match=conn.execute("SELECT device_id FROM devices WHERE ip=?",(ip,)).fetchone()
                did=(match[0] or "") if match else ""
            completed_by_ip[ip]=(did,raw or "",scan_ts)
        for ip,(did,raw,scan_ts) in completed_by_ip.items():
            ports={int(x) for x in re.findall(r"(?<!\d)(\d{1,5})(?!\d)",str(raw)) if 1<=int(x)<=65535}
            for port in sorted(ports):
                rule=EXPOSURE_RULES.get(port)
                if not rule: continue
                severity,title,recommendation=rule
                identity=did or ip
                key=hashlib.sha256(f"{identity}|TCP|{port}".encode()).hexdigest()[:32]
                evidence=f"TCP port {port} was reported open by a completed Nmap scan at {scan_ts}."
                conn.execute("""INSERT INTO exposure_findings(
                    finding_key,ip,device_id,rule_id,title,severity,confidence,observed_ports,
                    evidence,recommendation,first_seen,last_seen,status)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'OPEN')
                    ON CONFLICT(finding_key) DO UPDATE SET ip=excluded.ip,device_id=excluded.device_id,
                    observed_ports=excluded.observed_ports,evidence=excluded.evidence,
                    last_seen=excluded.last_seen,status='OPEN'""",
                    (key,ip,did,f"EXPOSED_TCP_{port}",title,severity,85,str(port),evidence,
                     recommendation,now,now))
                stats["observations_upserted"]+=1
        open_rows=conn.execute("SELECT finding_key,ip,device_id,observed_ports FROM exposure_findings WHERE status IN ('OPEN','STALE')").fetchall()
        for key,old_ip,old_did,old_port in open_rows:
            candidates=[]
            if old_did:
                candidates=[(ip,raw) for ip,(did,raw,_) in completed_by_ip.items() if did==old_did]
            elif old_ip in completed_by_ip:
                candidates=[(old_ip,completed_by_ip[old_ip][1])]
            if not candidates: continue
            try: port=int(re.sub(r"\D","",str(old_port or "0")) or 0)
            except ValueError: continue
            # Retire pre-9.5 IP-keyed duplicates after a device-keyed record is created.
            if old_did:
                canonical=hashlib.sha256(f"{old_did}|TCP|{port}".encode()).hexdigest()[:32]
                if key!=canonical and conn.execute("SELECT 1 FROM exposure_findings WHERE finding_key=?",(canonical,)).fetchone():
                    conn.execute("UPDATE exposure_findings SET status='RESOLVED',last_seen=?,evidence=evidence||' | Superseded by identity-keyed record.' WHERE finding_key=?",(now,key))
                    stats["resolved"]+=1
                    continue
            if not any(port in {int(x) for x in re.findall(r"(?<!\d)(\d{1,5})(?!\d)",raw)} for _,raw in candidates):
                conn.execute("UPDATE exposure_findings SET status='RESOLVED',last_seen=? WHERE finding_key=?",(now,key))
                stats["resolved"]+=1
        conn.execute("""INSERT INTO intelligence_cursors(cursor_name,last_id,updated_at) VALUES('exposure',?,?)
            ON CONFLICT(cursor_name) DO UPDATE SET last_id=excluded.last_id,updated_at=excluded.updated_at""",
            (latest_id,now))
    DB_MANAGER.write(_w)
    return {**stats,"timestamp":now,
            "scope":"Completed-scan service observations only; no vulnerability claim."}


def unknown_device_hunter(conn, limit=100):
    rows = conn.execute("""SELECT d.ip,d.device_id,d.mac,d.hostname,d.device_name,
        d.device_type,d.os_guess,d.model,d.identification_confidence,d.status,
        d.last_seen,COUNT(e.id),COUNT(DISTINCT e.source)
        FROM devices d LEFT JOIN device_identity_evidence e ON e.ip=d.ip
        WHERE d.status IN ('ONLINE','SUSPECTED_OFFLINE') AND
        (COALESCE(d.identification_confidence,0)<60 OR
         lower(COALESCE(d.device_type,'')) LIKE '%unclass%' OR
         lower(COALESCE(d.device_type,'')) LIKE '%unknown%' OR
         lower(COALESCE(d.device_name,'')) LIKE '%unident%')
        GROUP BY d.ip ORDER BY COALESCE(d.identification_confidence,0),d.last_seen DESC
        LIMIT ?""", (max(1,min(int(limit),250)),)).fetchall()
    results=[]
    for r in rows:
        results.append({"ip":r[0],"device_id":r[1] or "","mac":r[2] or "",
            "hostname":r[3] or "","name":r[4] or "Unidentified device",
            "device_type":r[5] or "Unclassified","os_guess":r[6] or "Unknown",
            "model":r[7] or "","confidence":int(r[8] or 0),"status":r[9],
            "last_seen":r[10],"evidence_count":int(r[11] or 0),
            "independent_sources":int(r[12] or 0),
            "next_steps":["Collect more passive observations",
                          "Review DHCP, mDNS and service evidence",
                          "Use an authorised endpoint inventory if exact hardware details are needed"]})
    return results


def investigate_unknown_devices(limit=50):
    """Create/update low-severity identity-review investigations from local evidence only."""
    created=updated=0; results=[]
    def _w(conn):
        nonlocal created,updated
        targets=unknown_device_hunter(conn,limit)
        for item in targets:
            ip=item["ip"]; did=item.get("device_id","")
            sources=[r[0] for r in conn.execute(
                "SELECT DISTINCT source FROM device_identity_evidence WHERE ip=? ORDER BY source",(ip,)).fetchall()]
            dhcp=conn.execute("""SELECT timestamp,hostname,vendor_class,parameter_request_list
                FROM dhcp_events WHERE client_ip=? ORDER BY id DESC LIMIT 3""",(ip,)).fetchall()
            dns=conn.execute("""SELECT domain,COUNT(*) AS n,MAX(timestamp) FROM dns_events
                WHERE client_ip=? AND is_response=0 AND domain<>''
                GROUP BY domain ORDER BY n DESC LIMIT 5""",(ip,)).fetchall()
            evidence={"ip":ip,"device_id":did,"confidence":item["confidence"],
                "identity_sources":sources,"dhcp_observations":[list(x) for x in dhcp],
                "frequent_dns_domains":[list(x) for x in dns],
                "observed_ports":conn.execute("SELECT open_ports FROM devices WHERE ip=?",(ip,)).fetchone()[0] or "",
                "interpretation":"Identity uncertainty; not a threat verdict."}
            description=("Automated identity review generated from local observations. "
                f"Confidence={item['confidence']}%; independent evidence sources={len(sources)}. "
                f"Sources: {', '.join(sources) if sources else 'none recorded'}. "
                f"DHCP observations={len(dhcp)}; DNS names={len(dns)}. "
                "Exact hardware model is not inferred without device-reported evidence.")
            existing=conn.execute("""SELECT id FROM investigations WHERE
                ((affected_device_id=? AND ?<>'') OR (affected_ip=? AND ?=''))
                AND title LIKE 'Device identity review:%' AND status IN ('OPEN','INVESTIGATING')
                ORDER BY id DESC LIMIT 1""",(did,did,ip,did)).fetchone()
            if existing:
                iid=existing[0]
                conn.execute("UPDATE investigations SET updated_at=?,description=?,confidence=? WHERE id=?",
                    (now_text(),description,min(70,max(10,item["confidence"])),iid))
                updated+=1
            else:
                cur=conn.execute("""INSERT INTO investigations(timestamp,updated_at,title,description,
                    severity,confidence,status,affected_device_id,affected_ip,notes)
                    VALUES(?,?,?,?,? ,?,'OPEN',?,?,?)""",
                    (now_text(),now_text(),f"Device identity review: {ip}",description,
                     "LOW",min(70,max(10,item["confidence"])),did,ip,
                     "Generated by Unknown Device Hunter; review evidence before conclusions."))
                iid=cur.lastrowid;created+=1
            results.append({"investigation_id":iid,"ip":ip,"device_id":did,
                "confidence":item["confidence"],"evidence_sources":sources,
                "dhcp_observations":len(dhcp),"dns_names":len(dns)})
    DB_MANAGER.write(_w)
    return {"created":created,"updated":updated,"investigations":results,
            "message":"Identity-review investigations created from observed local evidence. These are not threat findings."}


def intelligence_answer(conn, question):
    """Small, read-only query router grounded in local inventory tables."""
    q = _clean(question, 300).lower()
    if not q:
        return {"answer":"Ask a question about devices, unknown identities, IPv6 or exposure.","results":[]}
    if any(k in q for k in ("unknown", "unidentified", "not identified")):
        data=unknown_device_hunter(conn,100)
        return {"answer":f"There are {len(data)} devices in the current Unknown Device Hunter result set. These are devices with low identity confidence or unclassified identity fields.","results":data[:50],"source":"local device inventory and identity evidence"}
    if any(k in q for k in ("expos", "open port", "rdp", "telnet", "smb")):
        rows=conn.execute("SELECT ip,title,severity,observed_ports,evidence,recommendation,last_seen FROM exposure_findings WHERE status IN ('OPEN','STALE') ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,last_seen DESC LIMIT 100").fetchall()
        data=[{"ip":r[0],"finding":r[1],"severity":r[2],"port":r[3],"evidence":r[4],"recommendation":r[5],"last_seen":r[6]} for r in rows]
        return {"answer":f"I found {len(data)} open exposure observations. These indicate observed services, not confirmed vulnerabilities.","results":data,"source":"local exposure_findings"}
    if "ipv6" in q:
        rows=conn.execute("SELECT ipv6,mac,interface_alias,state,timestamp FROM ipv6_observations ORDER BY timestamp DESC LIMIT 100").fetchall()
        data=[{"ipv6":r[0],"mac":r[1],"interface":r[2],"state":r[3],"last_seen":r[4]} for r in rows]
        return {"answer":f"There are {len(data)} recent IPv6 neighbour observations in the local cache.","results":data,"source":"Windows IPv6 neighbour observations"}
    if any(k in q for k in ("new device", "appeared", "today", "recent device")):
        rows=conn.execute("SELECT ip,device_name,device_type,manufacturer,last_seen,identification_confidence FROM devices ORDER BY first_seen DESC LIMIT 50").fetchall()
        data=[{"ip":r[0],"name":r[1],"type":r[2],"manufacturer":r[3],"last_seen":r[4],"confidence":r[5]} for r in rows]
        return {"answer":"Here are the most recently first-seen inventory records. Confirm the first_seen timestamp before interpreting 'today'.","results":data,"source":"local device inventory"}
    if any(k in q for k in ("device", "inventory", "how many", "count")):
        total=conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online=conn.execute("SELECT COUNT(*) FROM devices WHERE status='ONLINE'").fetchone()[0]
        return {"answer":f"The inventory contains {total} historical device records, of which {online} are currently marked ONLINE.","results":[],"source":"local devices table"}
    return {"answer":"I can currently answer read-only questions about device counts, unknown identities, IPv6 observations, recent inventory records and observed service exposure. I will not infer facts that are not stored in NetworkRadar.","results":[],"source":"local query capability limits"}


WEB_PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NetworkRadar {APP_VERSION}</title><style>

:root{color-scheme:dark;--bg:#07101d;--panel:#0d1a2b;--panel2:#10233a;--line:#203b57;--text:#edf5ff;--muted:#91a9c2;--blue:#56b2ff;--cyan:#55e0d0;--green:#45d6a0;--amber:#ffc66d;--red:#ff7185;--shadow:0 18px 44px #0005}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 12% -10%,#16436a 0,transparent 34%),radial-gradient(ellipse at 95% 8%,#123b43 0,transparent 25%),var(--bg);color:var(--text);font:14px/1.55 "Segoe UI Variable","Segoe UI",Arial,sans-serif}
header{padding:22px clamp(18px,4vw,64px) 18px;border-bottom:1px solid #29476188;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;background:linear-gradient(110deg,#0b1c2eeb,#0a1928e8);backdrop-filter:blur(18px)}
.brand{display:flex;gap:15px;align-items:center}.logo{width:50px;height:50px;border-radius:16px;background:linear-gradient(140deg,#2389ee,#53dfcf);display:grid;place-items:center;font-size:21px;font-weight:900;color:#041422;box-shadow:0 8px 28px #2c9de755;position:relative}
h1{font-size:20px;letter-spacing:2px;margin:0;font-weight:800}.sub{color:#9bb9d3;font-size:10px;letter-spacing:2.4px;margin-top:3px}.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button{border:1px solid #65bdff55;border-radius:10px;padding:10px 15px;font-weight:750;cursor:pointer;background:linear-gradient(135deg,#3a9cf0,#56c7d9);color:#031522;box-shadow:0 7px 20px #168be333;transition:transform .16s}
button:hover{transform:translateY(-1px)}button:disabled{opacity:.55;cursor:wait}button.secondary{background:#132b42;color:var(--text);border:1px solid #31516e}
/* 11.0.2 navigation: persistent desktop sidebar + searchable mobile drawer */
:root{--sidebar-width:264px;--sidebar-collapsed:76px;--header-height:82px}
html{scroll-behavior:smooth;scroll-padding-top:calc(var(--header-height) + 18px)}
body{min-height:100vh}
header{position:sticky;top:0;z-index:45;min-height:var(--header-height);margin-left:var(--sidebar-width);padding:14px clamp(18px,3vw,42px);box-shadow:0 8px 28px #0003;transition:margin-left .22s ease}
nav{position:fixed;inset:0 auto 0 0;width:var(--sidebar-width);z-index:60;display:flex;flex-direction:column;align-items:stretch;gap:5px;overflow-y:auto;overflow-x:hidden;padding:18px 13px 24px;background:linear-gradient(180deg,#091827f7,#071321f8);border-right:1px solid #28445f;box-shadow:12px 0 35px #0003;backdrop-filter:blur(18px);font-size:11px;letter-spacing:.7px;scrollbar-width:thin;scrollbar-color:#315675 transparent;transition:width .22s ease,transform .22s ease}
.nav-brand{display:flex;align-items:center;gap:11px;padding:6px 8px 17px;margin-bottom:7px;border-bottom:1px solid #28445f;color:#eaf5ff;font-weight:900;letter-spacing:1.5px}
.nav-brand-mark{width:34px;height:34px;flex:0 0 34px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(140deg,#2389ee,#53dfcf);color:#041422;font-size:14px;font-weight:950}
.nav-brand small{display:block;color:#8faac4;font-size:9px;letter-spacing:1.3px;font-weight:700;margin-top:2px}
.nav-search-wrap{position:sticky;top:-18px;z-index:3;padding:8px 0 12px;background:#091827f7}
#navSearch{width:100%;min-height:40px;padding:9px 12px 9px 35px;border:1px solid #294761;border-radius:10px;background:#0d2033;color:var(--text);font-size:12px}
.nav-search-icon{position:absolute;left:12px;top:18px;color:#8daac4;pointer-events:none}
.nav-group{margin:9px 0 3px;padding:0 9px;color:#6f8da9;font-size:9px;font-weight:900;letter-spacing:1.5px;text-transform:uppercase}
nav a{display:flex;align-items:center;gap:10px;min-height:37px;color:#b4cde3;text-decoration:none;white-space:nowrap;padding:8px 10px;border-radius:9px;border:1px solid transparent;font-weight:750;transition:background .15s,border-color .15s,color .15s}
nav a::before{content:"";width:6px;height:6px;flex:0 0 6px;border-radius:50%;background:#52718e;transition:background .15s,box-shadow .15s}
nav a:hover,nav a:focus-visible{background:#132d46;color:#fff;border-color:#294c6b}
nav a.active{background:linear-gradient(90deg,#17466a,#12334e);color:#fff;border-color:#2a5a7d;box-shadow:inset 3px 0 0 var(--cyan)}
nav a.active::before{background:var(--cyan);box-shadow:0 0 10px #55e0d0aa}
.nav-empty{display:none;padding:12px;color:#9bb4cc;font-size:12px}
#navBackdrop{display:none}
#navToggle{min-width:42px;width:42px;padding:8px;display:grid;place-items:center;font-size:18px;line-height:1;background:#132b42;color:var(--text);border:1px solid #31516e;box-shadow:none}
#navToggle:hover{background:#1a3b59}
main{margin-left:var(--sidebar-width);max-width:none;padding:24px clamp(18px,3vw,42px) 54px;transition:margin-left .22s ease}
body.nav-collapsed nav{width:var(--sidebar-collapsed);padding-left:10px;padding-right:10px}
body.nav-collapsed header,body.nav-collapsed main{margin-left:var(--sidebar-collapsed)}
body.nav-collapsed .nav-brand-copy,body.nav-collapsed .nav-search-wrap,body.nav-collapsed .nav-group,body.nav-collapsed .nav-empty{display:none}
body.nav-collapsed nav a{position:relative;justify-content:center;padding:9px 6px;font-size:0}
body.nav-collapsed nav a::before{display:none}
body.nav-collapsed nav a::after{content:attr(data-short);display:block;color:#d9efff;font-size:11px;font-weight:900;letter-spacing:.2px}
body.nav-collapsed .nav-brand{justify-content:center;padding-left:0;padding-right:0}
body.nav-collapsed .nav-brand-mark{width:38px;height:38px;flex-basis:38px}
body.nav-collapsed #navToggle{margin-inline:auto}

main{padding:24px clamp(18px,4vw,64px) 48px;max-width:1800px;margin:auto}.meta{color:var(--muted);font-size:12px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:16px}
.card{background:linear-gradient(145deg,#122a42ed,#0b1929f2);border:1px solid #284762;border-radius:16px;padding:18px;min-width:0;box-shadow:var(--shadow)}
.section{margin-top:18px}.section h2{font-size:12px;letter-spacing:1.7px;color:#c3e2fa;margin:0 0 12px;font-weight:800}
.label{color:#9db5cc;font-size:10px;letter-spacing:1.45px;text-transform:uppercase}.value{font-size:30px;font-weight:800;margin-top:5px;letter-spacing:-.8px}.hint{color:var(--muted);font-size:12px;margin-top:4px}
.split{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}
.statusline{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid #213b54}.statusline:last-child{border:0}
.pill{font-size:10px;font-weight:850;letter-spacing:.7px;padding:5px 9px;border-radius:99px;background:#153d35;color:var(--green);border:1px solid #2a806d66}
.pill.warn{background:#493819;color:var(--amber);border-color:#a67b3e66}
.pill.bad{background:#48232b;color:var(--red);border-color:#a94b5b66}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}
th{text-align:left;color:#9db6cf;font-weight:750;padding:12px 10px;border-bottom:1px solid #31516d;background:#10263b;position:sticky;top:0;z-index:1;font-size:10px;letter-spacing:1px}
td{padding:11px 10px;border-bottom:1px solid #20374d;overflow-wrap:anywhere;color:#dce9f5}
tbody tr:hover{background:#54b9ff0b}.clickrow{cursor:pointer}.clickrow:focus-visible{outline:2px solid var(--cyan);outline-offset:-2px}.scroll{overflow:auto;max-height:420px;border:1px solid #203b55;border-radius:11px}
.mono{font-family:Consolas,"Cascadia Code",monospace}.muted{color:var(--muted)}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}
.notice{border:1px solid #80632c;background:#2b2417;color:#f5d58c;padding:13px 15px;border-radius:12px;font-size:12px;margin:14px 0}
input,select,textarea{font:inherit;outline:none;background:#07111f;color:#e8f1fb;border:1px solid var(--line);padding:9px 12px;border-radius:8px}
.modal{display:none;position:fixed;inset:0;background:#020812e8;z-index:50;padding:3vh 3vw;overflow:auto;backdrop-filter:blur(8px)}
.modal.open{display:flex;align-items:flex-start;justify-content:center}
.modalbox{width:min(1250px,100%);background:#0c1c2d;border:1px solid #3a5f80;border-radius:18px;padding:22px;box-shadow:0 28px 90px #000a}
.modalhead{display:flex;justify-content:space-between;align-items:center;gap:15px;border-bottom:1px solid var(--line);padding-bottom:14px}
.profilegrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.device-tabs{display:flex;gap:7px;overflow-x:auto;padding:10px 0 12px;margin:0 0 14px;position:sticky;top:0;z-index:4;background:var(--panel,#101a2a);scrollbar-width:thin}
.device-tab{white-space:nowrap;border:1px solid var(--line,#29364a);background:transparent;color:var(--muted,#9aa9bd);padding:8px 11px;border-radius:9px;font-size:11px;letter-spacing:.35px}
.device-tab[aria-selected="true"]{background:var(--accent-soft,#173451);border-color:var(--accent,#49a7ff);color:var(--text,#edf4ff)}
.device-pane{display:none;min-height:180px}.device-pane.active{display:block}
.device-pane h3{margin:8px 0 12px}.device-kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:12px 0}
.device-kpi{border:1px solid var(--line,#29364a);border-radius:11px;padding:12px;background:#0b1422}.device-kpi strong{display:block;font-size:22px;margin-top:5px}
.device-empty{padding:18px;border:1px dashed var(--line,#29364a);border-radius:10px;color:var(--muted,#9aa9bd)}
.device-table{width:100%;min-width:640px}.device-pane .notice,.device-pane .hint{margin:10px 0}
@media(max-width:700px){.device-kpis{grid-template-columns:1fr 1fr}.device-tabs{margin-inline:-3px}.device-tab{padding:8px 9px}}
@media(max-width:420px){.device-kpis{grid-template-columns:1fr}}

.profileitem{background:#10243a;border:1px solid var(--line);border-radius:11px;padding:12px;min-width:0}
.profileitem .value{font-size:14px;overflow-wrap:anywhere;margin-top:5px}
.clickrow{cursor:pointer}.clickrow:hover{background:#173653!important}
.risk-LOW{color:var(--green)}.risk-MEDIUM{color:var(--amber)}.risk-HIGH{color:var(--red)}.risk-CRITICAL{color:var(--red);font-weight:800}
@media(max-width:1050px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.split{grid-template-columns:1fr}.profilegrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
/* 11.0.0 Phantom Access layout */
.sectionhead{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:12px}.phantom-metrics{margin-top:12px}.phantom-metrics .card{padding:13px}.phantom-metrics .value{font-size:25px}#phantomAccess button{white-space:nowrap}#phantomAccess table td{vertical-align:middle}#paOutput{font:12px/1.6 Consolas,"Cascadia Code",monospace;color:#cce5f8}
/* 9.5.0 interaction, readability and responsive refinements */
:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
button{min-height:40px}button:active{transform:translateY(0) scale(.985)}
.card{transition:border-color .18s ease,transform .18s ease}.card:hover{border-color:#3c7197}
nav{scrollbar-width:thin;scrollbar-color:#315675 transparent}nav a{font-weight:750}nav a:focus-visible{background:#183a57}
input,select,textarea{min-height:40px;width:auto;max-width:100%}input::placeholder{color:#718aa3}
.scroll{scrollbar-width:thin;scrollbar-color:#315675 #091827}tbody tr:nth-child(even){background:#ffffff03}
th{backdrop-filter:blur(10px)}
.value{font-variant-numeric:tabular-nums}.mono{font-variant-numeric:tabular-nums}
.notice{line-height:1.65}.hint{line-height:1.6}
@media(max-width:900px){:root{--header-height:74px}header,body.nav-collapsed header{margin-left:0;padding:12px 16px}main,body.nav-collapsed main{margin-left:0;padding:18px 16px 40px}nav,body.nav-collapsed nav{width:min(310px,86vw);transform:translateX(-105%);padding:16px 13px;box-shadow:18px 0 48px #0008}body.nav-open nav{transform:translateX(0)}body.nav-open #navBackdrop{display:block;position:fixed;inset:0;z-index:55;background:#020812b8;backdrop-filter:blur(2px)}body.nav-collapsed .nav-brand-copy,body.nav-collapsed .nav-search-wrap,body.nav-collapsed .nav-group,body.nav-collapsed nav a .nav-label{display:block}body.nav-collapsed nav a{justify-content:flex-start;font-size:11px}body.nav-collapsed nav a::before{display:block}body.nav-collapsed nav a::after{display:none}body.nav-collapsed .nav-brand{justify-content:flex-start}body.nav-collapsed #navToggle{margin-inline:0}html{scroll-padding-top:calc(var(--header-height) + 12px)}}
@media(max-width:700px){header{padding:12px}.brand{gap:10px}.logo{width:42px;height:42px;border-radius:13px}h1{font-size:16px;letter-spacing:1.2px}.sub{font-size:9px;letter-spacing:1.4px}main{padding:16px 12px 32px}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.card{padding:13px;border-radius:13px}.value{font-size:25px}.profilegrid{grid-template-columns:1fr 1fr}.actions{width:auto}.actions button{flex:0 1 auto}.scroll{max-height:360px}table{font-size:11px}th,td{padding:9px 8px}.modal{padding:10px}.modalbox{padding:14px}.modalhead{align-items:flex-start}}
@media(max-width:420px){.brand .sub{letter-spacing:.8px}.actions{gap:6px}.actions button{padding:8px 9px;font-size:11px}.actions #connection{display:none}.grid{grid-template-columns:1fr 1fr}.profilegrid{grid-template-columns:1fr}.label{font-size:9px}button{padding:9px 11px}}
@media(max-width:420px){.grid{grid-template-columns:1fr 1fr}.profilegrid{grid-template-columns:1fr}.label{font-size:9px}button{padding:9px 11px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;animation-duration:.01ms!important;transition-duration:.01ms!important}}


/* ================================================================
   NETWORKRADAR 12.0 — NEXUS DESIGN SYSTEM
   Local-first security operations · responsive layout · accessible UI
   ================================================================ */
:root{
 --bg:#07111f;--panel:#0c1b2d;--panel2:#10253c;--line:#25435f;
 --text:#eef6ff;--muted:#93abc3;--blue:#55aaff;--cyan:#5ce4dc;
 --green:#4de0ad;--amber:#ffc66e;--red:#ff7188;
 --shadow:0 18px 52px #0006;--sidebar-width:270px;--sidebar-collapsed:78px;
 --radius-lg:18px;--radius-md:13px;--focus:0 0 0 3px #55aaff35;
}
body{background:radial-gradient(ellipse at 12% 0%,#123d65 0,transparent 32%),radial-gradient(ellipse at 88% 8%,#0c4b4c 0,transparent 23%),linear-gradient(160deg,#07111f,#091827 58%,#07111f);background-attachment:fixed}
header{background:#081827eF;border-bottom:1px solid #3a638255;backdrop-filter:blur(22px)}
.logo,.nav-brand-mark{background:linear-gradient(145deg,#4da7ff,#62e4d8);box-shadow:0 8px 28px #2c9de755}
nav{background:linear-gradient(180deg,#071624f7,#081321f8);border-right-color:#244967}
nav a{min-height:40px;border-radius:11px;letter-spacing:.25px}
nav a.active{background:linear-gradient(100deg,#174b78,#123c56);box-shadow:inset 3px 0 0 var(--cyan),0 5px 16px #0002}
main{padding-top:30px;padding-bottom:64px}
.card{background:linear-gradient(150deg,#112943ed,#0b1a2bf5 72%);border-color:#2a4c69;border-radius:var(--radius-lg);box-shadow:var(--shadow)}
.card:hover{border-color:#4384ad;transform:translateY(-1px)}
.section h2{font-size:12px;letter-spacing:1.9px;color:#cbe7ff}
.grid{gap:16px}
.phantom-metrics .card{position:relative;overflow:hidden}
.phantom-metrics .card:after{content:"";position:absolute;width:110px;height:110px;right:-42px;top:-45px;border-radius:50%;background:#55aaff12;border:1px solid #55aaff18}
button{border-radius:11px;background:linear-gradient(135deg,#2689e8,#4fc8d9);box-shadow:0 7px 20px #168be32a;letter-spacing:.25px}
button.secondary{background:linear-gradient(145deg,#17344f,#10273d);border-color:#345b7b;color:#eaf5ff;box-shadow:none}
button.secondary:hover{background:#1a4161;border-color:#5ca8dc}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:0;box-shadow:var(--focus);border-color:#65b9ff}
input,select,textarea{background:#071522;border-color:#294a67;border-radius:10px}
input::placeholder,textarea::placeholder{color:#6f8ca7}
.pill{letter-spacing:.8px;padding:6px 10px}
.scroll{border-color:#294762;border-radius:13px;background:#07152255}
th{background:#112a42;color:#b7d4ec}
td{border-bottom-color:#203d57}
tbody tr:nth-child(even){background:#ffffff04}
tbody tr:hover{background:#5bbaff0d}
.sectionhead{padding-bottom:12px;border-bottom:1px solid #27455f}
#phantomAccess .notice{background:linear-gradient(100deg,#352b19,#251f18);border-color:#8a6a32;color:#ffe0a1}
#phantomAccess .profileitem{background:linear-gradient(145deg,#102840,#0b1c2d);border-color:#2a4b68}
#phantomAccess .pa-row-actions{white-space:nowrap;min-width:220px}
#phantomAccess .pa-row-actions button{margin:2px;padding:8px 10px;font-size:10px}
#paOutput{background:#06131f;border-color:#294761;border-radius:13px}
.terminal-shell{margin-top:18px;padding:0!important;overflow:hidden;border-color:#2b5879!important;background:linear-gradient(150deg,#0c1e31,#081522)!important}
.terminal-topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:14px 17px;border-bottom:1px solid #2a4a64;background:linear-gradient(90deg,#102c45,#0c2135)}
.terminal-topbar>div{display:flex;align-items:center;gap:10px;flex-wrap:wrap;letter-spacing:1.2px;font-size:11px}
.terminal-led{width:9px;height:9px;border-radius:50%;background:#52dfb0;box-shadow:0 0 12px #52dfb088}
.terminal-subtitle{color:#86a8c4;font-size:9px;letter-spacing:1px}
.terminal-grid{display:grid;grid-template-columns:minmax(230px,290px) minmax(0,1fr);min-height:430px}
.terminal-connect{padding:16px;display:flex;flex-direction:column;gap:10px;border-right:1px solid #29445d;background:#0b1a2a}
.terminal-connect label{display:flex;flex-direction:column;gap:5px;color:#a9c1d8;font-size:10px;font-weight:800;letter-spacing:.9px;text-transform:uppercase}
.terminal-connect input,.terminal-connect select{width:100%;font-size:12px;min-width:0}
.terminal-connect button{width:100%;font-size:10px;min-height:38px}
.ssh-auth-field[hidden]{display:none!important}
.fingerprint-box{padding:11px;border:1px dashed #416783;border-radius:10px;background:#061421;color:#9dc6e8;font:11px/1.6 Consolas,monospace;overflow-wrap:anywhere;min-height:58px}
.terminal-connect .hint{font-size:10px;line-height:1.6}
.terminal-workspace{min-width:0;display:flex;flex-direction:column;padding:12px;background:#050d16}
.terminal-toolbar,.terminal-footer{display:flex;align-items:center;justify-content:space-between;gap:10px;color:#88a6c0;font:10px/1.4 Consolas,monospace;padding:4px 3px 10px}
.terminal-toolbar button{font:9px/1.2 "Segoe UI",sans-serif;min-height:30px;padding:6px 10px}
.terminal-output{flex:1;min-height:300px;max-height:520px;overflow:auto;margin:0;padding:16px;border:1px solid #1d394f;border-radius:10px;background:#02080e;color:#b8e8ce;font:12px/1.65 Consolas,"Cascadia Code",monospace;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4}
.terminal-input{width:100%;min-height:58px;resize:vertical;margin-top:8px;border:1px solid #28506a;background:#071522;color:#e4f4ff;font:12px/1.5 Consolas,monospace}
.terminal-footer{padding:9px 3px 0;font-size:9px;flex-wrap:wrap}
#paSelectionCount{display:inline-flex;align-items:center;border:1px solid #315c7d;background:#0b2032;color:#a9d8f5;border-radius:99px;padding:5px 10px;font:10px/1.2 Consolas,monospace;margin-top:6px}
@media(max-width:1000px){.terminal-grid{grid-template-columns:1fr}.terminal-connect{border-right:0;border-bottom:1px solid #29445d;display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.terminal-connect .hint,.fingerprint-box{grid-column:1/-1}.terminal-connect button{align-self:end}}
@media(max-width:700px){main{padding:16px 12px 36px}.card{border-radius:14px}.terminal-connect{grid-template-columns:1fr}.terminal-topbar{align-items:flex-start}.terminal-subtitle{display:none}.terminal-output{min-height:240px}.terminal-workspace{padding:9px}.terminal-footer{font-size:8px}}
@media(prefers-reduced-motion:reduce){.card:hover,button:hover{transform:none}}
.phantom-metrics{grid-template-columns:repeat(5,minmax(0,1fr))}
@media(max-width:1100px){.phantom-metrics{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:600px){.phantom-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}

.terminal-renderer-note{padding:0 3px 4px;color:#6788a4;font:9px/1.5 "Segoe UI",sans-serif}


/* ================================================================
   NETWORKRADAR 12.0.2 — SIDEBAR + RESPONSIVE LAYOUT HOTFIX
   Fixes the previous `main { margin:auto }` cascade overriding the
   navigation offsets. Keep this block last in the stylesheet.
   ================================================================ */
:root{
  --sidebar-width:272px;
  --sidebar-collapsed:78px;
  --header-height:78px;
  --nr-ease:cubic-bezier(.2,.75,.25,1);
}
html{scroll-padding-top:calc(var(--header-height) + 18px)}
body{min-width:320px;overflow-x:hidden}
header{
  box-sizing:border-box;
  width:calc(100% - var(--sidebar-width));
  margin:0 0 0 var(--sidebar-width)!important;
  transition:width .24s var(--nr-ease),margin-left .24s var(--nr-ease),padding .2s ease;
}
main{
  box-sizing:border-box;
  width:calc(100% - var(--sidebar-width));
  max-width:none!important;
  margin:0 0 0 var(--sidebar-width)!important;
  padding:26px clamp(18px,2.8vw,42px) 64px;
  transition:width .24s var(--nr-ease),margin-left .24s var(--nr-ease),padding .2s ease;
}
#sideNavigation{
  box-sizing:border-box;
  width:var(--sidebar-width);
  min-width:0;
  height:100dvh;
  transform:translateX(0);
  transition:width .24s var(--nr-ease),transform .24s var(--nr-ease),padding .24s ease;
  overscroll-behavior:contain;
}
body.nav-collapsed header,body.nav-collapsed main{
  width:calc(100% - var(--sidebar-collapsed));
  margin-left:var(--sidebar-collapsed)!important;
}
body.nav-collapsed #sideNavigation{
  width:var(--sidebar-collapsed);
  padding-left:9px;padding-right:9px;
}
body.nav-collapsed #sideNavigation .nav-brand-copy,
body.nav-collapsed #sideNavigation .nav-search-wrap,
body.nav-collapsed #sideNavigation .nav-group,
body.nav-collapsed #sideNavigation .nav-empty{display:none!important}
body.nav-collapsed #sideNavigation .nav-brand{
  justify-content:center;padding-inline:0;gap:0;
}
body.nav-collapsed #sideNavigation .nav-brand-mark{margin:0}
body.nav-collapsed #sideNavigation a{
  width:100%;min-width:0;min-height:43px;padding:8px 4px;
  justify-content:center;gap:0;overflow:hidden;font-size:0;
}
body.nav-collapsed #sideNavigation a .nav-label{
  display:none!important;
}
body.nav-collapsed #sideNavigation a::before{display:none}
body.nav-collapsed #sideNavigation a::after{
  content:attr(data-short);display:grid;place-items:center;
  width:34px;height:30px;border-radius:9px;
  color:#d9efff;font-size:10px;font-weight:900;letter-spacing:.25px;
  background:#ffffff08;border:1px solid #ffffff0b;
}
body.nav-collapsed #sideNavigation a:hover::after,
body.nav-collapsed #sideNavigation a.active::after{
  color:#071522;background:var(--cyan);border-color:var(--cyan);
}
#navToggle{flex:0 0 42px;position:relative;z-index:2}
#navBackdrop{display:none}
@media(max-width:900px){
  :root{--header-height:72px}
  header,body.nav-collapsed header{
    width:100%;margin:0!important;padding:11px 16px;
  }
  main,body.nav-collapsed main{
    width:100%;margin:0!important;padding:18px 16px 42px;
  }
  #sideNavigation,body.nav-collapsed #sideNavigation{
    position:fixed;inset:0 auto 0 0;
    width:min(320px,88vw);height:100dvh;max-height:100dvh;
    padding:16px 13px 24px;
    transform:translate3d(-105%,0,0);
    z-index:1002;
    box-shadow:22px 0 60px #0009;
  }
  body.nav-open #sideNavigation{
    transform:translate3d(0,0,0);
  }
  body.nav-collapsed #sideNavigation .nav-brand-copy,
  body.nav-collapsed #sideNavigation .nav-search-wrap,
  body.nav-collapsed #sideNavigation .nav-group,
  body.nav-collapsed #sideNavigation .nav-empty{display:block!important}
  body.nav-collapsed #sideNavigation a{
    justify-content:flex-start;gap:10px;font-size:11px;padding:8px 10px;
  }
  body.nav-collapsed #sideNavigation a .nav-label{display:inline!important}
  body.nav-collapsed #sideNavigation a::before{display:block}
  body.nav-collapsed #sideNavigation a::after{display:none}
  body.nav-collapsed #sideNavigation .nav-brand{justify-content:flex-start;padding:6px 8px 17px}
  body.nav-open #navBackdrop{
    display:block;position:fixed;inset:0;z-index:1001;
    background:#020812b8;backdrop-filter:blur(3px);
  }
}
@media(max-width:600px){
  header{gap:10px;align-items:center}
  header .actions{gap:7px}
  main{padding:15px 12px 34px}
}
@media(prefers-reduced-motion:reduce){
  #sideNavigation,header,main{transition:none!important}
}



/* ================================================================
   DEVICE INTELLIGENCE MODAL — VIEWPORT FIT & RESPONSIVE CONTENT
   Fixes: oversized detail panel, clipped lower sections, wide tables,
   overflowing identity cards, and poor small-screen tab navigation.
   ================================================================ */
.modal{
  padding:clamp(8px,2.2vh,24px) clamp(8px,2vw,24px);
  overflow-x:hidden;
  overflow-y:auto;
  overscroll-behavior:contain;
}
.modal.open{
  align-items:center;
  justify-content:center;
}
.modalbox{
  display:flex;
  flex-direction:column;
  width:min(1240px,100%);
  max-width:100%;
  max-height:calc(100dvh - 2 * clamp(8px,2.2vh,24px));
  min-height:0;
  padding:clamp(12px,2vw,22px);
  overflow:hidden;
}
.modalhead{
  flex:0 0 auto;
  position:relative;
  z-index:6;
  gap:12px;
  padding:0 0 12px;
}
.modalhead h2{
  margin:3px 0 0;
  font-size:clamp(16px,2vw,22px);
  line-height:1.3;
  overflow-wrap:anywhere;
}
.modalcontent{
  flex:1 1 auto;
  min-width:0;
  min-height:0;
  overflow-x:hidden;
  overflow-y:auto;
  overscroll-behavior:contain;
  scrollbar-width:thin;
  scrollbar-color:#315675 #091827;
  padding:0 2px 4px 0;
}
.device-tabs{
  position:sticky;
  top:0;
  z-index:5;
  max-width:100%;
  overflow-x:auto;
  overflow-y:hidden;
  flex-wrap:nowrap;
  padding:10px 2px 12px;
  margin:0 0 12px;
  background:#0c1c2d;
  border-bottom:1px solid #203b55;
  -webkit-overflow-scrolling:touch;
  overscroll-behavior-x:contain;
}
.device-tab{flex:0 0 auto;min-height:36px}
.device-pane{min-width:0;overflow-wrap:anywhere}
.device-pane h3{
  margin:18px 0 10px;
  font-size:11px;
  line-height:1.5;
  letter-spacing:1.15px;
  color:#c3e2fa;
}
.profilegrid{
  grid-template-columns:repeat(auto-fit,minmax(min(100%,205px),1fr));
  align-items:stretch;
}
.profileitem,.device-kpi{min-width:0;overflow:hidden}
.profileitem .value{
  max-width:100%;
  overflow-wrap:anywhere;
  word-break:break-word;
  line-height:1.45;
}
.device-kpis{grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr))}
.device-table{width:100%;min-width:640px;table-layout:auto}
.device-pane .scroll{
  width:100%;
  max-width:100%;
  max-height:min(42vh,390px);
  overflow:auto;
  overscroll-behavior:contain;
  -webkit-overflow-scrolling:touch;
}
.device-pane .scroll table th{position:sticky;top:0;z-index:2}
.device-pane .scroll td,.device-pane .scroll th{vertical-align:top}
.device-empty{overflow-wrap:anywhere;line-height:1.65}

@media(max-width:900px){
  .modal{padding:10px}
  .modalbox{
    width:100%;
    max-height:calc(100dvh - 20px);
    border-radius:15px;
  }
  .device-pane .scroll{max-height:38vh}
}
@media(max-width:600px){
  .modal{padding:6px}
  .modal.open{align-items:center}
  .modalbox{
    max-height:calc(100dvh - 12px);
    padding:12px;
    border-radius:13px;
  }
  .modalhead{align-items:center;gap:8px;padding-bottom:10px}
  .modalhead button{flex:0 0 auto;padding:8px 10px;min-height:36px}
  .modalhead h2{font-size:16px}
  .device-tabs{margin-inline:-2px;gap:6px;padding:9px 2px 10px}
  .device-tab{padding:7px 9px;font-size:10px}
  .profilegrid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .profileitem{padding:10px}
  .profileitem .label{font-size:9px;letter-spacing:1px}
  .profileitem .value{font-size:13px}
  .device-kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .device-kpi{padding:10px}
  .device-kpi strong{font-size:19px}
  .device-pane .scroll{max-height:34vh}
}
@media(max-width:380px){
  .modalbox{padding:9px}
  .profilegrid,.device-kpis{grid-template-columns:minmax(0,1fr)}
  .modalhead h2{font-size:14px}
  .device-tab{padding:7px 8px;font-size:9px}
}
@media(max-height:620px){
  .modal{padding:6px}
  .modalbox{max-height:calc(100dvh - 12px)}
  .device-tabs{padding-top:6px;padding-bottom:8px}
  .device-pane .scroll{max-height:30vh}
}

</style></head><body>
<header><div class="brand"><button id="navToggle" class="secondary" type="button" aria-label="Toggle navigation" aria-expanded="true" title="Collapse or open navigation" onclick="toggleNavigation()">☰</button><div class="logo">NR</div><div><h1>NETWORKRADAR {APP_VERSION}</h1><div class="sub">PHANTOM INTELLIGENCE &amp; NETWORK DEFENCE</div></div></div>
<div class="actions"><span id="connection" class="pill warn">CONNECTING</span><button id="scanButton" onclick="scanNow()">SCAN NOW</button><button class="secondary" onclick="refreshAll()">REFRESH</button></div></header>
<nav id="sideNavigation" aria-label="Main navigation">
 <div class="nav-brand"><div class="nav-brand-mark">NR</div><div class="nav-brand-copy">NETWORKRADAR<small>CONTROL CENTRE</small></div></div>
 <div class="nav-search-wrap"><span class="nav-search-icon">⌕</span><input id="navSearch" type="search" placeholder="Find a section…" aria-label="Search navigation sections"></div>
 <div class="nav-group">Overview</div>
 <a href="#cmd" data-short="CC" title="Command centre"><span class="nav-label">Command centre</span></a><a href="#devices" data-short="DV" title="Devices"><span class="nav-label">Devices</span></a><a href="#engines" data-short="EH" title="Engine health"><span class="nav-label">Engine health</span></a>
 <div class="nav-group">Device intelligence</div>
 <a href="#identity" data-short="ID" title="Radar identity"><span class="nav-label">Radar identity</span></a><a href="#continuity" data-short="PT" title="Phantom Track"><span class="nav-label">Phantom Track</span></a><a href="#candidates" data-short="IC" title="Identity candidates"><span class="nav-label">Identity candidates</span></a><a href="#unknownHunter" data-short="UH" title="Unknown Device Hunter"><span class="nav-label">Unknown Device Hunter</span></a><a href="#ipv6" data-short="V6" title="IPv6 intelligence"><span class="nav-label">IPv6 intelligence</span></a>
 <div class="nav-group">Network activity</div>
 <a href="#profiles" data-short="NP" title="Network profiles"><span class="nav-label">Network profiles</span></a><a href="#dns" data-short="DN" title="DNS intelligence"><span class="nav-label">DNS intelligence</span></a><a href="#dhcp" data-short="DH" title="DHCP"><span class="nav-label">DHCP</span></a><a href="#arp" data-short="AR" title="ARP"><span class="nav-label">ARP</span></a><a href="#behaviour" data-short="BH" title="Behaviour"><span class="nav-label">Behaviour</span></a><a href="#changes" data-short="CH" title="Network changes"><span class="nav-label">Network changes</span></a>
 <div class="nav-group">Security &amp; investigations</div>
 <a href="#investigations" data-short="IN" title="Investigations"><span class="nav-label">Investigations</span></a><a href="#alerts" data-short="AL" title="Alert stream"><span class="nav-label">Alert stream</span></a><a href="#config" data-short="AU" title="Configuration audit"><span class="nav-label">Configuration audit</span></a><a href="#hunt" data-short="TH" title="Threat hunt"><span class="nav-label">Threat hunt</span></a><a href="#exposure" data-short="EX" title="Exposure intelligence"><span class="nav-label">Exposure intelligence</span></a>
 <div class="nav-group">Remote management</div>
 <a href="#phantomAccess" data-short="PA" title="Phantom Access"><span class="nav-label">Phantom Access</span></a><a href="#commandCenter" data-short="ME" title="Managed endpoints"><span class="nav-label">Managed endpoints</span></a>
 <div class="nav-group">Tools &amp; reports</div>
 <a href="#assistant" data-short="AI" title="Intelligence assistant"><span class="nav-label">Intelligence assistant</span></a><a href="#reports" data-short="RP" title="Reports"><span class="nav-label">Reports</span></a>
 <div class="nav-empty" id="navEmpty">No matching sections.</div>
</nav><div id="navBackdrop" aria-hidden="true" onclick="closeNavigation()"></div>
<main>
<div class="meta" id="cmd">LOCAL · <span id="network">...</span> · <span id="updated">—</span></div>
<section class="card" style="margin-bottom:14px"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><div><div class="label">ENGINE</div><strong id="jobPhase">Init</strong><div class="hint" id="jobMessage">—</div></div><div style="font-size:22px;font-weight:800" id="jobPercent">0%</div></div><div style="height:9px;background:#07111f;border:1px solid var(--line);border-radius:99px;overflow:hidden;margin-top:12px"><div id="jobBar" style="height:100%;width:0%;background:linear-gradient(90deg,#2689ee,#39d6b0);transition:width .35s ease"></div></div></section>
<div class="grid">
<div class="card"><div class="label">Devices online</div><div class="value" id="online">—</div><div class="hint" id="deviceHint">—</div></div>
<div class="card"><div class="label">Historical</div><div class="value" id="historical">—</div><div class="hint">SQLite</div></div>
<div class="card"><div class="label">Open investigations</div><div class="value" id="openInvestigations">—</div></div>
<div class="card"><div class="label">Network risk</div><div class="value risk-UNKNOWN" id="networkRisk">—</div></div>
</div>
<div class="split">
<section class="card" id="engines"><h2>ENGINE HEALTH</h2>
<div class="statusline"><span>Discovery</span><span class="pill" id="nmapStatus">ONLINE</span></div>
<div class="statusline"><span>DNS</span><span class="pill warn" id="dnsStatus">STARTING</span></div>
<div class="statusline"><span>DHCP</span><span class="pill warn" id="dhcpStatus">STARTING</span></div>
<div class="statusline"><span>ARP</span><span class="pill warn" id="arpStatus">STARTING</span></div>
<div class="statusline"><span>DHCP classification</span><span class="mono" id="dhcpClass">—</span></div>
<div class="statusline"><span>Network context</span><span class="mono" id="netAuthz">—</span></div>
<div class="statusline"><span>DB queue</span><span class="mono" id="dbQueue">—</span></div>
<div class="statusline"><span>Scan quality</span><span class="mono" id="scanQuality">—</span></div>
</section>
<section class="card"><h2>NETWORK CONTEXT</h2>
<div class="profilegrid">
<div class="profileitem"><div class="label">SUBNET</div><div class="value" id="activeSubnet">...</div></div>
<div class="profileitem"><div class="label">GATEWAY</div><div class="value" id="defaultGateway">—</div></div>
<div class="profileitem"><div class="label">FINGERPRINT</div><div class="value mono" id="fingerprint">—</div></div>
<div class="profileitem"><div class="label">CONFIDENCE</div><div class="value" id="fpConf">—</div></div>
</div>
<div class="hint" id="networkWarning" style="margin:12px 0">Loading...</div>
<button id="authorizeNetwork" onclick="authorizeCurrentNetwork()" style="display:none">AUTHORISE THIS NETWORK</button>
</section>
</div>
<section id="devices" class="section card">
<div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
<h2 style="margin:0">DEVICE INVENTORY</h2>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<input id="deviceSearch" oninput="filterDevices()" placeholder="Search IP, name, MAC..." style="min-width:240px">
<select id="deviceFilter" onchange="filterDevices()"><option value="ALL">All</option><option value="ONLINE">Online</option><option value="OFFLINE">Offline</option><option value="TRUSTED">Trusted</option></select>
</div></div>
<div class="muted" style="font-size:12px;margin-bottom:10px">Identity uses multiple evidence sources. NIC manufacturer ≠ device manufacturer. Confidence ≠ certainty.</div>
<div class="scroll"><table><thead><tr><th>IP</th><th>NAME</th><th>TYPE</th><th>VENDOR</th><th>ID</th><th>RISK</th><th>STATUS</th></tr></thead><tbody id="deviceRows"><tr><td colspan="7">Loading...</td></tr></tbody></table></div>
</section>
<section id="identity" class="section card"><h2>RADAR IDENTITY INTELLIGENCE</h2>
<div class="grid" style="margin-top:12px"><div class="card"><div class="label">Devices with evidence</div><div class="value" id="idDevices">—</div></div><div class="card"><div class="label">Evidence records</div><div class="value" id="idEvidence">—</div></div><div class="card"><div class="label">IEEE OUI entries</div><div class="value" id="ouiEntries">—</div></div><div class="card"><div class="label">Last identity run</div><div class="value" style="font-size:14px" id="idLastRun">—</div></div></div>
<button class="secondary" style="margin-top:10px" onclick="updateOUI()">UPDATE IEEE OUI DATABASE</button>
</section>
<section id="continuity" class="section card"><div style="display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap"><div><h2 style="margin:0">PHANTOM TRACK · IDENTITY CONTINUITY</h2><div class="hint">Stable globally administered MACs anchor identity. Randomised MACs remain IP-scoped. Similar hostnames/vendor classes are review candidates only; no automatic merges.</div></div><button class="secondary" id="continuityRun" onclick="runContinuity()">RUN CONTINUITY ANALYSIS</button></div>
<div class="grid" style="margin-top:14px"><div class="card"><div class="label">Tracked anchors</div><div class="value" id="ctTracked">—</div></div><div class="card"><div class="label">Stable MAC anchors</div><div class="value" id="ctStable">—</div></div><div class="card"><div class="label">Randomised / local</div><div class="value" id="ctRandom">—</div></div><div class="card"><div class="label">Continuity events</div><div class="value" id="ctEvents">—</div></div></div>
<div class="scroll" style="margin-top:14px"><table><thead><tr><th>ANCHOR</th><th>IP</th><th>CLASS</th><th>HOSTNAME</th><th>VENDOR CLASS</th><th>CONF</th><th>OBS</th><th>LAST SEEN</th></tr></thead><tbody id="continuityRows"><tr><td colspan="8">Run continuity analysis to build observation ledger.</td></tr></tbody></table></div>
</section>
<section id="candidates" class="section card"><h2>IDENTITY CANDIDATES (MANUAL REVIEW)</h2>
<div class="hint">No cross-anchor identity is auto-merged. Similar hostnames/vendor classes are not proof; review requires independent unique evidence.</div>
<div class="scroll" style="margin-top:10px"><table><thead><tr><th>ID</th><th>DEVICE A</th><th>DEVICE B</th><th>OUTCOME</th><th>SCORE</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody id="candidateRows"><tr><td colspan="7">No candidates.</td></tr></tbody></table></div>
</section>
<section id="profiles" class="section card"><h2>NETWORK PROFILES</h2>
<div class="hint" style="margin-bottom:10px">Keyed by fingerprint. Approved profile + fingerprint confidence ≥ 55% required for active discovery.</div>
<div class="scroll"><table><thead><tr><th>SUBNET</th><th>FINGERPRINT</th><th>GATEWAY</th><th>APPROVED</th><th>CONF</th><th>LAST SEEN</th></tr></thead><tbody id="profileRows"><tr><td colspan="6">Loading...</td></tr></tbody></table></div>
</section>
<div class="split section" id="dns">
<section class="card"><h2>TOP DOMAINS</h2><div class="scroll"><table><thead><tr><th>DOMAIN</th><th>Q</th><th>RISK</th></tr></thead><tbody id="domainRows"><tr><td colspan="3">—</td></tr></tbody></table></div></section>
<section class="card"><h2>DNS ALERTS</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE</th><th>RULE</th><th>SEV</th></tr></thead><tbody id="alertRows"><tr><td colspan="4">—</td></tr></tbody></table></div></section>
</div>
<div class="split section" id="dhcp">
<section class="card"><h2>DHCP</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>MSG</th><th>MAC</th><th>IP</th><th>SERVER</th><th>HOST</th></tr></thead><tbody id="dhcpRows"><tr><td colspan="6">—</td></tr></tbody></table></div></section>
<section class="card" id="arp"><h2>ARP</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>OP</th><th>IP</th><th>MAC</th><th>FLAG</th></tr></thead><tbody id="arpRows"><tr><td colspan="5">—</td></tr></tbody></table></div></section>
</div>
<section id="behaviour" class="section card"><h2>BEHAVIOUR</h2><div class="hint" id="behaviourStatus">Checking baseline coverage...</div><div class="scroll" style="margin-top:10px"><table><thead><tr><th>DEVICE</th><th>METRIC</th><th>SEV</th><th>OBS</th><th>BASE</th></tr></thead><tbody id="behaviourRows"><tr><td colspan="5">None.</td></tr></tbody></table></div></section>
<section id="changes" class="section card"><h2>NETWORK CHANGES</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>CHANGE</th><th>CAT</th><th>SEV</th><th>IP</th><th>DETAILS</th></tr></thead><tbody id="changeRows"><tr><td colspan="6">None.</td></tr></tbody></table></div></section>
<section id="investigations" class="section card"><h2>INVESTIGATIONS</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>TITLE</th><th>SEV</th><th>STATUS</th><th>EVIDENCE</th></tr></thead><tbody id="investigationRows"><tr><td colspan="5">None.</td></tr></tbody></table></div></section>
<section id="alerts" class="section card"><h2>ALERT STREAM</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>RULE</th><th>SEV</th><th>TITLE</th><th>COUNT</th><th>INV</th></tr></thead><tbody id="alertStreamRows"><tr><td colspan="7">None.</td></tr></tbody></table></div></section>
<section id="config" class="section card"><h2>CONFIG AUDIT</h2><div class="scroll"><table><thead><tr><th>SEV</th><th>FINDING</th><th>EVIDENCE</th><th>RECOMMENDATION</th><th>STATUS</th></tr></thead><tbody id="configRows"><tr><td colspan="5">No findings.</td></tr></tbody></table></div></section>
<section id="hunt" class="section card"><h2>THREAT HUNT</h2>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
<select id="huntTemplate" style="flex:1;min-width:240px"><option value="">Select...</option></select>
<button onclick="runHunt()">RUN</button></div>
<div class="hint" id="huntResult">Select a template.</div>
<div class="scroll" style="margin-top:10px"><table><thead id="huntHead"><tr><th>—</th></tr></thead><tbody id="huntRows"><tr><td>No query.</td></tr></tbody></table></div>
</section>
<section id="reports" class="section card"><h2>REPORTS</h2>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">
<select id="reportType"><option value="daily">Daily</option><option value="devices">Devices</option><option value="investigations">Investigations</option><option value="changes">Changes</option><option value="threats">Threats</option><option value="health">Health</option><option value="config">Config</option></select>
<select id="reportFormat"><option value="json">JSON</option><option value="csv">CSV</option><option value="html">HTML</option></select>
<button onclick="downloadReport()">DOWNLOAD</button></div>
</section>
<section class="section card"><h2>RECENT EVENTS</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE</th><th>CAT</th><th>EVENT</th><th>DETAILS</th></tr></thead><tbody id="eventRows"><tr><td colspan="5">Loading...</td></tr></tbody></table></div></section>

<section class="section card" id="unknownHunter"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><div><h2 style="margin:0">UNKNOWN DEVICE HUNTER</h2><div class="hint">Devices with weak or incomplete identity evidence. A low score is uncertainty, not proof of a threat.</div></div><button class="secondary" onclick="investigateUnknown()">INVESTIGATE UNKNOWN DEVICES</button></div><div class="hint" id="unknownInvestigationStatus" style="margin-top:8px">Investigation is read-only and creates low-severity identity-review records.</div><div class="scroll" style="margin-top:12px"><table><thead><tr><th>IP</th><th>NAME</th><th>TYPE</th><th>OS</th><th>CONFIDENCE</th><th>EVIDENCE</th><th>STATUS</th></tr></thead><tbody id="unknownRows"><tr><td colspan="7">Loading…</td></tr></tbody></table></div></section>
<section class="section card" id="ipv6"><h2>IPV6 NEIGHBOUR INTELLIGENCE</h2><div class="hint">Read-only observations from the Windows IPv6 neighbour cache. This does not sweep the IPv6 subnet.</div><div class="scroll" style="margin-top:12px"><table><thead><tr><th>IPV6 ADDRESS</th><th>MAC</th><th>INTERFACE</th><th>STATE</th><th>LAST OBSERVED</th><th>IDENTITY LINK</th></tr></thead><tbody id="ipv6Rows"><tr><td colspan="6">Loading…</td></tr></tbody></table></div></section>
<section class="section card" id="exposure"><h2>EXPOSURE INTELLIGENCE</h2><div class="notice">These are observed open-service exposures, not confirmed vulnerabilities. No exploitation is performed.</div><div class="scroll"><table><thead><tr><th>IP</th><th>OBSERVATION</th><th>SEVERITY</th><th>PORT</th><th>RECOMMENDATION</th><th>LAST SEEN</th><th>STATUS</th></tr></thead><tbody id="exposureRows"><tr><td colspan="7">Loading…</td></tr></tbody></table></div></section>
<section class="section card" id="assistant"><h2>NETWORKRADAR INTELLIGENCE ASSISTANT</h2><div class="hint">Read-only assistant grounded in the local NetworkRadar database.</div><div style="display:flex;gap:8px;flex-wrap:wrap;margin:12px 0"><input id="assistantQuestion" style="flex:1;min-width:220px" placeholder="e.g. Which devices remain unidentified?"/><button onclick="askRadar()">ASK RADAR</button></div><div id="assistantAnswer" class="profileitem">Ask a question to inspect your local inventory.</div><div class="scroll" style="margin-top:12px"><table><thead><tr><th>DETAIL</th><th>VALUE</th></tr></thead><tbody id="assistantRows"></tbody></table></div></section>
<section class="section card" id="phantomAccess">
<div class="sectionhead"><div><h2>PHANTOM ACCESS · UNIVERSAL ENDPOINT ACCESS</h2><div class="hint">Multi-protocol access for authorised endpoints: Windows native management, SSH terminal sessions, and a capability-aware access path for other device types.</div></div><button class="secondary" onclick="loadPhantomAccess()">REFRESH INVENTORY</button></div>
<div class="notice">Agentless access is conditional. An open port indicates a possible service, not successful authentication. WinRM/WMI/RDP must already be enabled and permitted by Windows Firewall and the remote account. NetworkRadar does not enable remote access or store Windows passwords.</div>
<div class="grid phantom-metrics"><div class="card"><div class="label">Known devices</div><div class="value" id="paKnown">0</div></div><div class="card"><div class="label">Native management candidates</div><div class="value" id="paCandidates">0</div></div><div class="card"><div class="label">SSH reachable</div><div class="value" id="paSshReachable">0</div></div><div class="card"><div class="label">RDP reachable</div><div class="value" id="paRdp">0</div></div><div class="card"><div class="label">Agent-managed</div><div class="value" id="paAgents">0</div></div></div>
<div class="sectionhead" style="margin:12px 0"><div><strong>QUICK CONTROL · ALL SELECTED ONLINE DEVICES</strong><div class="hint">Select any number of online endpoints. Read-only jobs are automatically split into batches of 12 with per-device results.</div><span id="paSelectionCount">0 selected · 0 online</span></div><div class="actions"><button class="secondary" onclick="phantomBulk('probe')">PROBE SELECTED</button><button class="secondary" onclick="phantomBulk('remote_inventory')">REFRESH SYSTEM INFO</button><button class="secondary" onclick="phantomBulk('remote_network')">NETWORK SNAPSHOT</button><button class="secondary" onclick="phantomBulk('remote_storage')">STORAGE SNAPSHOT</button><button class="secondary" onclick="phantomBulk('remote_security')">SECURITY SNAPSHOT</button></div></div>
<div class="scroll"><table><thead><tr><th><input type="checkbox" id="paSelectAll" onchange="toggleAllPhantom(this.checked)" aria-label="Select all visible endpoints"></th><th>DEVICE</th><th>IDENTITY</th><th>IP</th><th>WINRM</th><th>WMI/RPC</th><th>SMB</th><th>RDP</th><th>SSH</th><th>READINESS</th><th>ACTIONS</th></tr></thead><tbody id="phantomAccessRows"><tr><td colspan="11">Loading known devices…</td></tr></tbody></table></div>
<div class="profilegrid" style="margin-top:14px"><div class="profileitem"><div class="label">Selected target</div><div class="value mono" id="paTarget">None selected</div></div><div class="profileitem"><div class="label">Native access method</div><div class="value" id="paMethod">Not tested</div></div><div class="profileitem"><div class="label">Authentication</div><div class="value">Current Windows account</div></div><div class="profileitem"><div class="label">Last operation</div><div class="value" id="paLastAction">None</div></div></div>
<div class="hint" id="paStatus" style="margin-top:12px">Select a known endpoint, probe its services, then choose an access method supported by that device.</div>
<div class="terminal-shell card" id="phantomTerminal">
 <div class="terminal-topbar"><div><span class="terminal-led"></span><strong>PHANTOM TERMINAL</strong><span class="terminal-subtitle">AUTHENTICATED SSH · INTERACTIVE SESSION</span></div><span id="paSshState" class="pill warn">DISCONNECTED</span></div>
 <div class="terminal-grid">
  <div class="terminal-connect">
   <label>Target IP<input id="paSshIp" type="text" inputmode="decimal" placeholder="Select an endpoint" readonly></label>
   <label>SSH port<input id="paSshPort" type="number" min="1" max="65535" value="22"></label>
   <label>Username<input id="paSshUser" type="text" maxlength="128" autocomplete="username" placeholder="SSH account"></label>
   <label>Authentication<select id="paSshAuth"><option value="agent">SSH agent / default keys</option><option value="key">Private-key file</option><option value="password">Password (memory only)</option></select></label>
   <label id="paSshKeyWrap" class="ssh-auth-field">Private-key path<input id="paSshKey" type="text" placeholder="C:\Users\you\.ssh\id_ed25519"></label>
   <label id="paSshPassphraseWrap" class="ssh-auth-field">Key passphrase<input id="paSshPassphrase" type="password" autocomplete="off"></label>
   <label id="paSshPasswordWrap" class="ssh-auth-field" hidden>Password<input id="paSshPassword" type="password" autocomplete="new-password"></label>
   <button class="secondary" id="paSshFingerprintBtn" type="button">1 · REVIEW HOST KEY</button>
   <div id="paSshFingerprint" class="fingerprint-box">Host key not reviewed.</div>
   <button class="secondary" id="paSshTrustBtn" type="button" disabled>2 · TRUST FINGERPRINT</button>
   <button id="paSshConnectBtn" type="button" disabled>3 · CONNECT TERMINAL</button>
   <button class="secondary" id="paSshDisconnectBtn" type="button" disabled>DISCONNECT</button>
   <div class="hint">SSH credentials are used only to establish this session. Passwords and private-key contents are not stored or written to the audit log. Verify the fingerprint using a trusted source on the target before accepting it. Unknown or changed keys are rejected.</div>
  </div>
  <div class="terminal-workspace">
   <div class="terminal-toolbar"><span id="paSshSessionLabel">No active session</span><button class="secondary" id="paTerminalClear" type="button">CLEAR OUTPUT</button></div>
   <pre id="paTerminalOutput" class="terminal-output" aria-live="polite">PHANTOM TERMINAL READY

Select an online device with SSH available. Review its host-key fingerprint before trusting it.

This terminal runs with the permissions of the SSH account you authenticate as.</pre>
   <textarea id="paTerminalInput" class="terminal-input" rows="2" spellcheck="false" autocomplete="off" autocapitalize="off" placeholder="Connect first, then type commands here…" disabled aria-label="SSH terminal keyboard input"></textarea>
   <div class="terminal-footer"><span>ENTER sends · CTRL+C interrupts · CTRL+D closes input</span><span id="paTerminalLatency">LOCAL SESSION</span></div>
   <div class="terminal-renderer-note">Interactive PTY shell · basic text renderer · full-screen terminal applications may not display correctly.</div>
  </div>
 </div>
</div>
<div class="scroll" style="margin-top:12px"><table><thead><tr><th>AVAILABLE READ-ONLY OPERATIONS</th><th>DESCRIPTION</th><th>ACTION</th></tr></thead><tbody>
<tr><td>Remote system inventory</td><td>Windows edition, model, manufacturer, CPU, memory and boot time.</td><td><button class="secondary" onclick="phantomAction('remote_inventory')">RUN</button></td></tr>
<tr><td>Network configuration</td><td>Adapters, MAC addresses, IP/subnet, gateway, DNS and DHCP state. No packet contents.</td><td><button class="secondary" onclick="phantomAction('remote_network')">RUN</button></td></tr>
<tr><td>Storage inventory</td><td>Fixed volumes, filesystem, total capacity and free space. No file listing or file contents.</td><td><button class="secondary" onclick="phantomAction('remote_storage')">RUN</button></td></tr>
<tr><td>BIOS / motherboard</td><td>BIOS vendor/version and motherboard manufacturer/product identifiers.</td><td><button class="secondary" onclick="phantomAction('remote_bios')">RUN</button></td></tr>
<tr><td>Security posture snapshot</td><td>Firewall profile state and Microsoft Defender protection status where supported. Not a compliance certification.</td><td><button class="secondary" onclick="phantomAction('remote_security')">RUN</button></td></tr>
<tr><td>Running processes</td><td>Read-only process names, IDs and memory use.</td><td><button class="secondary" onclick="phantomAction('remote_processes')">RUN</button></td></tr>
<tr><td>Windows services</td><td>Read-only service names, display names and states.</td><td><button class="secondary" onclick="phantomAction('remote_services')">RUN</button></td></tr>
<tr><td>Test WinRM</td><td>Verifies an authenticated PowerShell Remoting command can execute.</td><td><button class="secondary" onclick="phantomAction('test_winrm')">TEST WINRM</button></td></tr>
<tr><td>Test WMI/DCOM</td><td>Separately verifies authenticated CIM access over DCOM. WinRM may be unavailable while WMI works.</td><td><button class="secondary" onclick="phantomAction('test_wmi')">TEST WMI/DCOM</button></td></tr>
<tr><td>Open Remote Desktop</td><td>Launches the local Windows RDP client if port 3389 is reachable.</td><td><button class="secondary" onclick="phantomAction('open_rdp')">OPEN RDP</button></td></tr>
<tr><td>Restart Windows service</td><td>Requires exact service name, sufficient privileges and confirmation. Core services are blocked.</td><td><button class="secondary" onclick="phantomAction('restart_service')">RESTART SERVICE</button></td></tr>
<tr><td>Restart / shut down PC</td><td>Disruptive actions require explicit confirmation and working remote permissions.</td><td><button class="secondary" onclick="phantomAction('restart_computer')">RESTART</button> <button class="secondary" onclick="phantomAction('shutdown_computer')">SHUT DOWN</button></td></tr>
</tbody></table></div>
<pre id="paOutput" class="profileitem" style="white-space:pre-wrap;overflow:auto;max-height:340px;margin-top:12px">Results from agentless operations will appear here.</pre>
</section>
<section class="section card" id="commandCenter"><div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap"><div><h2>NETWORKRADAR COMMAND · MANAGED ENDPOINTS</h2><div class="hint">Explicitly enrolled devices only. No silent access, arbitrary shell or hidden remote control.</div></div><button onclick="createAgentToken()">GENERATE ENROLMENT TOKEN</button></div>
<div class="notice">Remote agent communications require TLS with certificate pinning. The agent hub is disabled by default. Configure its TLS certificate and explicitly enable it before enrolling another computer. Restart, shutdown, workstation lock and service restart require separate confirmation.</div>
<div class="grid" style="margin-top:12px"><div class="card"><div class="label">Managed endpoints</div><div class="value" id="agentManaged">0</div></div><div class="card"><div class="label">Recently online</div><div class="value" id="agentOnline">0</div></div><div class="card"><div class="label">Queued actions</div><div class="value" id="agentQueued">0</div></div><div class="card"><div class="label">Agent hub</div><div class="value" style="font-size:18px" id="agentHubState">DISABLED</div></div></div>
<div id="agentTokenBox" class="profileitem" style="display:none;margin:12px 0"><div class="label">Single-use enrolment token · expires in 15 minutes</div><div class="mono" id="agentToken" style="font-size:18px;overflow-wrap:anywhere"></div><div class="hint">Copy this token to the target computer. It can enrol one agent once.</div></div>
<div class="scroll"><table><thead><tr><th>DEVICE</th><th>PLATFORM</th><th>STATUS</th><th>LAST SEEN</th><th>CPU</th><th>RAM</th><th>IP</th><th>CONTROLS</th></tr></thead><tbody id="agentRows"><tr><td colspan="8">No endpoints enrolled.</td></tr></tbody></table></div>
<h2 style="margin-top:20px">COMMAND AUDIT</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE ID</th><th>ACTOR</th><th>ACTION</th><th>OUTCOME</th><th>DETAILS</th></tr></thead><tbody id="agentAuditRows"><tr><td colspan="6">No remote-management actions.</td></tr></tbody></table></div>
<h2 style="margin-top:20px">LATEST COMMAND OUTPUT</h2><div class="hint">Process/service listings and action results returned by enrolled agents appear here.</div><div class="scroll"><table><thead><tr><th>COMMAND</th><th>DEVICE</th><th>ACTION</th><th>STATUS</th><th>COMPLETED</th></tr></thead><tbody id="agentResultRows"><tr><td colspan="5">No command results.</td></tr></tbody></table></div><pre id="agentCommandOutput" class="profileitem" style="white-space:pre-wrap;overflow:auto;max-height:320px">Select a completed command to inspect its result.</pre></section>
</main>
<div id="toast" style="display:none;position:fixed;right:20px;bottom:20px;z-index:100;background:#153d35;color:#d8fff0;border:1px solid #35d39a;padding:12px 18px;border-radius:10px"></div>
<div id="deviceModal" class="modal" onclick="if(event.target===this)closeDevice()"><div class="modalbox"><div class="modalhead"><div><div class="sub">DEVICE</div><h2 id="modalTitle">Device</h2></div><button class="secondary" onclick="closeDevice()">CLOSE</button></div><div id="modalContent" class="modalcontent">Loading...</div></div></div>
<script src="/assets/dashboard.js?v={APP_VERSION}" defer></script>
</body></html>"""

# Self-contained dashboard bundle: the HTML no longer depends on a separate
# dashboard.js file being copied beside networkradar.py.
DASHBOARD_JS_BUNDLED = 'const $=id=>document.getElementById(id);\n// Startup diagnostics: make a failed dashboard script/API visible instead of leaving skeletons.\ntry{const c=$("connection");if(c){c.textContent="SCRIPT ACTIVE";c.className="pill warn";}}catch(_e){}\nwindow.addEventListener("error",e=>{try{const c=$("connection");if(c){c.textContent="SCRIPT ERROR";c.className="pill bad";}const u=$("updated");if(u)u.textContent="Dashboard error: "+(e.message||"unknown script error");}catch(_x){}});\nwindow.addEventListener("unhandledrejection",e=>{try{const u=$("updated");if(u)u.textContent="Dashboard request error: "+String(e.reason?.message||e.reason||"unknown");}catch(_x){}});\nfunction esc(v){return String(v??"").replace(/[&<>"\']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#39;"}[c]));}\nasync function getJSON(p){const ctl=new AbortController();const timer=setTimeout(()=>ctl.abort(),10000);try{const r=await fetch(p,{cache:"no-store",signal:ctl.signal});if(!r.ok)throw new Error("HTTP "+r.status);return await r.json();}finally{clearTimeout(timer);}}\nfunction pill(el,text,state){el.textContent=text;el.className="pill"+(state==="bad"?" bad":state==="warn"?" warn":"");}\nfunction toast(m){const t=$("toast");t.textContent=m;t.style.display="block";setTimeout(()=>t.style.display="none",3500);}\nlet deviceCache=[];\nfunction filterDevices(){\n const q=($("deviceSearch")?.value||"").toLowerCase().trim();\n const st=$("deviceFilter")?.value||"ALL";\n const rows=deviceCache.filter(x=>{\n  const b=[x.ip,x.device_name,x.manual_name,x.device_type,x.manufacturer,x.mac,x.hostname,x.model].join(" ").toLowerCase();\n  const ok=st==="ALL"||(st==="ONLINE"&&x.status==="ONLINE")||(st==="OFFLINE"&&x.status==="OFFLINE")||(st==="TRUSTED"&&x.trust_state==="TRUSTED");\n  return ok&&(!q||b.includes(q));\n });\n $("deviceRows").innerHTML=rows.map(x=>`<tr class="clickrow" data-open-device="${esc(x.ip)}" tabindex="0" role="button"><td class="mono">${esc(x.ip)}</td><td>${esc(x.manual_name||x.device_name)}</td><td>${esc(x.device_type)}</td><td>${esc(x.manufacturer)}</td><td>${esc(x.identification_confidence)}%</td><td class="risk-${esc(x.risk_band||"UNKNOWN")}">${esc(x.risk_band||"UNKNOWN")}</td><td class="${x.status==="ONLINE"?"green":"muted"}">${esc(x.status)}</td></tr>`).join("")||\'<tr><td colspan="7">No matches.</td></tr>\';\n $("deviceRows").querySelectorAll("[data-open-device]").forEach(row=>{\n  row.addEventListener("click",()=>openDevice(row.dataset.openDevice));\n  row.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();openDevice(row.dataset.openDevice);}});\n });\n}\nfunction closeDevice(){$("deviceModal").classList.remove("open");}\nfunction deviceRows(rows, cols, empty="No records available."){\n if(!rows||!rows.length)return `<div class="device-empty">${esc(empty)}</div>`;\n return `<div class="scroll"><table class="device-table"><thead><tr>${cols.map(c=>`<th>${esc(c[0])}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr>${cols.map(c=>`<td>${esc((r[c[1]]??"—")=== "" ? "—" : (r[c[1]]??"—"))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;\n}\nfunction deviceProfileCards(items){return \'<div class="profilegrid">\'+items.map(([k,v])=>`<div class="profileitem"><div class="label">${esc(k)}</div><div class="value">${esc(v===0?"0":(v||"Unknown"))}</div></div>`).join("")+\'</div>\';}\nfunction setDeviceTab(name){\n document.querySelectorAll("[data-device-tab]").forEach(b=>b.setAttribute("aria-selected",b.dataset.deviceTab===name?"true":"false"));\n document.querySelectorAll("[data-device-pane]").forEach(p=>p.classList.toggle("active",p.dataset.devicePane===name));\n}\nasync function openDevice(ip){\n $("deviceModal").classList.add("open");$("modalTitle").textContent="Device Intelligence · "+ip;$("modalContent").textContent="Loading device intelligence...";\n try{\n  const p=await getJSON("/api/device?ip="+encodeURIComponent(ip));const d=p.device;\n  if(!d){$("modalContent").textContent="Device not found.";return;}\n  const rec=d.recognition||{}, ev=p.identity_evidence||[], ass=p.identity_assessments||[];\n  const tabs=["Overview","Identity","Hardware","Operating System","Network","Services","Behaviour","Relationships","Security","History","Investigations"];\n  let html=\'<div class="device-tabs" role="tablist" aria-label="Device intelligence sections">\'+tabs.map((t,i)=>`<button class="device-tab" role="tab" id="devtab-${i}" aria-controls="devpane-${i}" aria-selected="${i===0?"true":"false"}" data-device-tab="${esc(t)}">${esc(t)}</button>`).join("")+\'</div>\';\n  const pane=(name,body,i)=>`<section class="device-pane ${i===0?"active":""}" role="tabpanel" id="devpane-${i}" aria-labelledby="devtab-${i}" data-device-pane="${esc(name)}">${body}</section>`;\n  const overview=deviceProfileCards([["IP ADDRESS",d.ip],["DEVICE NAME",d.manual_name||d.device_name||d.hostname],["CATEGORY",d.device_type],["MANUFACTURER",d.reported_manufacturer||d.manufacturer||d.oui_manufacturer],["MODEL",d.model],["OPERATING SYSTEM",d.os_guess],["MAC ADDRESS",d.mac],["IDENTITY CONFIDENCE",(d.identification_confidence||0)+"%"],["STATUS",d.status],["RISK",(d.risk_band||"UNKNOWN")+" · "+(d.risk_score||0)],["TRUST",d.trust_state],["FIRST SEEN",d.first_seen],["LAST SEEN",d.last_seen],["IDENTITY BASIS",d.identity_basis],["LAST ASSESSED",d.identity_last_assessed]]);\n  let identity=\'<div class="device-kpis"><div class="device-kpi"><span class="label">Evidence records</span><strong>\'+ev.length+\'</strong></div><div class="device-kpi"><span class="label">Independent assessments</span><strong>\'+ass.length+\'</strong></div><div class="device-kpi"><span class="label">Category confidence</span><strong>\'+(d.identity_category_confidence||0)+\'%</strong></div></div>\';\n  identity+=\'<h3>WHY NETWORKRADAR THINKS THIS IS THIS DEVICE</h3>\';\n  identity+=deviceRows(ass,[[\'ATTRIBUTE\',\'attribute\'],[\'ASSESSED VALUE\',\'value\'],[\'CONFIDENCE\',\'confidence\'],[\'STATUS\',\'status\'],[\'EVIDENCE COUNT\',\'evidence_count\'],[\'INDEPENDENT SOURCES\',\'independent_sources\'],[\'RATIONALE\',\'rationale\']],\'No persisted attribute assessments yet.\');\n  identity+=\'<h3>RAW IDENTITY EVIDENCE</h3>\'+deviceRows(ev,[[\'TIME\',\'timestamp\'],[\'SOURCE\',\'source\'],[\'ATTRIBUTE\',\'attribute\'],[\'OBSERVED VALUE\',\'value\'],[\'CONFIDENCE\',\'confidence\'],[\'CLASS\',\'class\']]);\n  if(rec.category){identity+=`<div class="notice"><b>${esc(rec.category)}</b> · ${esc(rec.confidence||0)}% · ${esc(rec.status||\'UNKNOWN\')}</div>`;identity+=deviceRows(rec.matches||[],[[\'MATCH\',\'matched\'],[\'CLASSIFICATION\',\'category\'],[\'SOURCE FAMILY\',\'source_family\'],[\'WEIGHT\',\'weight\']],\'No signature matches.\');}\n  const hardware=deviceProfileCards([["DEVICE-REPORTED MANUFACTURER",d.reported_manufacturer],["NIC OUI MANUFACTURER",d.oui_manufacturer],["NMAP VENDOR",d.manufacturer],["REPORTED MODEL",d.model],["HOSTNAME",d.hostname],["DEVICE CATEGORY",d.device_type],["MAC ADDRESS",d.mac],["MAC IDENTITY BASIS",d.identity_basis]]);\n  const os=deviceProfileCards([["OS GUESS",d.os_guess],["OS FINGERPRINT CONFIDENCE",d.identification_confidence+"%"],["PASSIVE TCP HINT",rec.passive_tcp_os_hint],["RECOGNITION STATUS",rec.status],["ALTERNATIVE CLASSIFICATIONS",(rec.alternatives||[]).map(x=>x.category+" ("+x.confidence+"%)").join(" · ")],["LIMITATIONS",(rec.limitations||[]).join(" ")]]);\n  const network=deviceProfileCards([["CURRENT IP",d.ip],["CURRENT MAC",d.mac],["IDENTITY KEY",d.device_id],["IDENTITY BASIS",d.identity_basis],["DHCP OBSERVATIONS",(p.dhcp_history||[]).length],["DNS OBSERVATIONS",(p.dns_activity||[]).length]]);\n  let networkHtml=network+\'<h3>DHCP HISTORY</h3>\'+deviceRows(p.dhcp_history,[[\'TIME\',\'timestamp\'],[\'MESSAGE\',\'message\'],[\'HOSTNAME\',\'hostname\'],[\'VENDOR CLASS\',\'vendor_class\'],[\'CLIENT MAC\',\'mac\'],[\'SERVER\',\'server_ip\']]);\n  networkHtml+=\'<h3>IP / MAC HISTORY</h3>\'+deviceRows(p.ip_history,[[\'IP\',\'ip\'],[\'MAC\',\'mac\'],[\'FIRST SEEN\',\'first_seen\'],[\'LAST SEEN\',\'last_seen\']]);\n  const services=deviceProfileCards([["OPEN PORTS",d.open_ports],["SERVICE SUMMARY",d.service_summary],["SERVICE SIGNATURES",(rec.matches||[]).filter(x=>String(x.source_family||"").toLowerCase().includes("service")).length],["TLS CERTIFICATES",(rec.evidence||[]).filter(x=>String(x.source||"").toLowerCase().includes("tls")).length],["SNMP DATA",Object.keys(d.snmp_intel||{}).length?"Available":"Not observed"]]);\n  let serviceHtml=services+\'<h3>IDENTIFIED SERVICE EVIDENCE</h3>\'+deviceRows((rec.evidence||[]).filter(x=>/service|tls|snmp|http|ssh|smb/i.test((x.source||"")+" "+(x.family||""))),[[\'SOURCE\',\'source\'],[\'FAMILY\',\'family\'],[\'OBSERVATION\',\'value\']]);\n  serviceHtml+=\'<h3>PORT SCAN HISTORY</h3>\'+deviceRows(p.port_scan_history,[[\'TIME\',\'timestamp\'],[\'COMPLETED\',\'completed\'],[\'PORTS\',\'ports\'],[\'METHOD\',\'method\'],[\'DETAIL\',\'detail\']]);\n  const behaviour=\'<h3>DNS ACTIVITY (LATEST OBSERVATIONS)</h3>\'+deviceRows(p.dns_activity,[[\'TIME\',\'timestamp\'],[\'DOMAIN\',\'domain\'],[\'TYPE\',\'type\'],[\'RESPONSE\',\'rcode\'],[\'ANSWERS\',\'answers\']]);\n  const behaviour2=\'<h3>BEHAVIOUR ALERTS</h3>\'+deviceRows(p.behaviour_alerts,[[\'TIME\',\'timestamp\'],[\'METRIC\',\'metric\'],[\'OBSERVED\',\'observed\'],[\'BASELINE\',\'baseline\'],[\'SEVERITY\',\'severity\'],[\'STATUS\',\'status\'],[\'DETAILS\',\'details\']]);\n  const relations=\'<h3>DEVICE RELATIONSHIPS</h3>\'+deviceRows(p.relationships,[[\'SOURCE IP\',\'source_ip\'],[\'TARGET IP\',\'target_ip\'],[\'TYPE\',\'type\'],[\'CONFIDENCE\',\'confidence\'],[\'EVIDENCE\',\'evidence\'],[\'LAST SEEN\',\'last_seen\']]);\n  const relations2=\'<h3>TOPOLOGY LINKS</h3>\'+deviceRows(p.topology,[[\'SOURCE\',\'source\'],[\'TARGET\',\'target\'],[\'KIND\',\'kind\'],[\'CONFIDENCE\',\'confidence\'],[\'EVIDENCE\',\'evidence\'],[\'LAST SEEN\',\'last_seen\']]);\n  let security=deviceProfileCards([["RISK SCORE",d.risk_score||0],["RISK BAND",d.risk_band||"UNKNOWN"],["THREAT RISK",d.threat_risk||0],["IDENTITY UNCERTAINTY",d.identification_uncertainty||0],["OPERATIONAL HEALTH",d.operational_health||0],["TRUST STATE",d.trust_state]]);\n  security+=\'<h3>EXPOSURE FINDINGS</h3>\'+deviceRows(p.exposure_findings,[[\'TITLE\',\'title\'],[\'SEVERITY\',\'severity\'],[\'CONFIDENCE\',\'confidence\'],[\'PORTS\',\'ports\'],[\'STATUS\',\'status\'],[\'RECOMMENDATION\',\'recommendation\']]);\n  security+=\'<h3>SECURITY ALERTS</h3>\'+deviceRows(p.alerts,[[\'TIME\',\'timestamp\'],[\'SOURCE\',\'source\'],[\'RULE\',\'rule\'],[\'SEVERITY\',\'severity\'],[\'TITLE\',\'title\'],[\'STATUS\',\'status\']]);\n  if(d.risk_explanation)security+=\'<div class="notice">\'+esc(d.risk_explanation)+\'</div>\';\n  const history=\'<h3>IDENTITY CHANGES</h3>\'+deviceRows(p.identity_history,[[\'TIME\',\'timestamp\'],[\'ATTRIBUTE\',\'attribute\'],[\'OLD VALUE\',\'old\'],[\'NEW VALUE\',\'new\'],[\'REASON\',\'reason\']]);\n  const history2=\'<h3>DISCOVERY OBSERVATIONS</h3>\'+deviceRows(p.observations,[[\'TIME\',\'timestamp\'],[\'METHOD\',\'method\'],[\'OBSERVATION\',\'observation\'],[\'CONFIDENCE\',\'confidence\']]);\n  const investigations=deviceRows(p.investigations,[[\'ID\',\'id\'],[\'CREATED\',\'timestamp\'],[\'TITLE\',\'title\'],[\'SEVERITY\',\'severity\'],[\'CONFIDENCE\',\'confidence\'],[\'STATUS\',\'status\'],[\'DESCRIPTION\',\'description\'],[\'CLOSURE\',\'closure_reason\']]);\n  html+=pane("Overview",overview,0)+pane("Identity",identity,1)+pane("Hardware",hardware,2)+pane("Operating System",os,3)+pane("Network",networkHtml,4)+pane("Services",serviceHtml,5)+pane("Behaviour",behaviour+behaviour2,6)+pane("Relationships",relations+relations2,7)+pane("Security",security,8)+pane("History",history+history2,9)+pane("Investigations",investigations,10);\n  $("modalContent").innerHTML=html;\n  $("modalContent").querySelectorAll("[data-device-tab]").forEach(b=>b.addEventListener("click",()=>setDeviceTab(b.dataset.deviceTab)));\n }catch(err){$("modalContent").textContent="Error loading device intelligence: "+err.message;}\n}\nasync function runContinuity(){\n const b=$("continuityRun");b.disabled=true;b.textContent="ANALYSING...";\n try{\n  const r=await fetch("/api/identity/continuity/run",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});\n  const p=await r.json();if(!r.ok)throw new Error(p.error||"Analysis failed");\n  toast(`PHANTOM TRACK: ${p.result.observed} observations · ${p.result.stable_anchors} stable anchors · ${p.result.randomised} randomised · ${p.result.candidate_groups} review groups.`);\n  await loadContinuity();await loadCandidates();\n }catch(e){toast("Continuity: "+e.message);}finally{b.disabled=false;b.textContent="RUN CONTINUITY ANALYSIS";}\n}\nasync function updateOUI(){\n if(!confirm("Download and cache the official IEEE MAC address registries? Requires internet."))return;\n try{\n  const r=await fetch("/api/intelligence/update-oui",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});\n  const p=await r.json();if(!r.ok)throw new Error((p.errors||[]).join("; ")||p.error||"Update failed");\n  toast(`IEEE registry: ${p.updated} prefixes.`);await loadIdentityIntel();\n }catch(e){toast("OUI update: "+e.message);}\n}\nasync function authorizeCurrentNetwork(){\n if(!confirm("Only authorise if you own this network."))return;\n try{\n  const r=await fetch("/api/network/authorize",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true})});\n  const j=await r.json();if(!r.ok)throw new Error(j.error||"Failed");\n  toast(j.message);await refreshAll();\n }catch(e){toast(e.message);}\n}\nasync function scanNow(){\n const b=$("scanButton");b.disabled=true;b.textContent="QUEUED...";\n try{await fetch("/api/scan",{method:"POST"});$("updated").textContent="Queued...";}\n catch(e){$("updated").textContent=e.message;}\n finally{setTimeout(()=>{b.disabled=false;b.textContent="SCAN NOW";},2500);}\n}\nasync function loadCandidates(){\n try{\n  const c=await getJSON("/api/identity/candidates?status=PENDING");\n  $("candidateRows").innerHTML=c.map(x=>`<tr><td>${x.id}</td><td class="mono">${esc(x.device_a)}</td><td class="mono">${esc(x.device_b)}</td><td>${esc(x.outcome)}</td><td>${(x.score*100).toFixed(1)}%</td><td>${esc(x.status)}</td><td><button class="secondary" style="padding:3px 8px;font-size:10px" onclick="reviewCandidate(${x.id},\'ACCEPT\')">ACCEPT</button> <button class="secondary" style="padding:3px 8px;font-size:10px" onclick="reviewCandidate(${x.id},\'REJECT\')">REJECT</button></td></tr>`).join("")||\'<tr><td colspan="7">No pending candidates.</td></tr>\';\n }catch(e){$("candidateRows").innerHTML=\'<tr><td colspan="7">Error: \'+esc(e.message)+\'</td></tr>\';}\n}\nasync function reviewCandidate(id,action){\n try{\n  const r=await fetch("/api/identity/candidates/review",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,action,reviewer:"local-user"})});\n  const p=await r.json();if(!r.ok)throw new Error(p.error||"Failed");\n  toast("Candidate #"+id+" "+action.toLowerCase()+"d.");await loadCandidates();\n }catch(e){toast(e.message);}\n}\nasync function loadContinuity(){\n try{\n  const [s,d]=await Promise.all([getJSON(\'/api/identity/continuity/summary\'),getJSON(\'/api/identity/continuity/devices\')]);\n  $(\'ctTracked\').textContent=s.tracked||0;$(\'ctStable\').textContent=s.stable_anchors||0;$(\'ctRandom\').textContent=s.randomised_observations||0;$(\'ctEvents\').textContent=s.events||0;\n  $(\'continuityRows\').innerHTML=d.map(x=>`<tr><td class="mono">${esc(x.id)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.anchor_type)}</td><td>${esc(x.hostname||\'—\')}</td><td>${esc(x.vendor_class||\'—\')}</td><td>${esc(x.confidence)}%</td><td>${esc(x.observations)}</td><td>${esc(x.last_seen)}</td></tr>`).join(\'\')||\'<tr><td colspan="8">No identity observations yet.</td></tr>\';\n }catch(e){$(\'continuityRows\').innerHTML=\'<tr><td colspan="8">Continuity service unavailable: \'+esc(e.message)+\'</td></tr>\';}\n}\nasync function loadIdentityIntel(){\n try{\n  const [s,u]=await Promise.all([getJSON("/api/identity/summary"),getJSON("/api/identity/unknown")]);\n  $("idDevices").textContent=s.devices_with_evidence||0;$("idEvidence").textContent=s.evidence_records||0;$("ouiEntries").textContent=s.oui_entries||0;$("idLastRun").textContent=s.last_run?s.last_run.timestamp:"Not run";\n }catch(e){$("idLastRun").textContent="Unavailable";}\n}\nasync function loadProfiles(){\n try{\n  const p=await getJSON("/api/profiles");\n  $("profileRows").innerHTML=p.map(x=>`<tr style="${x.is_current?\'background:#173653\':\'\'}"><td class="mono">${esc(x.network)}${x.is_current?\' <span class="pill">CUR</span>\':\'\'}</td><td class="mono">${esc(x.fingerprint)}</td><td class="mono">${esc(x.gateway)}</td><td>${x.approved?\'<span class="green">YES</span>\':\'<span class="amber">NO</span>\'}</td><td>${esc(x.confidence)}%</td><td>${esc(x.last_seen)}</td></tr>`).join("")||\'<tr><td colspan="6">None.</td></tr>\';\n }catch(e){}\n}\nasync function loadChanges(){\n try{const c=await getJSON("/api/changes");$("changeRows").innerHTML=c.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.change_type)}</td><td>${esc(x.category)}</td><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.details)}</td></tr>`).join("")||\'<tr><td colspan="6">None.</td></tr>\';}catch(e){}\n}\nasync function loadConfig(){\n try{const c=await getJSON("/api/config_findings");$("configRows").innerHTML=c.map(x=>`<tr><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td>${esc(x.title)}<div class="muted">${esc(x.description)}</div></td><td style="font-size:11px">${esc(x.evidence)}</td><td style="font-size:11px">${esc(x.recommendation)}</td><td>${esc(x.status)}</td></tr>`).join("")||\'<tr><td colspan="5">No findings.</td></tr>\';}catch(e){}\n}\nasync function loadAlertStream(){\n try{const a=await getJSON("/api/alerts_stream");$("alertStreamRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.source)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":x.severity==="MEDIUM"?"amber":"muted"}">${esc(x.severity)}</td><td>${esc(x.title)}</td><td>${esc(x.occurrence_count||1)}</td><td>${x.investigation_id?\'#\'+x.investigation_id:\'—\'}</td></tr>`).join("")||\'<tr><td colspan="7">None.</td></tr>\';}catch(e){}\n}\nasync function loadHuntTemplates(){\n try{const t=await getJSON("/api/hunt/templates");$("huntTemplate").innerHTML=\'<option value="">Select...</option>\'+t.map(x=>`<option value="${esc(x.key)}">${esc(x.title)}</option>`).join("");}catch(e){}\n}\nasync function runHunt(){\n const tpl=$("huntTemplate").value;if(!tpl){toast("Select template.");return;}\n $("huntResult").textContent="Running...";\n try{const r=await getJSON("/api/hunt/run?template="+encodeURIComponent(tpl));\n  if(r.error){$("huntResult").textContent="Error: "+r.error;return;}\n  $("huntResult").textContent=`${r.title} — ${r.count} results`;\n  $("huntHead").innerHTML=\'<tr>\'+r.columns.map(c=>`<th>${esc(c)}</th>`).join("")+\'</tr>\';\n  $("huntRows").innerHTML=r.results.map(row=>\'<tr>\'+r.columns.map(c=>`<td class="mono">${esc(row[c]??"")}</td>`).join("")+\'</tr>\').join("")||\'<tr><td colspan="\'+r.columns.length+\'">No results.</td></tr>\';\n }catch(e){$("huntResult").textContent="Error: "+e.message;}\n}\nasync function downloadReport(){\n const t=$("reportType").value;const f=$("reportFormat").value;\n window.location.href=`/api/report?type=${encodeURIComponent(t)}&format=${encodeURIComponent(f)}`;\n}\nlet refreshInFlight=false;\nasync function refreshAll(){\n if(refreshInFlight)return;refreshInFlight=true;\n const specs=[\n  ["status","/api/status"],["devices","/api/devices"],["domains","/api/domains"],\n  ["alerts","/api/alerts"],["events","/api/events"],["dns","/api/dns"],\n  ["progress","/api/progress"],["investigations","/api/investigations"],\n  ["network","/api/network"],["diagnostics","/api/diagnostics"],\n  ["engine","/api/engine_diagnostics"]\n ];\n try{\n  const settled=await Promise.allSettled(specs.map(([,path])=>getJSON(path)));\n  const data={},failed=[];\n  settled.forEach((r,i)=>{const name=specs[i][0];if(r.status==="fulfilled")data[name]=r.value;else{data[name]=null;failed.push(name+": "+String(r.reason?.message||r.reason||"request failed"));}});\n  const s=data.status||{},d=Array.isArray(data.devices)?data.devices:[],domains=Array.isArray(data.domains)?data.domains:[],a=Array.isArray(data.alerts)?data.alerts:[],e=Array.isArray(data.events)?data.events:[],inv=Array.isArray(data.investigations)?data.investigations:[],n=data.network||{},diag=data.diagnostics||{},eng=data.engine||{},j=data.progress||{};\n  const statusOK=!!data.status;\n  pill($("connection"),!statusOK?"API DEGRADED":(failed.length?"CONNECTED · PARTIAL":"CONNECTED"),!statusOK?"bad":(failed.length?"warn":"ok"));\n  if(!statusOK){$("updated").textContent="Status API unavailable. "+failed.join(" | ");}\n  else{$("updated").textContent="Updated "+(s.timestamp||new Date().toLocaleTimeString())+(failed.length?" · "+failed.length+" API request(s) failed: "+failed.map(x=>x.split(":")[0]).join(", "):"");}\n  $("network").textContent=s.network||n.network||"—";$("activeSubnet").textContent=n.network||s.network||"—";\n  $("defaultGateway").textContent=n.gateway||"—";$("fingerprint").textContent=n.fingerprint||"—";$("fpConf").textContent=(n.confidence||0)+"%";\n  $("networkWarning").textContent=n.warning||(n.authorized?"Authorised.":"Passive only.");$("authorizeNetwork").style.display=n.authorized?"none":"inline-block";$("netAuthz").textContent=n.auth_decision||"—";\n  $("jobPhase").textContent=j.phase||"—";$("jobMessage").textContent=j.message||"Waiting for engine status.";$("jobPercent").textContent=(j.percent??0)+"%";$("jobBar").style.width=(j.percent??0)+"%";\n  $("online").textContent=s.online??"—";$("historical").textContent=s.historical??"—";$("deviceHint").textContent=(s.offline??"—")+" offline";$("openInvestigations").textContent=s.open_investigations??inv.length;\n  const nr=$("networkRisk");nr.textContent=s.network_risk_band||"UNKNOWN";nr.className="value risk-"+(s.network_risk_band||"UNKNOWN");\n  pill($("dnsStatus"),s.dns_status||"UNKNOWN",s.dns_status==="ONLINE"?"ok":"warn");pill($("dhcpStatus"),s.dhcp_status||"UNKNOWN",s.dhcp_status==="ONLINE"?"ok":"warn");pill($("arpStatus"),s.arp_status||"UNKNOWN",s.arp_status==="ONLINE"?"ok":"warn");\n  const dhcp=eng.engines?.dhcp||{};$("dhcpClass").textContent=(dhcp.state||"UNKNOWN")+" — "+(dhcp.reason||"").slice(0,60);\n  $("dbQueue").textContent=(s.db_health?.queued??"—")+" queued, "+(s.db_health?.processed??"—")+" done";$("scanQuality").textContent=(diag.scan_quality?.score??"—")+"/100 · "+(diag.scan_quality?.band||"—");\n  if(data.devices){deviceCache=d;filterDevices();}else{$("deviceRows").innerHTML=\'<tr><td colspan="7">Device API unavailable. Check server log and /api/devices.</td></tr>\';}\n  $("domainRows").innerHTML=domains.map(x=>`<tr><td class="mono">${esc(x.domain)}</td><td>${x.query_count}</td><td>${esc(x.risk_level)}</td></tr>`).join("")||\'<tr><td colspan="3">—</td></tr>\';\n  $("alertRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.client_ip)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":"amber"}">${esc(x.severity)}</td></tr>`).join("")||\'<tr><td colspan="4">—</td></tr>\';\n  $("eventRows").innerHTML=e.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.category)}</td><td>${esc(x.event_type)}</td><td>${esc(x.details)}</td></tr>`).join("")||\'<tr><td colspan="5">—</td></tr>\';\n  $("behaviourStatus").textContent=diag.behaviour?.message||"Behaviour diagnostics unavailable.";\n  $("behaviourRows").innerHTML=((diag.behaviour?.baseline_devices||0)>0?\'<tr><td colspan="5">See device detail for samples.</td></tr>\':\'<tr><td colspan="5">Collecting baselines.</td></tr>\');\n  $("investigationRows").innerHTML=inv.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.title)}</td><td>${esc(x.severity)}</td><td>${esc(x.status)}</td><td>${esc(x.evidence_count)}</td></tr>`).join("")||\'<tr><td colspan="5">None.</td></tr>\';\n  loadProfiles();loadChanges();loadConfig();loadAlertStream();loadIdentityIntel();loadContinuity();loadCandidates();loadPhantomPanels();\n }catch(err){pill($("connection"),"DASHBOARD ERROR","bad");$("updated").textContent=err.message||String(err);}\n finally{refreshInFlight=false;}\n}\nloadHuntTemplates();refreshAll();setInterval(refreshAll,5000);\n// Searchable, collapsible navigation with deterministic desktop/mobile state.\nconst nrNavMedia = window.matchMedia(\'(max-width: 900px)\');\nfunction syncNavigationButton(){\n const b=document.getElementById(\'navToggle\');\n if(!b)return;\n const mobile=nrNavMedia.matches;\n const expanded=mobile?document.body.classList.contains(\'nav-open\'):!document.body.classList.contains(\'nav-collapsed\');\n b.setAttribute(\'aria-expanded\',expanded?\'true\':\'false\');\n b.setAttribute(\'aria-label\',mobile?(expanded?\'Close navigation\':\'Open navigation\'):(expanded?\'Collapse navigation\':\'Expand navigation\'));\n b.title=mobile?(expanded?\'Close navigation\':\'Open navigation\'):(expanded?\'Collapse navigation\':\'Expand navigation\');\n b.textContent=mobile?(expanded?\'✕\':\'☰\'):(expanded?\'☰\':\'»\');\n}\nfunction toggleNavigation(){\n if(nrNavMedia.matches){\n  document.body.classList.toggle(\'nav-open\');\n  if(document.body.classList.contains(\'nav-open\')){\n   const first=document.querySelector(\'#sideNavigation a:not([hidden])\');\n   if(first)window.setTimeout(()=>first.focus(),80);\n  }\n }else{\n  document.body.classList.remove(\'nav-open\');\n  document.body.classList.toggle(\'nav-collapsed\');\n  try{localStorage.setItem(\'nr-nav-collapsed\',document.body.classList.contains(\'nav-collapsed\')?\'1\':\'0\');}catch(e){}\n }\n syncNavigationButton();\n}\nfunction closeNavigation(){\n document.body.classList.remove(\'nav-open\');\n syncNavigationButton();\n}\n(function initNavigation(){\n try{if(localStorage.getItem(\'nr-nav-collapsed\')===\'1\'&&!nrNavMedia.matches)document.body.classList.add(\'nav-collapsed\');}catch(e){}\n const search=document.getElementById(\'navSearch\'),nav=document.getElementById(\'sideNavigation\'),empty=document.getElementById(\'navEmpty\');\n if(search&&nav){\n  search.addEventListener(\'input\',()=>{\n   const q=search.value.trim().toLowerCase();let shown=0;\n   nav.querySelectorAll("a[href^=\'#\']").forEach(a=>{const hit=!q||a.textContent.toLowerCase().includes(q);a.hidden=!hit;if(hit)shown++;});\n   nav.querySelectorAll(\'.nav-group\').forEach(g=>{let n=g.nextElementSibling,has=false;while(n&&!n.classList.contains(\'nav-group\')){if(n.matches(\'a\')&&!n.hidden)has=true;n=n.nextElementSibling;}g.hidden=!!q&&!has;});\n   if(empty)empty.style.display=shown?\'none\':\'block\';\n  });\n  nav.querySelectorAll("a[href^=\'#\']").forEach(a=>a.addEventListener(\'click\',()=>{closeNavigation();if(search){search.value=\'\';search.dispatchEvent(new Event(\'input\'));}}));\n }\n document.addEventListener(\'keydown\',e=>{if(e.key===\'Escape\')closeNavigation();});\n window.addEventListener(\'resize\',()=>{if(!nrNavMedia.matches)document.body.classList.remove(\'nav-open\');syncNavigationButton();});\n if(typeof nrNavMedia.addEventListener===\'function\')nrNavMedia.addEventListener(\'change\',()=>{document.body.classList.remove(\'nav-open\');syncNavigationButton();});\n syncNavigationButton();\n})();\n// Keep the navigation highlight aligned with the section currently in view.\nif("IntersectionObserver" in window){\n const navLinks=[...document.querySelectorAll("#sideNavigation a[href^=\'#\']")];\n const sections=navLinks.map(a=>document.querySelector(a.getAttribute("href"))).filter(Boolean);\n const navObserver=new IntersectionObserver(entries=>{\n  const visible=entries.filter(e=>e.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];\n  if(!visible)return;navLinks.forEach(a=>a.classList.toggle("active",a.getAttribute("href")==="#"+visible.target.id));\n },{rootMargin:"-16% 0px -70% 0px",threshold:[0,.12,.3]});\n sections.forEach(section=>navObserver.observe(section));\n}\n\nasync function loadPhantomPanels(){\n try{\n  const [u,v,x]=await Promise.all([fetch(\'/api/unknown-hunter\').then(r=>r.json()),fetch(\'/api/ipv6\').then(r=>r.json()),fetch(\'/api/exposure\').then(r=>r.json())]);\n  $(\'unknownRows\').innerHTML=u.map(d=>`<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.name)}</td><td>${esc(d.device_type)}</td><td>${esc(d.os_guess)}</td><td>${d.confidence}%</td><td>${d.evidence_count} / ${d.independent_sources} sources</td><td>${esc(d.status)}</td></tr>`).join(\'\')||\'<tr><td colspan="7">No low-confidence devices in current inventory.</td></tr>\';\n  $(\'ipv6Rows\').innerHTML=v.map(d=>`<tr><td class="mono">${esc(d.ipv6)}</td><td class="mono">${esc(d.mac||\'—\')}</td><td>${esc(d.interface_alias||\'—\')}</td><td>${esc(d.state)}</td><td>${esc(d.timestamp)}</td><td>${esc(d.linked_device_id||\'Uncorrelated\')}</td></tr>`).join(\'\')||\'<tr><td colspan="6">No IPv6 neighbour observations recorded.</td></tr>\';\n  $(\'exposureRows\').innerHTML=x.map(d=>`<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.title)}</td><td class="${d.severity===\'HIGH\'?\'red\':\'amber\'}">${esc(d.severity)}</td><td>${esc(d.observed_ports)}</td><td>${esc(d.recommendation)}</td><td>${esc(d.last_seen)}</td><td>${esc(d.status)}</td></tr>`).join(\'\')||\'<tr><td colspan="7">No current or stale exposure observations.</td></tr>\';\n }catch(e){$(\'unknownRows\').innerHTML=\'<tr><td colspan="7">Panel unavailable: \'+esc(e.message)+\'</td></tr>\';}\n}\nasync function investigateUnknown(){\n const status=$("unknownInvestigationStatus");status.textContent="Reviewing local identity evidence…";\n try{const r=await fetch("/api/unknown-hunter/investigate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({confirm:true,limit:50})});\n  const data=await r.json();if(!r.ok)throw new Error(data.error||("HTTP "+r.status));\n  status.textContent=`Created ${data.created} new and updated ${data.updated} identity-review investigations. These are not threat findings.`;\n  await refreshAll();\n }catch(e){status.textContent="Investigation failed: "+e.message;}\n}\nasync function askRadar(){\n const q=$(\'assistantQuestion\').value.trim(); if(!q)return;\n $(\'assistantAnswer\').textContent=\'Analysing local evidence…\';\n try{const r=await fetch(\'/api/assistant?q=\'+encodeURIComponent(q)).then(x=>x.json());$(\'assistantAnswer\').textContent=r.answer||r.error||\'No answer\';\n const rows=(r.results||[]).slice(0,50);$(\'assistantRows\').innerHTML=rows.map(obj=>`<tr><td>${esc(obj.ip||obj.ipv6||obj.name||\'Record\')}</td><td>${esc(Object.entries(obj).filter(([k])=>![\'ip\',\'ipv6\',\'name\'].includes(k)).map(([k,v])=>k+\': \'+(typeof v===\'object\'?JSON.stringify(v):v)).join(\' · \'))}</td></tr>`).join(\'\')||\'<tr><td colspan="2">No supporting records returned.</td></tr>\';\n }catch(e){$(\'assistantAnswer\').textContent=\'Assistant error: \'+e.message;}\n}\n$(\'assistantQuestion\')?.addEventListener(\'keydown\',e=>{if(e.key===\'Enter\')askRadar();});\n\nlet phantomSelectedIP="";\nlet phantomSshFingerprint="";\nlet phantomSshTrusted=false;\nlet phantomSshSession="";\nlet phantomSshSessionTarget="";\nlet phantomSshTrustedTarget="";\nlet phantomSshSocket=null;\nlet phantomSshResizeObserver=null;\nlet phantomTerminalBuffer=\'\';\nlet phantomTerminalCursor=0;\nlet phantomTerminalPendingCR=false;\nfunction updatePhantomSelectionCount(){\n const selected=document.querySelectorAll(\'.pa-device-check:checked\').length;\n const total=document.querySelectorAll(\'.pa-device-check:not(:disabled)\').length;\n const el=$(\'paSelectionCount\');if(el)el.textContent=`${selected} selected · ${total} online`;\n const all=$(\'paSelectAll\');if(all){all.checked=total>0&&selected===total;all.indeterminate=selected>0&&selected<total;}\n}\nasync function loadPhantomAccess(){\n const body=$(\'phantomAccessRows\'); if(!body)return;\n const previous=new Set([...document.querySelectorAll(\'.pa-device-check:checked\')].map(x=>x.value));\n body.innerHTML=\'<tr><td colspan="11">Loading known devices and previous capability observations…</td></tr>\';\n try{\n  const [data,summary]=await Promise.all([getJSON(\'/api/phantom-access/devices\'),getJSON(\'/api/phantom-access/summary\')]);\n  $(\'paKnown\').textContent=summary.known||0;$(\'paCandidates\').textContent=summary.native_candidates||0;$(\'paSshReachable\').textContent=summary.ssh_reachable||0;$(\'paRdp\').textContent=summary.rdp_reachable||0;$(\'paAgents\').textContent=summary.agent_managed||0;\n  body.innerHTML=(data||[]).map(d=>{const p=d.probes||{};const yes=v=>v===true?\'<span class="green">OPEN</span>\':v===false?\'<span class="muted">CLOSED</span>\':\'<span class="muted">—</span>\';const online=d.status===\'ONLINE\';const checked=previous.has(d.ip);return `<tr data-pa-row="${esc(d.ip)}"><td><input type="checkbox" class="pa-device-check" value="${esc(d.ip)}" ${online?\'\':\'disabled\'} ${checked?\'checked\':\'\'} aria-label="Select ${esc(d.ip)}"></td><td><strong>${esc(d.hostname||d.friendly_name||d.device_name||\'Unknown\')}</strong><div class="hint">${esc(d.manufacturer||\'\')} ${esc(d.model||\'\')}</div></td><td>${esc(d.device_type||\'Unclassified\')}<div class="hint">${esc(d.os_guess||\'Unknown\')}</div></td><td class="mono">${esc(d.ip)}</td><td>${yes(p.winrm_http||p.winrm_https)}</td><td>${yes(p.rpc_endpoint_mapper)}</td><td>${yes(p.smb)}</td><td>${yes(p.rdp)}</td><td>${yes(p.ssh)}</td><td><span class="pill ${d.readiness===\'NATIVE_MGMT_CANDIDATE\'?\'\':\'warn\'}">${esc(d.readiness||\'NOT_PROBED\')}</span><div class="hint">${esc(d.readiness_score??0)}% · ${esc(d.last_probe||\'Not probed\')}</div></td><td class="pa-row-actions"><button class="secondary" data-pa-action="probe" data-ip="${esc(d.ip)}">PROBE</button> <button class="secondary" data-pa-action="select" data-ip="${esc(d.ip)}">SELECT</button> <button class="secondary" data-pa-action="terminal" data-ip="${esc(d.ip)}" ${p.ssh===true&&online?\'\':\'disabled\'}>SSH TERMINAL</button></td></tr>`}).join(\'\')||\'<tr><td colspan="11">No known devices in inventory yet. Run a network scan first.</td></tr>\';\n  updatePhantomSelectionCount();\n }catch(e){body.innerHTML=`<tr><td colspan="11">Could not load Phantom Access: ${esc(e.message)}</td></tr>`;}\n}\nfunction toggleAllPhantom(on){document.querySelectorAll(\'.pa-device-check:not(:disabled)\').forEach(x=>x.checked=on);updatePhantomSelectionCount();}\nfunction selectedPhantomIPs(){return [...document.querySelectorAll(\'.pa-device-check:checked\')].map(x=>x.value);}\nasync function phantomBulk(action){\n const ips=selectedPhantomIPs();if(!ips.length){alert(\'Select at least one online endpoint.\');return;}\n const labels={probe:\'probe\',remote_inventory:\'refresh system inventory\',remote_network:\'collect network snapshots\',remote_storage:\'collect storage snapshots\',remote_security:\'collect security snapshots\'};\n if(!confirm(`Run ${labels[action]||action} on all ${ips.length} selected endpoint(s)? Work will be split into batches of 12 and every result will be recorded.`))return;\n $(\'paStatus\').textContent=`Preparing ${ips.length} endpoint(s)…`;$(\'paOutput\').textContent=\'\';\n const aggregate={action,requested:ips.length,succeeded:0,failed:0,batches:[],results:[]};\n try{\n  for(let offset=0;offset<ips.length;offset+=12){\n   const batch=ips.slice(offset,offset+12);$(\'paStatus\').textContent=`${action.replaceAll(\'_\',\' \')} · batch ${Math.floor(offset/12)+1}/${Math.ceil(ips.length/12)} · ${Math.min(offset+batch.length,ips.length)}/${ips.length} endpoints`;\n   try{const r=await fetch(\'/api/phantom-access/bulk\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({ips:batch,action})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);\n    aggregate.succeeded+=d.succeeded||0;aggregate.failed+=d.failed||0;aggregate.batches.push({batch:Math.floor(offset/12)+1,requested:d.requested,succeeded:d.succeeded,failed:d.failed});aggregate.results.push(...(d.results||[]));\n   }catch(batchError){aggregate.failed+=batch.length;aggregate.batches.push({batch:Math.floor(offset/12)+1,requested:batch.length,succeeded:0,failed:batch.length,error:batchError.message});aggregate.results.push(...batch.map(ip=>({ip,success:false,error:\'Batch request failed: \'+batchError.message})));}\n   $(\'paOutput\').textContent=JSON.stringify(aggregate,null,2);\n  }\n  $(\'paStatus\').textContent=`Bulk ${action}: ${aggregate.succeeded} succeeded · ${aggregate.failed} failed · ${aggregate.requested} requested.`;toast(`Phantom Access: ${aggregate.succeeded}/${aggregate.requested} completed.`);await loadPhantomAccess();\n }catch(e){$(\'paStatus\').textContent=\'Bulk operation interrupted: \'+e.message;$(\'paOutput\').textContent=JSON.stringify(aggregate,null,2)+\'\\n\\n\'+e.message;}\n}\nfunction selectPhantom(ip){if(phantomSshSessionTarget&&phantomSshSessionTarget!==ip&&phantomSshSocket&&phantomSshSocket.readyState<2){if(!confirm(\'Disconnect the active SSH terminal before switching to \'+ip+\'?\'))return;sshDisconnect();}phantomSelectedIP=ip;$(\'paTarget\').textContent=ip;$(\'paSshIp\').value=ip;phantomSshFingerprint=\'\';phantomSshTrusted=false;phantomSshTrustedTarget=\'\';$(\'paSshFingerprint\').textContent=\'Host key not reviewed for this endpoint.\';$(\'paSshTrustBtn\').disabled=true;$(\'paSshConnectBtn\').disabled=true;$(\'paStatus\').textContent=\'Selected \'+ip+\'. Probe capabilities before attempting a remote operation.\';}\nasync function probePhantom(ip){selectPhantom(ip);$(\'paStatus\').textContent=\'Testing management service reachability…\';try{const r=await fetch(\'/api/phantom-access/probe\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({ip,confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$(\'paMethod\').textContent=d.readiness;$(\'paStatus\').textContent=d.summary;$(\'paOutput\').textContent=JSON.stringify(d,null,2);await loadPhantomAccess();}catch(e){$(\'paStatus\').textContent=\'Probe failed: \'+e.message;}}\nasync function phantomAction(action){\n if(!phantomSelectedIP){alert(\'Select a known device first.\');return;}\n let args={};if(action===\'restart_service\'){const n=prompt(\'Exact Windows service name to restart:\');if(!n)return;args.service_name=n;}\n const disruptive=[\'restart_service\',\'restart_computer\',\'shutdown_computer\'];\n if(disruptive.includes(action)&&!confirm(`Run ${action.replaceAll(\'_\',\' \')} on ${phantomSelectedIP} using your current Windows account? This action will be audited.`))return;\n $(\'paStatus\').textContent=\'Executing \'+action+\' using native Windows management…\';\n try{const r=await fetch(\'/api/phantom-access/action\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({ip:phantomSelectedIP,action,args,confirm:disruptive.includes(action)})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$(\'paLastAction\').textContent=action+\' · \'+(d.method||\'\');$(\'paMethod\').textContent=d.method||$(\'paMethod\').textContent;$(\'paOutput\').textContent=JSON.stringify(d,null,2);$(\'paStatus\').textContent=d.message||\'Operation completed.\';await loadPhantomAccess();}catch(e){$(\'paStatus\').textContent=\'Operation failed: \'+e.message;$(\'paOutput\').textContent=e.message;}\n}\nasync function sshApi(path,payload){const r=await fetch(\'/api/phantom-access/ssh/\'+path,{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok)throw new Error(d.error||`HTTP ${r.status}`);return d;}\nfunction sshSetState(text,state=\'warn\'){pill($(\'paSshState\'),text,state);}\nfunction sshAppend(text){\n const out=$(\'paTerminalOutput\');let raw=String(text).replace(/\\x1b\\][^\\x07]*(?:\\x07|\\x1b\\\\)/g,\'\');raw=raw.replace(/\\x1b\\[([0-?]*)([ -/]*)([@-~])/g,(seq,params,inter,final)=>{if(final===\'J\'&&params===\'2\'){phantomTerminalBuffer=\'\';phantomTerminalCursor=0;phantomTerminalPendingCR=false;}else if((final===\'H\'||final===\'f\')&&!params){phantomTerminalCursor=0;}else if(final===\'K\'){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor);}return \'\';});const clean=raw;\n for(const ch of clean){\n  if(ch===\'\\r\'){const lineStart=phantomTerminalBuffer.lastIndexOf(\'\\n\',Math.max(0,phantomTerminalCursor-1))+1;phantomTerminalCursor=lineStart;phantomTerminalPendingCR=true;continue;}\n  if(ch===\'\\n\'){\n   if(phantomTerminalPendingCR){phantomTerminalBuffer+=\'\\n\';phantomTerminalCursor=phantomTerminalBuffer.length;}\n   else{phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+\'\\n\'+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor++;}\n   phantomTerminalPendingCR=false;continue;\n  }\n  if(phantomTerminalPendingCR){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor);phantomTerminalPendingCR=false;}\n  if(ch===\'\\b\'){\n   const lineStart=phantomTerminalBuffer.lastIndexOf(\'\\n\',Math.max(0,phantomTerminalCursor-1))+1;\n   if(phantomTerminalCursor>lineStart){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor-1)+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor--;}\n   continue;\n  }\n  if(ch===\'\\t\'){const spaces=4-(phantomTerminalCursor-(phantomTerminalBuffer.lastIndexOf(\'\\n\')+1))%4;for(let i=0;i<spaces;i++){phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+\' \'+phantomTerminalBuffer.slice(phantomTerminalCursor);phantomTerminalCursor++;}continue;}\n  const code=ch.charCodeAt(0);if(code<32||code===127)continue;\n  if(phantomTerminalCursor<phantomTerminalBuffer.length&&phantomTerminalBuffer[phantomTerminalCursor]!==\'\\n\')phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+ch+phantomTerminalBuffer.slice(phantomTerminalCursor+1);\n  else phantomTerminalBuffer=phantomTerminalBuffer.slice(0,phantomTerminalCursor)+ch+phantomTerminalBuffer.slice(phantomTerminalCursor);\n  phantomTerminalCursor++;\n }\n if(phantomTerminalBuffer.length>220000){const trim=phantomTerminalBuffer.length-180000;phantomTerminalBuffer=phantomTerminalBuffer.slice(trim);phantomTerminalCursor=Math.max(0,phantomTerminalCursor-trim);}\n out.textContent=phantomTerminalBuffer;out.scrollTop=out.scrollHeight;\n}\nasync function sshReviewHostKey(){\n const ip=$(\'paSshIp\').value||phantomSelectedIP;if(!ip){alert(\'Select an online endpoint first.\');return;}\n try{$(\'paSshFingerprintBtn\').disabled=true;$(\'paSshFingerprint\').textContent=\'Performing SSH protocol handshake…\';phantomSshFingerprint=\'\';phantomSshTrusted=false;$(\'paSshTrustBtn\').disabled=true;$(\'paSshConnectBtn\').disabled=true;\n  const d=await sshApi(\'hostkey\',{ip,port:Number($(\'paSshPort\').value||22)});phantomSshFingerprint=d.fingerprint;phantomSshTrustedTarget=\'\';$(\'paSshFingerprint\').textContent=`${d.key_type}\\n${d.fingerprint}\\n\\nVerify this fingerprint on the target device through a trusted channel before accepting it.`;$(\'paSshTrustBtn\').disabled=false;toast(\'SSH host key retrieved. Verify the fingerprint before trusting it.\');\n }catch(e){$(\'paSshFingerprint\').textContent=\'Host-key review failed: \'+e.message;$(\'paStatus\').textContent=e.message;}finally{$(\'paSshFingerprintBtn\').disabled=false;}\n}\nasync function sshTrustHostKey(){\n if(!phantomSshFingerprint||!confirm(\'Trust this exact SSH server fingerprint for this IP and port? Only continue after independently verifying it.\'))return;\n try{$(\'paSshTrustBtn\').disabled=true;const d=await sshApi(\'trust\',{ip:$(\'paSshIp\').value,port:Number($(\'paSshPort\').value||22),fingerprint:phantomSshFingerprint,confirm:true});phantomSshTrusted=!!d.trusted;phantomSshTrustedTarget=($(\'paSshIp\').value||phantomSelectedIP)+\':\'+Number($(\'paSshPort\').value||22);$(\'paSshConnectBtn\').disabled=!phantomSshTrusted;sshAppend(`\\n[TRUSTED HOST KEY] ${d.fingerprint}\\n`);toast(\'SSH host key trusted. You can now authenticate.\');}\n catch(e){$(\'paSshTrustBtn\').disabled=false;$(\'paSshConnectBtn\').disabled=true;$(\'paStatus\').textContent=\'Host-key trust failed: \'+e.message;}\n}\nfunction sshAuthFields(){const mode=$(\'paSshAuth\').value;$(\'paSshKeyWrap\').hidden=mode!==\'key\';$(\'paSshPassphraseWrap\').hidden=mode!==\'key\';$(\'paSshPasswordWrap\').hidden=mode!==\'password\';}\nasync function sshConnect(){\n const targetIp=$(\'paSshIp\').value||phantomSelectedIP;const targetPort=Number($(\'paSshPort\').value||22);if(!phantomSshTrusted||phantomSshTrustedTarget!==targetIp+\':\'+targetPort){alert(\'Review and trust the SSH host key for this exact IP and port first.\');return;}\n const payload={ip:targetIp,port:targetPort,username:$(\'paSshUser\').value,auth_type:$(\'paSshAuth\').value};\n if(payload.auth_type===\'password\')payload.password=$(\'paSshPassword\').value;\n if(payload.auth_type===\'key\'){payload.key_path=$(\'paSshKey\').value;payload.passphrase=$(\'paSshPassphrase\').value;}\n try{$(\'paSshConnectBtn\').disabled=true;sshSetState(\'AUTHENTICATING\',\'warn\');phantomTerminalBuffer=\'\';phantomTerminalCursor=0;phantomTerminalPendingCR=false;$(\'paTerminalOutput\').textContent=\'Connecting to authenticated SSH shell…\\n\';\n  const d=await sshApi(\'connect\',payload);phantomSshSession=d.session_token;phantomSshSessionTarget=targetIp;$(\'paSshPassword\').value=\'\';$(\'paSshPassphrase\').value=\'\';$(\'paSshDisconnectBtn\').disabled=false;$(\'paSshSessionLabel\').textContent=`${d.username}@${d.ip}:${d.port}`;$(\'paTerminalInput\').disabled=false;$(\'paTerminalInput\').focus();\n  const proto=location.protocol===\'https:\'?\'wss:\':\'ws:\';phantomSshSocket=new WebSocket(`${proto}//${location.host}/api/phantom-access/ssh/terminal?token=${encodeURIComponent(phantomSshSession)}`);\n  phantomSshSocket.onopen=()=>{sshSetState(\'CONNECTED\',\'ok\');$(\'paTerminalLatency\').textContent=\'SSH SESSION ACTIVE\';$(\'paTerminalInput\').focus();sshResizeTerminal();if(window.ResizeObserver){phantomSshResizeObserver=new ResizeObserver(sshResizeTerminal);phantomSshResizeObserver.observe($(\'paTerminalOutput\'));}};\n  phantomSshSocket.onmessage=e=>{try{const m=JSON.parse(e.data);if(m.type===\'output\')sshAppend(m.data);else if(m.type===\'status\'&&m.state===\'closed\')sshSetState(\'CLOSED\',\'warn\');}catch(_){sshAppend(e.data);}};\n  phantomSshSocket.onerror=()=>{sshSetState(\'CONNECTION ERROR\',\'bad\');};\n  phantomSshSocket.onclose=()=>{if(phantomSshResizeObserver){phantomSshResizeObserver.disconnect();phantomSshResizeObserver=null;}sshSetState(\'DISCONNECTED\',\'warn\');$(\'paTerminalInput\').disabled=true;$(\'paSshDisconnectBtn\').disabled=true;$(\'paSshConnectBtn\').disabled=false;$(\'paTerminalLatency\').textContent=\'SESSION CLOSED\';phantomSshSocket=null;phantomSshSession=\'\';phantomSshSessionTarget=\'\';};\n }catch(e){sshSetState(\'AUTH FAILED\',\'bad\');$(\'paTerminalOutput\').textContent=\'SSH connection failed: \'+e.message+\'\\n\';$(\'paSshConnectBtn\').disabled=false;$(\'paSshPassword\').value=\'\';$(\'paSshPassphrase\').value=\'\';}\n}\nfunction sshSend(data){if(phantomSshSocket&&phantomSshSocket.readyState===WebSocket.OPEN)phantomSshSocket.send(JSON.stringify({type:\'input\',data}));}\nfunction sshResizeTerminal(){if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;const box=$(\'paTerminalOutput\');const cols=Math.max(40,Math.min(240,Math.floor(box.clientWidth/8)));const rows=Math.max(10,Math.min(100,Math.floor(box.clientHeight/19)));phantomSshSocket.send(JSON.stringify({type:\'resize\',cols,rows}));}\nfunction sshDisconnect(){if(phantomSshSocket){try{if(phantomSshSocket.readyState===WebSocket.OPEN)phantomSshSocket.send(JSON.stringify({type:\'close\'}));}catch(_){}try{phantomSshSocket.close();}catch(_){}}else if(phantomSshSession){sshApi(\'close\',{session_token:phantomSshSession}).catch(()=>{});phantomSshSession=\'\';phantomSshSessionTarget=\'\';}}\nfunction sshTerminalKeydown(e){\n if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;\n const map={Enter:\'\\r\',Backspace:\'\\x7f\',Tab:\'\\t\',Escape:\'\\x1b\',ArrowUp:\'\\x1b[A\',ArrowDown:\'\\x1b[B\',ArrowRight:\'\\x1b[C\',ArrowLeft:\'\\x1b[D\',Home:\'\\x1b[H\',End:\'\\x1b[F\',Delete:\'\\x1b[3~\',PageUp:\'\\x1b[5~\',PageDown:\'\\x1b[6~\'};\n if(e.ctrlKey&&e.key.toLowerCase()===\'c\'){e.preventDefault();sshSend(\'\\x03\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'d\'){e.preventDefault();sshSend(\'\\x04\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'l\'){e.preventDefault();sshSend(\'\\x0c\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'a\'){e.preventDefault();sshSend(\'\\x01\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'e\'){e.preventDefault();sshSend(\'\\x05\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'u\'){e.preventDefault();sshSend(\'\\x15\');return;}\n if(e.ctrlKey&&e.key.toLowerCase()===\'w\'){e.preventDefault();sshSend(\'\\x17\');return;}\n if(map[e.key]){e.preventDefault();sshSend(map[e.key]);return;}\n if(e.key.length===1&&!e.altKey&&!e.metaKey){e.preventDefault();sshSend(e.key);}\n}\nfunction sshTerminalPaste(e){if(!phantomSshSocket||phantomSshSocket.readyState!==WebSocket.OPEN)return;const text=e.clipboardData?.getData(\'text\');if(text){e.preventDefault();sshSend(text.replace(/\\r?\\n/g,\'\\r\'));}}\nfunction bindPhantomTerminal(){\n $(\'phantomAccessRows\')?.addEventListener(\'change\',e=>{if(e.target.matches(\'.pa-device-check\'))updatePhantomSelectionCount();});\n $(\'phantomAccessRows\')?.addEventListener(\'click\',e=>{const b=e.target.closest(\'[data-pa-action]\');if(!b)return;const ip=b.dataset.ip;const action=b.dataset.paAction;if(action===\'probe\')probePhantom(ip);else if(action===\'select\')selectPhantom(ip);else if(action===\'terminal\'){selectPhantom(ip);$(\'phantomTerminal\').scrollIntoView({behavior:\'smooth\',block:\'center\'});$(\'paSshFingerprintBtn\').focus();}});\n $(\'paSshFingerprintBtn\')?.addEventListener(\'click\',sshReviewHostKey);$(\'paSshTrustBtn\')?.addEventListener(\'click\',sshTrustHostKey);$(\'paSshConnectBtn\')?.addEventListener(\'click\',sshConnect);$(\'paSshDisconnectBtn\')?.addEventListener(\'click\',sshDisconnect);$(\'paSshAuth\')?.addEventListener(\'change\',sshAuthFields);$(\'paSshPort\')?.addEventListener(\'change\',()=>{phantomSshFingerprint=\'\';phantomSshTrusted=false;phantomSshTrustedTarget=\'\';$(\'paSshFingerprint\').textContent=\'Port changed. Review the SSH host key again.\';$(\'paSshTrustBtn\').disabled=true;$(\'paSshConnectBtn\').disabled=true;});$(\'paTerminalClear\')?.addEventListener(\'click\',()=>{phantomTerminalBuffer=\'\';phantomTerminalCursor=0;phantomTerminalPendingCR=false;$(\'paTerminalOutput\').textContent=\'\';});$(\'paTerminalInput\')?.addEventListener(\'keydown\',sshTerminalKeydown);$(\'paTerminalInput\')?.addEventListener(\'paste\',sshTerminalPaste);sshAuthFields();\n}\nbindPhantomTerminal();\n\nfunction bindCommandCenterEvents(){\n $(\'agentRows\')?.addEventListener(\'click\',e=>{const b=e.target.closest(\'[data-agent-action]\');if(!b)return;const id=b.dataset.agentId;const action=b.dataset.agentAction;if(action===\'restart_computer\')restartRemote(id);else if(action===\'shutdown_computer\')shutdownRemote(id);else if(action===\'restart_service\')restartRemoteService(id);else if(action===\'revoke\')revokeAgent(id);else agentAction(id,action,{},action===\'lock_workstation\');});\n $(\'agentResultRows\')?.addEventListener(\'click\',e=>{const row=e.target.closest(\'[data-command-id]\');if(row)showAgentResult(Number(row.dataset.commandId));});\n $(\'agentResultRows\')?.addEventListener(\'keydown\',e=>{if(e.key===\'Enter\'||e.key===\' \'){const row=e.target.closest(\'[data-command-id]\');if(row){e.preventDefault();showAgentResult(Number(row.dataset.commandId));}}});\n}\nbindCommandCenterEvents();\n\nasync function loadCommandCenter(){\n try{\n  const [agents,summary,audit,results]=await Promise.all([fetch(\'/api/command/agents\').then(r=>r.json()),fetch(\'/api/command/summary\').then(r=>r.json()),fetch(\'/api/command/audit\').then(r=>r.json()),fetch(\'/api/command/results\').then(r=>r.json())]);\n  $(\'agentManaged\').textContent=summary.managed||0;$(\'agentOnline\').textContent=summary.online||0;$(\'agentQueued\').textContent=summary.queued_commands||0;$(\'agentHubState\').textContent=summary.hub?.state||\'UNKNOWN\';\n  $(\'agentRows\').innerHTML=agents.map(a=>{const inv=a.inventory||{};const cpu=inv.cpu_percent??\'—\';const ram=inv.memory_percent??\'—\';const id=esc(a.agent_id);const controls=a.status===\'REVOKED\'?\'Revoked\':`<button class="secondary" data-agent-action="refresh_inventory" data-agent-id="${id}">Refresh</button> <button class="secondary" data-agent-action="list_processes" data-agent-id="${id}">Processes</button> <button class="secondary" data-agent-action="list_services" data-agent-id="${id}">Services</button> <button class="secondary" data-agent-action="lock_workstation" data-agent-id="${id}">Lock</button> <button class="secondary" data-agent-action="restart_computer" data-agent-id="${id}">Restart PC</button> <button class="secondary" data-agent-action="shutdown_computer" data-agent-id="${id}">Shut down</button> <button class="secondary" data-agent-action="restart_service" data-agent-id="${id}">Restart service</button> <button class="secondary" data-agent-action="revoke" data-agent-id="${id}">Revoke</button>`;return `<tr><td><strong>${esc(a.hostname)}</strong><div class="hint mono">${id}</div></td><td>${esc(a.platform)}<div class="hint">${esc(a.inventory?.manufacturer||\'\')} ${esc(a.inventory?.model||\'\')}</div><div class="hint">${esc(a.os_version)}</div></td><td><span class="pill ${a.status===\'REVOKED\'?\'bad\':(a.status===\'ONLINE\'?\'\':\'warn\')}">${esc(a.status)}</span></td><td>${esc(a.last_seen||\'—\')}</td><td>${esc(cpu)}${cpu===\'—\'?\'\':\'%\'}</td><td>${esc(ram)}${ram===\'—\'?\'\':\'%\'}</td><td class="mono">${esc(a.last_ip||\'—\')}</td><td>${controls}</td></tr>`}).join(\'\')||\'<tr><td colspan="8">No endpoints enrolled. Generate a one-time enrolment token to begin.</td></tr>\';\n  $(\'agentAuditRows\').innerHTML=audit.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.agent_id)}</td><td>${esc(x.actor)}</td><td>${esc(x.action)}</td><td>${esc(x.outcome)}</td><td>${esc(x.details)}</td></tr>`).join(\'\')||\'<tr><td colspan="6">No audit records.</td></tr>\';\n  $(\'agentResultRows\').innerHTML=results.map(x=>`<tr class="clickrow" tabindex="0" role="button" data-command-id="${Number(x.command_id)||0}"><td>#${Number(x.command_id)||0}</td><td>${esc(x.hostname)}</td><td>${esc(x.action)}</td><td>${esc(x.status)}</td><td>${esc(x.completed_at||\'—\')}</td></tr>`).join(\'\')||\'<tr><td colspan="5">No command results.</td></tr>\';window.agentCommandResults=results;\n }catch(e){$(\'agentRows\').innerHTML=\'<tr><td colspan="8">Command Centre unavailable: \'+esc(e.message)+\'</td></tr>\';}\n}\nfunction showAgentResult(id){const item=(window.agentCommandResults||[]).find(x=>x.command_id===id);if(item)$(\'agentCommandOutput\').textContent=JSON.stringify({command_id:item.command_id,device:item.hostname,action:item.action,status:item.status,result:item.result},null,2);}\nasync function createAgentToken(){\n if(!confirm(\'Generate a one-time enrolment token valid for 15 minutes?\'))return;\n try{const r=await fetch(\'/api/command/enrol-token\',{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);$(\'agentToken\').textContent=d.token;$(\'agentTokenBox\').style.display=\'block\';await loadCommandCenter();}catch(e){alert(\'Could not create token: \'+e.message);}\n}\nasync function agentAction(id,action,args={},confirmation=false){\n const risky=[\'restart_computer\',\'shutdown_computer\',\'restart_service\',\'lock_workstation\'];\n if(risky.includes(action)&&!confirm(`Queue ${action.replaceAll(\'_\',\' \')} for ${id}? The action will be recorded in the audit log.`))return;\n try{const r=await fetch(`/api/command/agents/${encodeURIComponent(id)}/commands`,{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({action,args,confirm:confirmation||risky.includes(action)})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);alert(`Action queued. Command #${d.command_id}`);await loadCommandCenter();}catch(e){alert(\'Action not queued: \'+e.message);}\n}\nasync function restartRemote(id){if(!confirm(\'Restart \'+id+\'? The endpoint will schedule a restart in 60 seconds.\'))return;await agentAction(id,\'restart_computer\',{},true);}\nasync function shutdownRemote(id){if(!confirm(\'Shut down \'+id+\'? The endpoint will schedule shutdown in 60 seconds.\'))return;await agentAction(id,\'shutdown_computer\',{},true);}\nasync function restartRemoteService(id){const name=prompt(\'Exact Windows service name to restart (protected core services are blocked):\');if(!name)return;if(!confirm(\'Restart Windows service \'+name+\' on \'+id+\'?\'))return;await agentAction(id,\'restart_service\',{service_name:name},true);}\nasync function revokeAgent(id){if(!confirm(`Immediately revoke ${id}? Its future requests will be rejected and queued commands cancelled.`))return;try{const r=await fetch(`/api/command/agents/${encodeURIComponent(id)}/revoke`,{method:\'POST\',headers:{\'Content-Type\':\'application/json\'},body:JSON.stringify({confirm:true})});const d=await r.json();if(!r.ok)throw new Error(d.error||r.status);await loadCommandCenter();}catch(e){alert(e.message);}}\n\nloadCommandCenter();setInterval(loadCommandCenter,10000);loadPhantomAccess();setInterval(loadPhantomAccess,30000);\n'

# ============================================================
# NETWORKRADAR COMMAND — AUTHENTICATED ENDPOINT MANAGEMENT
# ============================================================

AGENT_HUB = None
AGENT_HUB_THREAD = None
AGENT_ACTIONS = {
    "refresh_inventory": {"confirmation": False, "description": "Refresh hardware and OS inventory"},
    "list_processes": {"confirmation": False, "description": "List running processes"},
    "list_services": {"confirmation": False, "description": "List Windows services"},
    "lock_workstation": {"confirmation": True, "description": "Lock the interactive workstation"},
    "restart_computer": {"confirmation": True, "description": "Restart the computer after a 60-second delay"},
    "shutdown_computer": {"confirmation": True, "description": "Shut down the computer after a 60-second delay"},
    "restart_service": {"confirmation": True, "description": "Restart one explicitly named non-critical Windows service"},
}
_AGENT_CRITICAL_SERVICES = {"rpcss", "dcomlaunch", "lsass", "winlogon", "eventlog", "samss", "plugplay", "power", "profsvc", "winmgmt"}


def _agent_hash(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _agent_pepper():
    # Keep a server-only key outside SQLite so a database copy alone cannot
    # impersonate enrolled agents. Each endpoint still has its own random secret.
    path = DB_MANAGER.path.parent / ".networkradar-agent-pepper"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(32)); handle.flush(); os.fsync(handle.fileno())
        except FileExistsError:
            pass
    raw = path.read_bytes()
    if len(raw) != 32:
        raise RuntimeError("Agent pepper file is invalid; restore its 32-byte backup or revoke/re-enrol agents.")
    try:
        if os.name != "nt": os.chmod(path, 0o600)
    except OSError: pass
    return raw


def _agent_hmac_key(secret_hash, pepper=None):
    pepper = pepper or _agent_pepper()
    return hmac.new(pepper, bytes.fromhex(secret_hash), hashlib.sha256).digest()


def _agent_auth_key(agent_id):
    with DB_MANAGER.read() as conn:
        row = conn.execute("SELECT secret_hash,status FROM remote_agents WHERE agent_id=?", (agent_id,)).fetchone()
    if not row or row[1] == "REVOKED":
        raise PermissionError("Agent is unknown or revoked.")
    return _agent_hmac_key(row[0]).hex()


def _agent_signature_payload(method, path, timestamp, nonce, body):
    return "\n".join([method.upper(), path, str(timestamp), nonce, hashlib.sha256(body).hexdigest()]).encode("utf-8")


def _verify_agent_request(handler, body=b""):
    agent_id = _clean(handler.headers.get("X-NR-Agent", ""), 80)
    timestamp = handler.headers.get("X-NR-Timestamp", "")
    nonce = _clean(handler.headers.get("X-NR-Nonce", ""), 100)
    signature = handler.headers.get("X-NR-Signature", "")
    if not agent_id or not timestamp.isdigit() or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", nonce):
        raise PermissionError("Missing or invalid agent authentication headers.")
    if abs(int(time.time()) - int(timestamp)) > 120:
        raise PermissionError("Request timestamp outside permitted clock-skew window.")
    key = _agent_auth_key(agent_id)
    expected = hmac.new(bytes.fromhex(key), _agent_signature_payload(handler.command, urlparse(handler.path).path, timestamp, nonce, body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise PermissionError("Agent request signature invalid.")
    def _nonce(conn):
        conn.execute("DELETE FROM agent_request_nonces WHERE created_at < ?", ((datetime.now()-timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),))
        conn.execute("INSERT INTO agent_request_nonces(agent_id,nonce,created_at) VALUES(?,?,?)", (agent_id, nonce, now_text()))
    try:
        DB_MANAGER.write(_nonce)
    except sqlite3.IntegrityError:
        raise PermissionError("Replay detected: nonce already used.")
    return agent_id


def _agent_json_body(handler, maximum=65536):
    raw_len = handler.headers.get("Content-Length", "0")
    if not raw_len.isdigit() or int(raw_len) < 0 or int(raw_len) > maximum:
        raise ValueError("Invalid request size.")
    raw = handler.rfile.read(int(raw_len)) if int(raw_len) else b"{}"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid JSON body.") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON object required.")
    return raw, payload


class AgentHubHandler(BaseHTTPRequestHandler):
    server_version = "NetworkRadar-AgentHub/11.0.1"
    def log_message(self, *args):
        pass
    def _reply(self, obj, status=200):
        data=json.dumps(obj,ensure_ascii=False,default=str).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        try:
            raw,payload=_agent_json_body(self)
            if self.path == "/agent/v1/enrol":
                if not is_authorized():
                    return self._reply({"error":"Endpoint enrolment is disabled until the current network is authorised."},403)
                token=str(payload.get("token",""))
                if len(token)<32 or len(token)>128: return self._reply({"error":"Invalid enrolment token."},401)
                token_hash=_agent_hash(token); agent_id="nr-"+uuid.uuid4().hex[:20]
                agent_secret=secrets.token_urlsafe(48); secret_hash=_agent_hash(agent_secret)
                hostname=_clean(payload.get("hostname","Unknown endpoint"),120)
                platform_name=_clean(payload.get("platform","unknown"),80)
                os_version=_clean(payload.get("os_version",""),160)
                agent_version=_clean(payload.get("agent_version",""),40)
                def _enrol(conn):
                    row=conn.execute("SELECT expires_at,used_at FROM agent_enrollment_tokens WHERE token_hash=?",(token_hash,)).fetchone()
                    if not row or row[1] or row[0] < now_text(): raise PermissionError("Enrolment token is invalid, expired or already used.")
                    conn.execute("UPDATE agent_enrollment_tokens SET used_at=? WHERE token_hash=?",(now_text(),token_hash))
                    conn.execute("INSERT INTO remote_agents(agent_id,hostname,platform,os_version,agent_version,secret_hash,status,enrolled_at,last_seen,last_ip,capabilities_json) VALUES(?,?,?,?,?,?,'ONLINE',?,?,?,?)",(agent_id,hostname,platform_name,os_version,agent_version,secret_hash,now_text(),now_text(),self.client_address[0],json.dumps(["inventory","processes","services","lock","power-control"])) )
                    conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),agent_id,"endpoint","ENROL","SUCCESS",hostname))
                DB_MANAGER.write(_enrol)
                # Give this endpoint only its own derived HMAC key. Never disclose
                # the server-wide pepper: a shared pepper would let one enrolled
                # endpoint plus a database copy impersonate every other agent.
                agent_auth_key = _agent_hmac_key(secret_hash).hex()
                return self._reply({"agent_id":agent_id,"auth_key":agent_auth_key,
                    "message":"Enrolled. Store this per-agent key securely; it will not be shown again."},201)
            if self.path == "/agent/v1/report":
                agent_id=_verify_agent_request(self,raw)
                inventory=payload.get("inventory",{})
                if not isinstance(inventory,dict): return self._reply({"error":"inventory must be an object"},400)
                safe=json.dumps(inventory,ensure_ascii=False,default=str)[:50000]
                def _report(conn):
                    cur=conn.execute("UPDATE remote_agents SET status='ONLINE',last_seen=?,last_ip=?,inventory_json=? WHERE agent_id=? AND status!='REVOKED'",(now_text(),self.client_address[0],safe,agent_id))
                    return cur.rowcount
                if not DB_MANAGER.write(_report): return self._reply({"error":"Agent is revoked or no longer enrolled."},401)
                return self._reply({"ok":True,"server_time":int(time.time())})
            if self.path == "/agent/v1/result":
                agent_id=_verify_agent_request(self,raw)
                command_id=int(payload.get("command_id",0)); result=payload.get("result",{})
                if not isinstance(result,dict): result={"error":"invalid result"}
                def _result(conn):
                    state=conn.execute("SELECT status FROM remote_agents WHERE agent_id=?",(agent_id,)).fetchone()
                    if not state or state[0]=="REVOKED": return 0
                    cur=conn.execute("UPDATE agent_commands SET status='COMPLETED',result_json=?,completed_at=? WHERE id=? AND agent_id=? AND status='DELIVERED'",(json.dumps(result,default=str)[:60000],now_text(),command_id,agent_id))
                    conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),agent_id,"agent",f"COMMAND_RESULT:{command_id}","SUCCESS" if not result.get("error") else "ERROR",json.dumps(result,default=str)[:1000]))
                    return cur.rowcount
                if not DB_MANAGER.write(_result): return self._reply({"error":"Command not found or not awaiting result."},404)
                return self._reply({"ok":True})
            return self._reply({"error":"Not found"},404)
        except PermissionError as exc: return self._reply({"error":str(exc)},401)
        except Exception as exc: return self._reply({"error":_clean(exc,250)},400)
    def _handle_ssh_websocket(self, parsed):
        origin = self.headers.get("Origin", "")
        port = int(self.server.server_address[1])
        expected_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        if origin not in expected_origins:
            return self.send_json({"error": "SSH terminal requires a same-origin local browser session."}, 403)
        if self.headers.get("Upgrade", "").lower() != "websocket" or "upgrade" not in self.headers.get("Connection", "").lower():
            return self.send_json({"error": "WebSocket upgrade required."}, 400)
        if self.headers.get("Sec-WebSocket-Version") != "13":
            return self.send_json({"error": "Unsupported WebSocket version."}, 400)
        ws_key = self.headers.get("Sec-WebSocket-Key", "")
        try:
            raw_key = base64.b64decode(ws_key, validate=True)
            if len(raw_key) != 16: raise ValueError("invalid key")
        except Exception:
            return self.send_json({"error": "Invalid WebSocket handshake."}, 400)
        _phantom_ssh_prune_sessions()
        token = parse_qs(parsed.query).get("token", [""])[0]
        with SSH_SESSION_LOCK:
            session = SSH_SESSIONS.get(token)
            if not session or session.get("attached") or time.time()-session.get("last_activity",0) > SSH_SESSION_TTL_SECONDS:
                session = None
            else:
                session["attached"] = True
                session["last_activity"] = time.time()
        if not session:
            return self.send_json({"error": "SSH session is invalid, expired or already attached."}, 401)
        accept = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True
        sock = self.connection
        buffer = bytearray()
        started = time.time()
        try:
            sock.setblocking(False)
            self._ssh_ws_send(sock, {"type": "status", "state": "connected", "ip": session["ip"], "username": session["username"]})
            while time.time() - started < SSH_SESSION_TTL_SECONDS:
                if not session["channel"].active or not session["client"].get_transport() or not session["client"].get_transport().is_active():
                    break
                readable, _, _ = select.select([sock], [], [], 0.04)
                if readable:
                    try: chunk = sock.recv(65536)
                    except BlockingIOError: chunk = None
                    if chunk == b"": break
                    if chunk: buffer.extend(chunk)
                    for opcode, payload in _ws_extract_frames(buffer):
                        if opcode == 8: raise ConnectionAbortedError("Browser closed terminal.")
                        if opcode == 9:
                            self._ssh_ws_send_raw(sock, payload, opcode=10)
                            continue
                        if opcode != 1: continue
                        try: message = json.loads(payload.decode("utf-8"))
                        except Exception: continue
                        if not isinstance(message, dict): continue
                        kind = message.get("type")
                        if kind == "input":
                            data = message.get("data", "")
                            if isinstance(data, str) and len(data) <= 8192:
                                session["channel"].sendall(data.encode("utf-8"))
                                session["last_activity"] = time.time()
                        elif kind == "resize":
                            cols = max(40, min(240, int(message.get("cols", 120))))
                            rows = max(10, min(100, int(message.get("rows", 36))))
                            session["channel"].resize_pty(width=cols, height=rows)
                        elif kind == "close":
                            raise ConnectionAbortedError("Operator closed terminal.")
                channel = session["channel"]
                if channel.recv_ready():
                    output = channel.recv(32768)
                    if output: self._ssh_ws_send(sock, {"type": "output", "data": output.decode("utf-8", errors="replace")})
                if channel.recv_stderr_ready():
                    output = channel.recv_stderr(16384)
                    if output: self._ssh_ws_send(sock, {"type": "output", "data": output.decode("utf-8", errors="replace")})
                session["last_activity"] = time.time()
        except Exception:
            # A failed browser socket or SSH channel must always release the session.
            pass
        finally:
            try: self._ssh_ws_send(sock, {"type": "status", "state": "closed"})
            except Exception: pass
            phantom_ssh_close(token, "websocket_closed")

    @staticmethod
    def _ssh_ws_send_raw(sock, payload, opcode=1):
        frame = _ws_encode(payload, opcode=opcode)
        sock.setblocking(True); sock.settimeout(1.0)
        try: sock.sendall(frame)
        finally: sock.setblocking(False)

    @classmethod
    def _ssh_ws_send(cls, sock, payload):
        cls._ssh_ws_send_raw(sock, json.dumps(payload, ensure_ascii=False).encode("utf-8"), opcode=1)

    def do_GET(self):
        try:
            if self.path.startswith("/agent/v1/commands"):
                if not is_authorized():
                    return self._reply({"error":"Command delivery is disabled until the current network is authorised."},403)
                agent_id=_verify_agent_request(self,b"")
                def _take(conn):
                    conn.execute("UPDATE agent_commands SET status='EXPIRED' WHERE agent_id=? AND status IN ('QUEUED','DELIVERED') AND expires_at<?",(agent_id,now_text()))
                    rows=conn.execute("SELECT id,action,args_json FROM agent_commands WHERE agent_id=? AND status='QUEUED' AND expires_at>=? ORDER BY id LIMIT 5",(agent_id,now_text())).fetchall()
                    for row in rows: conn.execute("UPDATE agent_commands SET status='DELIVERED' WHERE id=? AND status='QUEUED'",(row[0],))
                    return [{"id":r[0],"action":r[1],"args":json.loads(r[2] or "{}")} for r in rows]
                return self._reply({"commands":DB_MANAGER.write(_take)})
            return self._reply({"error":"Not found"},404)
        except PermissionError as exc: return self._reply({"error":str(exc)},401)
        except Exception as exc: return self._reply({"error":_clean(exc,250)},400)


def stop_agent_hub():
    global AGENT_HUB, AGENT_HUB_THREAD
    server, AGENT_HUB = AGENT_HUB, None
    if server is not None:
        try: server.shutdown(); server.server_close()
        except Exception: pass
    AGENT_HUB_THREAD = None


def start_agent_hub_status():
    if not is_authorized():
        return {"state":"BLOCKED","reason":"The current network profile is not authorised."}
    if AGENT_HUB is not None:
        return {"state":"ONLINE","address":str(AGENT_HUB.server_address)}
    if os.environ.get("NETWORKRADAR_AGENT_ENABLED","0")!="1": return {"state":"DISABLED"}
    return {"state":"NOT_STARTED_OR_BLOCKED","reason":"Check TLS certificate/key configuration and startup logs."}


def start_agent_hub():
    global AGENT_HUB, AGENT_HUB_THREAD
    if not is_authorized():
        return {"state":"BLOCKED","reason":"The current network profile is not authorised; endpoint management remains disabled."}
    if AGENT_HUB is not None:
        return {"state":"ONLINE","address":str(AGENT_HUB.server_address),"note":"Agent hub is already running."}
    if os.environ.get("NETWORKRADAR_AGENT_ENABLED", "0") != "1":
        return {"state":"DISABLED","reason":"Set NETWORKRADAR_AGENT_ENABLED=1 to enable endpoint management."}
    cert=os.environ.get("NETWORKRADAR_AGENT_CERT","").strip(); key=os.environ.get("NETWORKRADAR_AGENT_KEY","").strip()
    if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
        return {"state":"BLOCKED","reason":"TLS certificate and private key are required; agent hub was not started."}
    bind=os.environ.get("NETWORKRADAR_AGENT_BIND","127.0.0.1").strip()
    port=int(os.environ.get("NETWORKRADAR_AGENT_PORT","8767"))
    class TLSServer(ThreadingHTTPServer):
        daemon_threads=True; allow_reuse_address=False
    server=None
    try:
        server=TLSServer((bind,port),AgentHubHandler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert,keyfile=key); server.socket=context.wrap_socket(server.socket,server_side=True)
        AGENT_HUB=server
        AGENT_HUB_THREAD=threading.Thread(target=server.serve_forever,name="NR-AgentHub",daemon=True); AGENT_HUB_THREAD.start()
        return {"state":"ONLINE","bind":bind,"port":port,"certificate_file":cert,"note":"Agents must pin the SHA-256 fingerprint of the presented leaf certificate. Default bind is loopback; configure an explicit LAN bind only when remote agents need access."}
    except Exception as exc:
        if server is not None:
            try: server.server_close()
            except Exception: pass
        return {"state":"FAILED","reason":_clean(exc,250)}


def create_agent_enrollment_token(actor="local-user"):
    if not is_authorized():
        raise RuntimeError("The current network profile is not authorised; endpoint enrolment is disabled.")
    token=secrets.token_urlsafe(36); created=datetime.now(); expires=created+timedelta(minutes=15)
    def _w(conn):
        conn.execute("INSERT INTO agent_enrollment_tokens(token_hash,created_at,expires_at,created_by) VALUES(?,?,?,?)",(_agent_hash(token),created.strftime("%Y-%m-%d %H:%M:%S"),expires.strftime("%Y-%m-%d %H:%M:%S"),_clean(actor,80)))
        conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),"",_clean(actor,80),"CREATE_ENROLMENT_TOKEN","SUCCESS","Single-use token; expires in 15 minutes."))
    DB_MANAGER.write(_w)
    return {"token":token,"expires_at":expires.strftime("%Y-%m-%d %H:%M:%S"),"uses":1}


def queue_agent_command(agent_id, action, args=None, actor="local-user", confirmed=False):
    if not is_authorized():
        raise ValueError("The current network profile is not authorised; endpoint commands are disabled.")
    agent_id=str(agent_id or "")
    if not re.fullmatch(r"nr-[a-f0-9]{20}",agent_id): raise ValueError("Invalid agent identifier.")
    action=str(action or "").strip().lower(); spec=AGENT_ACTIONS.get(action)
    if not spec: raise ValueError("Unsupported management action.")
    if spec["confirmation"] and confirmed is not True: raise ValueError("This action requires explicit confirmation.")
    args=args if isinstance(args,dict) else {}
    clean_args={}
    if action=="restart_service":
        name=str(args.get("service_name","")).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",name) or name.lower() in _AGENT_CRITICAL_SERVICES:
            raise ValueError("Invalid or protected Windows service name.")
        clean_args={"service_name":name}
    def _w(conn):
        row=conn.execute("SELECT status FROM remote_agents WHERE agent_id=?",(agent_id,)).fetchone()
        if not row or row[0]=="REVOKED": raise ValueError("Agent not found or revoked.")
        cur=conn.execute("INSERT INTO agent_commands(agent_id,action,args_json,status,created_at,expires_at,approved_by) VALUES(?,?,?,'QUEUED',?,?,?)",(agent_id,action,json.dumps(clean_args),now_text(),(datetime.now()+timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),_clean(actor,80)))
        conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),agent_id,_clean(actor,80),action,"QUEUED",json.dumps(clean_args)))
        return cur.lastrowid
    return {"queued":True,"command_id":DB_MANAGER.write(_w),"action":action}


# ============================================================
# PHANTOM ACCESS — AGENTLESS WINDOWS MANAGEMENT
# ============================================================

PHANTOM_PORTS = {
    "rpc_endpoint_mapper": 135, "smb": 445, "rdp": 3389,
    "winrm_http": 5985, "winrm_https": 5986, "ssh": 22,
}
PHANTOM_PROTECTED_SERVICES = {"rpcss", "dcomlaunch", "lsass", "winlogon", "eventlog", "samss", "plugplay", "power", "profsvc", "winmgmt"}
PHANTOM_PROBE_MAX_AGE_SECONDS = 180

def _phantom_validate_target(ip):
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError("Target must be a literal IP address from the current NetworkRadar inventory.")
    if not addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise ValueError("Agentless management is restricted to private, routable LAN addresses.")
    with DB_MANAGER.read() as conn:
        row = conn.execute("SELECT ip,status FROM devices WHERE ip=?", (str(addr),)).fetchone()
    if not row or row[1] != "ONLINE":
        raise ValueError("Target must be an ONLINE device already present in NetworkRadar inventory.")
    if not is_authorized():
        raise ValueError("The current network profile is not authorised for active management. Approve the current network profile first.")
    return str(addr)

def _phantom_probe_port(ip, port, timeout=0.45):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except (OSError, TimeoutError, ValueError):
        return False

# ============================================================
# PHANTOM TERMINAL — AUTHENTICATED SSH ACCESS
# ============================================================
SSH_KNOWN_HOSTS = DATA / "ssh_known_hosts"
SSH_SESSION_TTL_SECONDS = 900
SSH_MAX_SESSIONS = 4
SSH_SESSIONS = {}
SSH_SESSION_LOCK = threading.RLock()


def _phantom_ssh_require():
    if paramiko is None:
        raise RuntimeError("SSH support is not installed. Run: python -m pip install -r requirements-ssh.txt")
    return paramiko


def _phantom_ssh_port(value):
    try:
        port = int(22 if value is None or value == "" else value)
    except (TypeError, ValueError):
        raise ValueError("SSH port must be an integer between 1 and 65535.")
    if not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535.")
    return port


def _phantom_ssh_host_alias(ip, port):
    return str(ip) if int(port) == 22 else f"[{ip}]:{int(port)}"


def _phantom_ssh_fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _phantom_ssh_fetch_host_key(ip, port=22):
    """Perform an SSH protocol handshake only; never authenticates or executes commands."""
    lib = _phantom_ssh_require()
    target = _phantom_validate_target(ip)
    port = _phantom_ssh_port(port)
    sock = socket.create_connection((target, port), timeout=5)
    transport = None
    try:
        transport = lib.Transport(sock)
        transport.start_client(timeout=6)
        key = transport.get_remote_server_key()
        return {"ip": target, "port": port, "key_type": key.get_name(),
                "fingerprint": _phantom_ssh_fingerprint(key), "key": key}
    finally:
        try:
            if transport: transport.close()
            else: sock.close()
        except Exception:
            pass


def phantom_ssh_hostkey_preview(ip, port=22):
    info = _phantom_ssh_fetch_host_key(ip, port)
    return {k: info[k] for k in ("ip", "port", "key_type", "fingerprint")}


def phantom_ssh_trust_hostkey(ip, port=22, fingerprint="", confirm=False):
    if confirm is not True:
        raise ValueError("Explicit confirmation is required to trust this SSH host key.")
    info = _phantom_ssh_fetch_host_key(ip, port)
    if not secrets.compare_digest(str(fingerprint), info["fingerprint"]):
        raise ValueError("The SSH host key changed between review and trust. Review the new fingerprint before proceeding.")
    alias = _phantom_ssh_host_alias(info["ip"], info["port"])
    SSH_KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    keys = paramiko.HostKeys()
    if SSH_KNOWN_HOSTS.exists():
        keys.load(str(SSH_KNOWN_HOSTS))
    existing = keys.lookup(alias) or {}
    current = existing.get(info["key_type"])
    if current and current.asbytes() != info["key"].asbytes():
        raise ValueError("A different key is already trusted for this endpoint. Resolve the host-key change manually; it was not overwritten.")
    keys.add(alias, info["key_type"], info["key"])
    temporary = SSH_KNOWN_HOSTS.with_suffix(".tmp")
    keys.save(str(temporary))
    os.replace(temporary, SSH_KNOWN_HOSTS)
    try:
        if os.name != "nt": os.chmod(SSH_KNOWN_HOSTS, 0o600)
    except OSError:
        pass
    DB_MANAGER.write(lambda conn: conn.execute(
        "INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",
        (now_text(), "", "local-user", "SSH_HOST_KEY_TRUST", "SUCCESS",
         json.dumps({"ip": info["ip"], "port": info["port"], "key_type": info["key_type"], "fingerprint": info["fingerprint"]}))))
    return {"trusted": True, "ip": info["ip"], "port": info["port"],
            "key_type": info["key_type"], "fingerprint": info["fingerprint"]}


def _phantom_ssh_audit(ip, action, outcome, details=None):
    safe = details if isinstance(details, dict) else {}
    DB_MANAGER.write(lambda conn: conn.execute(
        "INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",
        (now_text(), "", "local-user", "SSH:" + str(action)[:64], str(outcome)[:32],
         json.dumps({"ip": str(ip), **safe}, default=str)[:3000])))


def _phantom_ssh_prune_sessions():
    expired = []
    with SSH_SESSION_LOCK:
        for token, session in list(SSH_SESSIONS.items()):
            if time.time() - session.get("last_activity", 0) > SSH_SESSION_TTL_SECONDS:
                expired.append(SSH_SESSIONS.pop(token, None))
    for session in expired:
        if not session: continue
        try: session["channel"].close()
        except Exception: pass
        try: session["client"].close()
        except Exception: pass
        try: _phantom_ssh_audit(session["ip"], "SESSION_EXPIRED", "SUCCESS",
                               {"port": session["port"], "username": session["username"]})
        except Exception: pass


def phantom_ssh_connect(ip, username, port=22, auth_type="agent", password=None,
                        key_path=None, passphrase=None):
    lib = _phantom_ssh_require()
    _phantom_ssh_prune_sessions()
    target = _phantom_validate_target(ip)
    port = _phantom_ssh_port(port)
    username = str(username or "").strip()
    if not username or len(username) > 128 or any(c in username for c in "\r\n\x00"):
        raise ValueError("Enter a valid SSH username.")
    auth_type = str(auth_type or "agent").lower()
    if auth_type not in {"agent", "password", "key"}:
        raise ValueError("Unsupported SSH authentication method.")
    if not _phantom_probe_port(target, port, timeout=1.2):
        raise RuntimeError("SSH port is not reachable. Probe the endpoint and confirm SSH is enabled.")
    alias = _phantom_ssh_host_alias(target, port)
    if not SSH_KNOWN_HOSTS.exists():
        raise ValueError("SSH host key has not been trusted. Review and trust its fingerprint first.")
    client = lib.SSHClient()
    client.load_host_keys(str(SSH_KNOWN_HOSTS))
    client.set_missing_host_key_policy(lib.RejectPolicy())
    connect_args = {"hostname": target, "port": port, "username": username,
                    "timeout": 8, "banner_timeout": 8, "auth_timeout": 12,
                    "look_for_keys": auth_type == "agent",
                    "allow_agent": auth_type == "agent"}
    if auth_type == "password":
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise ValueError("Enter the SSH password. It is used only for this connection and is not stored.")
        connect_args["password"] = password
    elif auth_type == "key":
        path = Path(str(key_path or "")).expanduser()
        if not path.is_file():
            raise ValueError("The private-key file path does not exist on the NetworkRadar computer.")
        connect_args["key_filename"] = str(path)
        connect_args["passphrase"] = passphrase or None
        connect_args["look_for_keys"] = False
        connect_args["allow_agent"] = False
    token = None
    try:
        client.connect(**connect_args)
        transport = client.get_transport()
        if not transport or not transport.is_authenticated():
            raise RuntimeError("SSH transport did not reach an authenticated state.")
        transport.set_keepalive(30)
        channel = client.invoke_shell(term="xterm-256color", width=120, height=36)
        channel.settimeout(2.0)
        token = secrets.token_urlsafe(32)
        session = {"token": token, "ip": target, "port": port, "username": username,
                   "auth_type": auth_type, "client": client, "channel": channel,
                   "created": time.time(), "last_activity": time.time(), "attached": False}
        with SSH_SESSION_LOCK:
            if len(SSH_SESSIONS) >= SSH_MAX_SESSIONS:
                channel.close(); client.close()
                raise RuntimeError(f"Phantom Terminal supports at most {SSH_MAX_SESSIONS} concurrent SSH sessions. Close an existing session first.")
            SSH_SESSIONS[token] = session
        _phantom_ssh_audit(target, "SESSION_OPEN", "SUCCESS",
                           {"port": port, "username": username, "auth_type": auth_type,
                            "host_key_alias": alias})
        return {"connected": True, "ip": target, "port": port, "username": username,
                "auth_type": auth_type, "session_token": token,
                "expires_in_seconds": SSH_SESSION_TTL_SECONDS,
                "message": "SSH authenticated. Attach the local terminal to begin interacting."}
    except Exception:
        if token:
            with SSH_SESSION_LOCK:
                SSH_SESSIONS.pop(token, None)
        client.close()
        raise


def phantom_ssh_close(token, reason="operator_closed"):
    with SSH_SESSION_LOCK:
        session = SSH_SESSIONS.pop(str(token or ""), None)
    if not session:
        return {"closed": False, "message": "Session was already closed or expired."}
    try: session["channel"].close()
    except Exception: pass
    try: session["client"].close()
    except Exception: pass
    try:
        _phantom_ssh_audit(session["ip"], "SESSION_CLOSE", "SUCCESS",
                           {"port": session["port"], "username": session["username"],
                            "duration_seconds": round(time.time()-session["created"], 1),
                            "reason": str(reason)[:80]})
    except Exception:
        pass
    return {"closed": True}


def _ws_encode(payload, opcode=1):
    data = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
    n = len(data)
    head = bytearray([0x80 | (opcode & 0x0f)])
    if n < 126: head.append(n)
    elif n < 65536: head.extend((126,)); head.extend(struct.pack("!H", n))
    else: head.extend((127,)); head.extend(struct.pack("!Q", n))
    return bytes(head) + data


def _ws_extract_frames(buffer):
    frames = []
    while len(buffer) >= 2:
        b1, b2 = buffer[0], buffer[1]
        fin, opcode, masked = bool(b1 & 0x80), b1 & 0x0f, bool(b2 & 0x80)
        if not fin:
            raise ValueError("Fragmented terminal frames are not supported.")
        if not masked:
            raise ValueError("Browser-to-server WebSocket frames must be masked.")
        length, offset = b2 & 0x7f, 2
        if length == 126:
            if len(buffer) < 4: break
            length = struct.unpack("!H", buffer[2:4])[0]; offset = 4
        elif length == 127:
            if len(buffer) < 10: break
            length = struct.unpack("!Q", buffer[2:10])[0]; offset = 10
        if length > 65536:
            raise ValueError("WebSocket frame exceeds the terminal message limit.")
        if masked:
            if len(buffer) < offset + 4 + length: break
            mask = buffer[offset:offset+4]; offset += 4
            payload = bytearray(buffer[offset:offset+length])
            for i in range(length): payload[i] ^= mask[i % 4]
            payload = bytes(payload)
        else:
            if len(buffer) < offset + length: break
            payload = bytes(buffer[offset:offset+length])
        frames.append((opcode, payload))
        del buffer[:offset+length]
    return frames


def phantom_probe_device(ip):
    target = _phantom_validate_target(ip)
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_phantom_probe_port, target, port): name for name, port in PHANTOM_PORTS.items()}
        for future in as_completed(futures):
            results[futures[future]] = bool(future.result())
    winrm = results.get("winrm_http") or results.get("winrm_https")
    wmi_rpc = results.get("rpc_endpoint_mapper")
    rdp = results.get("rdp")
    if winrm:
        readiness, score = "NATIVE_MGMT_CANDIDATE", 70 + (10 if wmi_rpc else 0)
        summary = "WinRM port reachable. Native PowerShell Remoting is a candidate; authentication and policy still need verification."
    elif wmi_rpc:
        readiness, score = "WMI_READ_CANDIDATE", 45
        summary = "RPC endpoint mapper reachable. WMI/DCOM read-only inventory may be possible if Windows firewall and account permissions allow it."
    elif rdp:
        readiness, score = "RDP_REACHABLE", 40
        summary = "RDP port reachable. Desktop access may be possible for an authorised account; this is not an authentication test."
    elif results.get("ssh"):
        readiness, score = "SSH_TERMINAL_CANDIDATE", 35
        summary = "SSH port reachable. Review the server host-key fingerprint and authenticate with an authorised account before opening a terminal."
    elif results.get("smb") or results.get("rpc_endpoint_mapper"):
        readiness, score = "LIMITED_NATIVE_SERVICES", 25
        summary = "Some Windows management-related ports are reachable, but remote command access is not established."
    else:
        readiness, score = "DISCOVERY_ONLY", 5
        summary = "No tested native management service is reachable. Device discovery remains available."
    # Presence of an agent takes precedence over inferred agentless capability.
    with DB_MANAGER.read() as conn:
        agent = conn.execute("SELECT agent_id FROM remote_agents WHERE last_ip=? AND status!='REVOKED' AND last_seen>=? ORDER BY last_seen DESC LIMIT 1", (target, (datetime.now()-timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"))).fetchone()
    if agent:
        readiness, score = "AGENT_MANAGED", 100
        summary = "A NetworkRadar agent is enrolled for this endpoint. Agentless capabilities remain separately visible."
    payload = json.dumps(results, separators=(",", ":"))
    def _save(conn):
        conn.execute("""INSERT INTO agentless_device_access(ip,last_probe,probes_json,readiness,readiness_score)
            VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET last_probe=excluded.last_probe,
            probes_json=excluded.probes_json,readiness=excluded.readiness,readiness_score=excluded.readiness_score""",
            (target, now_text(), payload, readiness, score))
        conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",
            (now_text(), "", "local-user", "AGENTLESS_CAPABILITY_PROBE", "SUCCESS", json.dumps({"ip":target,"readiness":readiness,"ports":results})))
    DB_MANAGER.write(_save)
    return {"ip":target,"probes":results,"readiness":readiness,"readiness_score":score,"summary":summary,
            "important":"Port reachability is not proof of successful authentication or authorisation."}

def _phantom_readiness_from_probes(probes):
    """Conservative display classification derived only from last probe results."""
    if probes.get("winrm_http") or probes.get("winrm_https"):
        return "NATIVE_MGMT_CANDIDATE", 70 + (10 if probes.get("rpc_endpoint_mapper") else 0)
    if probes.get("rpc_endpoint_mapper"):
        return "WMI_READ_CANDIDATE", 45
    if probes.get("rdp"):
        return "RDP_REACHABLE", 40
    if probes.get("ssh"):
        return "SSH_TERMINAL_CANDIDATE", 35
    if probes.get("smb"):
        return "LIMITED_NATIVE_SERVICES", 25
    if probes:
        return "DISCOVERY_ONLY", 5
    return "NOT_PROBED", 0


def phantom_access_inventory():
    with DB_MANAGER.read() as conn:
        rows = conn.execute("""SELECT d.ip,d.manufacturer,d.hostname,d.device_name,d.device_type,d.os_guess,d.model,d.status,
            a.last_probe,a.probes_json,a.readiness,a.readiness_score
            FROM devices d LEFT JOIN agentless_device_access a ON a.ip=d.ip
            ORDER BY CASE d.status WHEN 'ONLINE' THEN 0 ELSE 1 END,d.ip""").fetchall()
        agents = {r[0] for r in conn.execute("SELECT last_ip FROM remote_agents WHERE status!='REVOKED' AND last_ip!='' AND last_seen>=?", ((datetime.now()-timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),)).fetchall()}
        recent_reads = {}
        cutoff = (datetime.now()-timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        for audit in conn.execute("""SELECT timestamp,action,details FROM agent_audit_events
            WHERE outcome='SUCCESS' AND action IN ('AGENTLESS:remote_inventory',
            'AGENTLESS:remote_processes','AGENTLESS:remote_services') AND timestamp>=?
            ORDER BY timestamp DESC LIMIT 300""", (cutoff,)).fetchall():
            try:
                detail=json.loads(audit[2] or "{}")
                addr=detail.get("ip")
                if addr and addr not in recent_reads:
                    recent_reads[addr]={"timestamp":audit[0],"action":audit[1],
                                        "method":detail.get("method","Native Windows")}
            except Exception:
                continue
    out=[]
    for r in rows:
        try: probes=json.loads(r[9] or "{}")
        except Exception: probes={}
        readiness=r[10] or "NOT_PROBED"; score=r[11] or 0
        verified_read = recent_reads.get(r[0])
        if r[0] in agents:
            readiness,score="AGENT_MANAGED",100
        elif verified_read:
            readiness,score="NATIVE_READ_VERIFIED",90
        elif readiness == "AGENT_MANAGED":
            # Do not leave an endpoint labelled agent-managed forever after its
            # heartbeat stops. Fall back to its last independent native probe.
            readiness,score=_phantom_readiness_from_probes(probes)
        try:
            probe_age=max(0,int((datetime.now()-datetime.strptime(r[8], "%Y-%m-%d %H:%M:%S")).total_seconds())) if r[8] else None
        except (TypeError,ValueError):
            probe_age=None
        out.append({"ip":r[0],"manufacturer":r[1],"hostname":r[2],"friendly_name":r[3],"device_name":r[3],"device_type":r[4],"os_guess":r[5],"model":r[6],"status":r[7],"last_probe":r[8],"probe_age_seconds":probe_age,"probes":probes,"readiness":readiness,"readiness_score":score,
                    "last_successful_read":verified_read})
    return out

def phantom_access_bulk(ips, action="probe"):
    """Run bounded, audited bulk discovery/read-only actions on selected inventory devices."""
    allowed = {"probe", "remote_inventory", "remote_network", "remote_storage", "remote_bios", "remote_security"}
    if action not in allowed:
        raise ValueError("Bulk mode supports discovery and read-only inventory actions only.")
    if not isinstance(ips, list) or not ips:
        raise ValueError("Select at least one device.")
    if len(ips) > 12:
        raise ValueError("Bulk operations are limited to 12 devices per run.")
    # De-duplicate without changing the user's selection order.
    targets = list(dict.fromkeys(str(x).strip() for x in ips))
    if len(targets) > 12:
        raise ValueError("Bulk operations are limited to 12 unique devices per run.")
    def run_one(ip):
        try:
            _phantom_validate_target(ip)
            if action == "probe":
                result = phantom_probe_device(ip)
            else:
                # Always refresh reachability immediately before an operation.
                probe = phantom_probe_device(ip)
                if not (probe["probes"].get("winrm_http") or probe["probes"].get("winrm_https") or probe["probes"].get("rpc_endpoint_mapper")):
                    raise RuntimeError("No WinRM or WMI/DCOM management path was reachable.")
                result = phantom_agentless_action(ip, action, {}, False)
            return {"ip": ip, "success": True, "result": result}
        except Exception as exc:
            return {"ip": ip, "success": False, "error": _clean(exc, 500)}
    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
        results = list(pool.map(run_one, targets))
    return {"action": action, "requested": len(targets),
            "succeeded": sum(1 for x in results if x["success"]),
            "failed": sum(1 for x in results if not x["success"]),
            "results": results,
            "safety": "Bulk operations are read-only; disruptive actions must be performed individually."}


def phantom_access_summary():
    rows=phantom_access_inventory()
    return {"known":len(rows),
            "native_candidates":sum(1 for x in rows if x["readiness"] in {"NATIVE_MGMT_CANDIDATE","WMI_READ_CANDIDATE"}),
            "rdp_reachable":sum(1 for x in rows if x["probes"].get("rdp")),
            "ssh_reachable":sum(1 for x in rows if x["probes"].get("ssh")),
            "agent_managed":sum(1 for x in rows if x["readiness"]=="AGENT_MANAGED")}

def _phantom_run_powershell(target, script, timeout=45):
    if os.name != "nt":
        raise RuntimeError("Native Windows remote management can only be initiated from a Windows NetworkRadar host.")
    encoded = __import__("base64").b64encode(script.encode("utf-16le")).decode("ascii")
    proc = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand", encoded], capture_output=True, text=True, timeout=timeout, creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    if proc.returncode != 0:
        detail=(proc.stderr or proc.stdout or f"PowerShell exited {proc.returncode}").strip()
        raise RuntimeError(detail[-1800:])
    raw=proc.stdout.strip()
    try: return json.loads(raw) if raw else {"success":True,"output":""}
    except json.JSONDecodeError: return {"success":True,"output":raw[-12000:]}

def _phantom_agentless_action_impl(ip, action, args=None, confirm=False):
    target=_phantom_validate_target(ip); args=args if isinstance(args,dict) else {}
    allowed={"test_winrm","test_wmi","remote_inventory","remote_processes","remote_services",
             "remote_network","remote_storage","remote_bios","remote_security",
             "open_rdp","restart_service","restart_computer","shutdown_computer"}
    if action not in allowed: raise ValueError("Unsupported agentless action.")
    if action in {"restart_service","restart_computer","shutdown_computer"} and confirm is not True:
        raise ValueError("Explicit confirmation is required for this operation.")
    # Capability observations expire quickly: do not act on stale port state.
    with DB_MANAGER.read() as conn:
        row=conn.execute("SELECT last_probe,probes_json FROM agentless_device_access WHERE ip=?",(target,)).fetchone()
    if not row:
        raise ValueError("No capability probe exists. Probe this device before attempting management.")
    try:
        probe_time=datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        probe_age=(datetime.now()-probe_time).total_seconds()
    except (TypeError, ValueError):
        raise ValueError("The stored capability probe timestamp is invalid. Probe this device again.")
    if probe_age < -30 or probe_age > PHANTOM_PROBE_MAX_AGE_SECONDS:
        raise ValueError("The capability probe is stale (older than 3 minutes). Probe this device again before management.")
    try:
        probes=json.loads(row[1] or "{}")
    except (TypeError, json.JSONDecodeError):
        raise ValueError("The stored capability results are invalid. Probe this device again.")
    if not isinstance(probes, dict):
        raise ValueError("The stored capability results are invalid. Probe this device again.")
    if action=="open_rdp":
        if not row or not json.loads(row[1] or "{}").get("rdp"):
            raise ValueError("RDP has not been observed reachable. Probe the device first.")
        if os.name!="nt": raise RuntimeError("RDP launch is supported from Windows NetworkRadar hosts only.")
        rdp_target=f"[{target}]" if ipaddress.ip_address(target).version==6 else target
        subprocess.Popen(["mstsc.exe",f"/v:{rdp_target}"],creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        result={"launched":True,"target":target,"message":"Windows Remote Desktop client launched. Authentication remains controlled by Windows."}
        method="RDP client hand-off"
    else:
        winrm_available = bool(probes.get("winrm_http") or probes.get("winrm_https"))
        winrm_ssl_flag = " -UseSSL" if probes.get("winrm_https") else ""
        wmi_available = bool(probes.get("rpc_endpoint_mapper"))
        if action == "test_wmi":
            if not wmi_available:
                raise ValueError("RPC endpoint mapper (TCP 135) was not reachable during the latest probe. WMI/DCOM cannot be tested until the service and firewall permit it.")
            script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -OperationTimeoutSec 15 -ErrorAction Stop; try {{$cs=Get-CimInstance -CimSession $s Win32_ComputerSystem -ErrorAction Stop; [pscustomobject]@{{success=$true;computer=$cs.Name;manufacturer=$cs.Manufacturer;model=$cs.Model;method='WMI/DCOM'}} | ConvertTo-Json -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            result=_phantom_run_powershell(target,script,timeout=35)
            method="WMI/DCOM authenticated test"
        elif action in {"remote_inventory", "remote_processes", "remote_services", "remote_network", "remote_storage", "remote_bios", "remote_security"} and not winrm_available and wmi_available:
            # Read-only WMI/DCOM fallback. This uses the current Windows logon token;
            # no password is collected, embedded or persisted by NetworkRadar.
            if action == "remote_inventory":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{$cs=Get-CimInstance -CimSession $s Win32_ComputerSystem; $os=Get-CimInstance -CimSession $s Win32_OperatingSystem; $cpu=Get-CimInstance -CimSession $s Win32_Processor | Select-Object -First 1; [pscustomobject]@{{hostname=$cs.Name;manufacturer=$cs.Manufacturer;model=$cs.Model;os=$os.Caption;version=$os.Version;build=$os.BuildNumber;ram_gb=[math]::Round($cs.TotalPhysicalMemory/1GB,2);cpu=$cpu.Name;cores=$cpu.NumberOfCores}} | ConvertTo-Json -Depth 5 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            elif action == "remote_processes":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{Get-CimInstance -CimSession $s Win32_Process | Select-Object -First 100 Name,ProcessId,WorkingSetSize | ConvertTo-Json -Depth 4 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            elif action == "remote_services":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{Get-CimInstance -CimSession $s Win32_Service | Select-Object -First 200 Name,DisplayName,State,StartMode | ConvertTo-Json -Depth 4 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            elif action == "remote_network":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{Get-CimInstance -CimSession $s Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object Description,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,DHCPEnabled | ConvertTo-Json -Depth 5 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            elif action == "remote_storage":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{$d=Get-CimInstance -CimSession $s Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace; @($d | ForEach-Object {{[pscustomobject]@{{drive=$_.DeviceID;label=$_.VolumeName;filesystem=$_.FileSystem;size_gb=[math]::Round($_.Size/1GB,2);free_gb=[math]::Round($_.FreeSpace/1GB,2);free_percent=if($_.Size){{[math]::Round(100*$_.FreeSpace/$_.Size,1)}}else{{$null}}}}}}) | ConvertTo-Json -Depth 4 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            elif action == "remote_bios":
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{$b=Get-CimInstance -CimSession $s Win32_BIOS; $c=Get-CimInstance -CimSession $s Win32_BaseBoard; [pscustomobject]@{{bios_manufacturer=$b.Manufacturer;bios_version=$b.SMBIOSBIOSVersion;bios_release=$b.ReleaseDate;board_manufacturer=$c.Manufacturer;board_product=$c.Product}} | ConvertTo-Json -Depth 4 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            else:
                # Conservative posture metadata only; no secrets, keys, or user content are collected.
                script=f"$ErrorActionPreference='Stop'; $o=New-CimSessionOption -Protocol Dcom; $s=New-CimSession -ComputerName '{target}' -SessionOption $o -ErrorAction Stop; try {{$os=Get-CimInstance -CimSession $s Win32_OperatingSystem; $fw=Get-CimInstance -CimSession $s -Namespace root/StandardCimv2 -ClassName MSFT_NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction; [pscustomobject]@{{os_caption=$os.Caption;firewall_profiles=@($fw)}} | ConvertTo-Json -Depth 5 -Compress}} finally {{Remove-CimSession $s -ErrorAction SilentlyContinue}}"
            result=_phantom_run_powershell(target,script)
            method="WMI/DCOM"
        else:
            method="WinRM/PowerShell Remoting"
            if not winrm_available:
                if action == "test_winrm":
                    raise ValueError("WinRM TCP 5985/5986 was not reachable. This test checks WinRM only; WMI/DCOM may still work independently. Use TEST WMI/DCOM when RPC endpoint mapper is reachable.")
                raise ValueError("WinRM is not reachable. WMI/DCOM was not available in the latest probe, or this action requires WinRM. Configure the relevant Windows management service through its authorised administrator.")
            if action=="test_winrm":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ [pscustomobject]@{{computer=$env:COMPUTERNAME;user=(whoami);powershell=$PSVersionTable.PSVersion.ToString()}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 4 -Compress"
            elif action=="remote_inventory":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ $cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; $cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; [pscustomobject]@{{hostname=$env:COMPUTERNAME;manufacturer=$cs.Manufacturer;model=$cs.Model;os=$os.Caption;version=$os.Version;build=$os.BuildNumber;ram_gb=[math]::Round($cs.TotalPhysicalMemory/1GB,2);cpu=$cpu.Name;cores=$cpu.NumberOfCores;last_boot=$os.LastBootUpTime}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 5 -Compress"
            elif action=="remote_processes":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ Get-Process | Sort-Object CPU -Descending | Select-Object -First 100 ProcessName,Id,CPU,WorkingSet64 }}{winrm_ssl_flag} -ErrorAction Stop; @($r) | ConvertTo-Json -Depth 4 -Compress"
            elif action=="remote_services":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ Get-Service | Sort-Object Status,DisplayName | Select-Object -First 200 Name,DisplayName,Status,StartType }}{winrm_ssl_flag} -ErrorAction Stop; @($r) | ConvertTo-Json -Depth 4 -Compress"
            elif action=="remote_network":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceDescription,NetProfile,IPv4Address,IPv4DefaultGateway,DNSServer }}{winrm_ssl_flag} -ErrorAction Stop; @($r) | ConvertTo-Json -Depth 5 -Compress"
            elif action=="remote_storage":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,VolumeName,FileSystem,@{{n='size_gb';e={{[math]::Round($_.Size/1GB,2)}}}},@{{n='free_gb';e={{[math]::Round($_.FreeSpace/1GB,2)}}}},@{{n='free_percent';e={{if($_.Size){{[math]::Round(100*$_.FreeSpace/$_.Size,1)}}else{{$null}}}}}} }}{winrm_ssl_flag} -ErrorAction Stop; @($r) | ConvertTo-Json -Depth 5 -Compress"
            elif action=="remote_bios":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ $b=Get-CimInstance Win32_BIOS; $c=Get-CimInstance Win32_BaseBoard; [pscustomobject]@{{bios_manufacturer=$b.Manufacturer;bios_version=$b.SMBIOSBIOSVersion;bios_release=$b.ReleaseDate;board_manufacturer=$c.Manufacturer;board_product=$c.Product}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 4 -Compress"
            elif action=="remote_security":
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ $fw=Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction; $def=Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated; $os=Get-CimInstance Win32_OperatingSystem; [pscustomobject]@{{os_caption=$os.Caption;firewall_profiles=@($fw);defender_status=$def}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 6 -Compress"
            elif action=="restart_service":
                name=str(args.get("service_name",""))
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}",name) or name.lower() in PHANTOM_PROTECTED_SERVICES: raise ValueError("Invalid or protected Windows service name.")
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $n='{name}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ param($serviceName) $svc=Get-Service -Name $serviceName -ErrorAction Stop; Restart-Service -InputObject $svc -ErrorAction Stop; [pscustomobject]@{{service=$serviceName;status=(Get-Service -Name $serviceName).Status.ToString()}} }} -ArgumentList $n{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 4 -Compress"
            elif action=="restart_computer":
                # Run shutdown.exe inside the authenticated remote session. Restart-Computer
                # does not accept Invoke-Command's -UseSSL switch; this works with either
                # the selected WinRM HTTP or HTTPS transport.
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ & (Join-Path $env:SystemRoot 'System32\\shutdown.exe') /r /t 60 /c 'NetworkRadar operator-approved restart'; if ($LASTEXITCODE -ne 0) {{ throw ('shutdown.exe failed with exit code ' + $LASTEXITCODE) }}; [pscustomobject]@{{target=$env:COMPUTERNAME;scheduled='restart';delay_seconds=60}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 4 -Compress"
            else:
                script=f"$ErrorActionPreference='Stop'; $t='{target}'; $r=Invoke-Command -ComputerName $t -Authentication Negotiate -ScriptBlock {{ & (Join-Path $env:SystemRoot 'System32\\shutdown.exe') /s /t 60 /c 'NetworkRadar operator-approved shutdown'; if ($LASTEXITCODE -ne 0) {{ throw ('shutdown.exe failed with exit code ' + $LASTEXITCODE) }}; [pscustomobject]@{{target=$env:COMPUTERNAME;scheduled='shutdown';delay_seconds=60}} }}{winrm_ssl_flag} -ErrorAction Stop; $r | ConvertTo-Json -Depth 4 -Compress"
            result=_phantom_run_powershell(target,script,timeout=60 if action in {"restart_computer","shutdown_computer"} else 45)
    safe=json.dumps(result,default=str)[:5000]
    def _audit(conn): conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),"","local-user","AGENTLESS:"+action,"SUCCESS",json.dumps({"ip":target,"method":method,"result":safe})))
    DB_MANAGER.write(_audit)
    return {"ip":target,"action":action,"method":method,"result":result,"message":f"{action.replace('_',' ').title()} completed or was handed to Windows successfully. Check the returned result for details."}


def phantom_agentless_action(ip, action, args=None, confirm=False):
    """Run an allowlisted native action and audit failures as well as successes."""
    try:
        return _phantom_agentless_action_impl(ip, action, args, confirm)
    except Exception as exc:
        # Never let an audit-write failure hide the original management error.
        try:
            safe_ip=_clean(ip, 64)
            safe_action=_clean(action, 64)
            details=json.dumps({"ip":safe_ip,"error":_clean(exc, 700)})
            DB_MANAGER.write(lambda conn: conn.execute(
                "INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",
                (now_text(),"","local-user","AGENTLESS:"+safe_action,"FAILED",details)))
        except Exception:
            pass
        raise

# ============================================================
# HTTP HANDLER
# ============================================================

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _local_request_allowed(self):
        port = int(self.server.server_address[1])
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urlparse(origin)
            return (parsed.scheme == "http"
                    and (parsed.hostname or "").lower() in {"127.0.0.1", "localhost"}
                    and parsed.port == port
                    and parsed.username is None
                    and parsed.password is None
                    and parsed.path in ("", "/")
                    and not parsed.query
                    and not parsed.fragment)
        except (ValueError, TypeError):
            return False

    def _send_bytes(self, body, status=200, content_type="application/octet-stream",
                    extra_headers=None):
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            port = int(self.server.server_address[1])
            self.send_header("Content-Security-Policy", f"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:{port} ws://localhost:{port}; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                TimeoutError, OSError):
            return False

    def send_json(self, p, status=200):
        b = json.dumps(p, ensure_ascii=False, default=str).encode("utf-8")
        return self._send_bytes(b, status, "application/json; charset=utf-8")

    def do_GET(self):
        if not self._local_request_allowed():
            return self.send_json({"error": "Local access only."}, 403)
        p = urlparse(self.path)
        if p.path == "/api/phantom-access/ssh/terminal":
            return self._handle_ssh_websocket(p)
        if p.path == "/assets/networkradar.css":
            asset = ROOT / "networkradar.css"
            if not asset.is_file(): return self.send_json({"error": "Dashboard stylesheet is missing."}, 404)
            return self._send_bytes(asset.read_bytes(), 200, "text/css; charset=utf-8")
        if p.path == "/assets/dashboard.js":
            asset = ROOT / "dashboard.js"
            if not asset.is_file(): return self.send_json({"error": "Dashboard script is missing."}, 404)
            return self._send_bytes(asset.read_bytes(), 200, "application/javascript; charset=utf-8")
        if self.path == "/" or p.path == "/index.html":
            page = WEB_PAGE.replace("{APP_VERSION}", APP_VERSION)
            external_tag = f'<script src="/assets/dashboard.js?v={APP_VERSION}" defer></script>'
            inline_script = "<!-- Bundled dashboard script; compatibility asset remains at /assets/dashboard.js -->\n<script>\n" + DASHBOARD_JS_BUNDLED.replace("</script", "<\\/script") + "\n</script>"
            # Inline the exact tested dashboard bundle so missing/stale sidecar JS
            # cannot leave the page permanently stuck at CONNECTING/Loading.
            page = page.replace(external_tag, inline_script)
            b = page.encode("utf-8")
            return self._send_bytes(b, 200, "text/html; charset=utf-8")
        try:
            if p.path == "/api/phantom-access/devices":
                return self.send_json(phantom_access_inventory())
            if p.path == "/api/phantom-access/summary":
                return self.send_json(phantom_access_summary())
            with DB_MANAGER.read() as conn:
                if p.path == "/api/command/agents":
                    rows=conn.execute("SELECT agent_id,hostname,platform,os_version,agent_version,CASE WHEN status='REVOKED' THEN status WHEN last_seen<? THEN 'OFFLINE' ELSE status END AS display_status,enrolled_at,last_seen,last_ip,inventory_json,capabilities_json,revoked_at FROM remote_agents ORDER BY last_seen DESC",((datetime.now()-timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),)).fetchall()
                    out=[]
                    for r in rows:
                        try: inv=json.loads(r[9] or "{}")
                        except Exception: inv={}
                        out.append({"agent_id":r[0],"hostname":r[1],"platform":r[2],"os_version":r[3],"agent_version":r[4],"status":r[5],"enrolled_at":r[6],"last_seen":r[7],"last_ip":r[8],"inventory":inv,"capabilities":json.loads(r[10] or "[]"),"revoked_at":r[11]})
                    return self.send_json(out)
                if p.path == "/api/command/summary":
                    total=conn.execute("SELECT COUNT(*) FROM remote_agents WHERE status!='REVOKED'").fetchone()[0]
                    online=conn.execute("SELECT COUNT(*) FROM remote_agents WHERE status!='REVOKED' AND last_seen>=?",((datetime.now()-timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),)).fetchone()[0]
                    pending=conn.execute("SELECT COUNT(*) FROM agent_commands WHERE status='QUEUED'").fetchone()[0]
                    hub=start_agent_hub_status()
                    return self.send_json({"managed":total,"online":online,"queued_commands":pending,"hub":hub})
                if p.path == "/api/command/audit":
                    rows=conn.execute("SELECT timestamp,agent_id,actor,action,outcome,details FROM agent_audit_events ORDER BY id DESC LIMIT 100").fetchall()
                    return self.send_json([{"timestamp":r[0],"agent_id":r[1],"actor":r[2],"action":r[3],"outcome":r[4],"details":r[5]} for r in rows])
                if p.path == "/api/command/results":
                    rows=conn.execute("SELECT c.id,c.agent_id,a.hostname,c.action,c.status,c.created_at,c.completed_at,c.result_json FROM agent_commands c LEFT JOIN remote_agents a ON a.agent_id=c.agent_id ORDER BY c.id DESC LIMIT 40").fetchall()
                    out=[]
                    for r in rows:
                        try: result=json.loads(r[7] or "{}")
                        except Exception: result={"error":"Stored result could not be parsed."}
                        out.append({"command_id":r[0],"agent_id":r[1],"hostname":r[2] or r[1],"action":r[3],"status":r[4],"created_at":r[5],"completed_at":r[6],"result":result})
                    return self.send_json(out)
                if p.path == "/api/status":
                    online, hist, off = conn.execute("""SELECT
                        SUM(CASE WHEN status='ONLINE' THEN 1 ELSE 0 END),
                        COUNT(*), SUM(CASE WHEN status='OFFLINE' THEN 1 ELSE 0 END)
                        FROM devices""").fetchone()
                    dq, ud, dc, nx, _dr, ac = conn.execute("""SELECT
                        (SELECT COUNT(*) FROM dns_events WHERE is_response=0),
                        (SELECT COUNT(*) FROM domain_intel),
                        (SELECT COUNT(DISTINCT client_ip) FROM dns_client_domains),
                        (SELECT COUNT(*) FROM dns_events WHERE response_code='NXDOMAIN'),
                        (SELECT COUNT(*) FROM dns_events WHERE is_response=1),
                        (SELECT COUNT(*) FROM dns_alerts)""").fetchone()
                    scan = conn.execute("SELECT duration FROM scans "
                                        "ORDER BY id DESC LIMIT 1").fetchone()
                    open_inv = conn.execute("SELECT COUNT(*) FROM investigations "
                                            "WHERE status IN ('OPEN','INVESTIGATING')"
                                            ).fetchone()[0]
                    bands = conn.execute("SELECT band FROM device_risk_scores").fetchall()
                    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 0}
                    worst, wr = "LOW", 0
                    for (bn,) in bands:
                        r = rank.get(bn or "UNKNOWN", 0)
                        if r > wr:
                            wr, worst = r, bn
                    with DNS_STATE_LOCK:
                        dns = dict(DNS_STATE)
                    with DHCP_STATE_LOCK:
                        dhcp = dict(DHCP_STATE)
                    with ARP_STATE_LOCK:
                        arp = dict(ARP_STATE)
                    with NET_LOCK:
                        network = NET_CTX.get("network", "")
                    return self.send_json({
                        "network": network, "timestamp": now_text(),
                        "online": online or 0, "historical": hist or 0,
                        "offline": off or 0, "dns_queries": dq or 0,
                        "unique_domains": ud or 0, "dns_clients": dc or 0,
                        "nxdomain": nx or 0, "alert_count": ac or 0,
                        "dns_status": dns["status"],
                        "interface": dns["interface"],
                        "dhcp_status": dhcp["status"],
                        "dhcp_error": dhcp.get("error", ""),
                        "dhcp_last_error": dhcp.get("last_error", ""),
                        "dhcp_restart_count": dhcp.get("restart_count", 0),
                        "arp_status": arp["status"],
                        "last_scan_duration": scan[0] if scan else 0,
                        "open_investigations": open_inv,
                        "network_risk_band": worst,
                        "db_health": DB_MANAGER.health()})

                if p.path == "/api/diagnostics":
                    with DNS_STATE_LOCK:
                        dns_diag = dict(DNS_STATE)
                    with DHCP_STATE_LOCK:
                        dhcp_diag = dict(DHCP_STATE)
                    with ARP_STATE_LOCK:
                        arp_diag = dict(ARP_STATE)
                    return self.send_json({
                        "behaviour": behaviour_diagnostics(conn),
                        "scan_quality": scan_quality_report(conn),
                        "engines": {
                            "dns": dns_diag,
                            "dhcp": dhcp_diag,
                            "arp": arp_diag,
                            "database": DB_MANAGER.health(),
                        },
                    })

                if p.path == "/api/engine_diagnostics":
                    with DNS_STATE_LOCK:
                        dns_s = dict(DNS_STATE)
                    with DHCP_STATE_LOCK:
                        dhcp_s = dict(DHCP_STATE)
                    with ARP_STATE_LOCK:
                        arp_s = dict(ARP_STATE)
                    dhcp_class = (DHCP_ENGINE.diagnostic_classification()
                                  if 'DHCP_ENGINE' in globals() and DHCP_ENGINE
                                  else {"state": "UNKNOWN", "reason": "engine not started"})
                    engines = {
                        "ipv6_inventory": {"state": "AVAILABLE" if sys.platform == "win32" else "UNSUPPORTED",
                                           "reason": "Windows neighbour-cache reader; sampled during discovery."},
                        "exposure_intelligence": {"state": "ONLINE",
                                                   "reason": "Observed-service assessment only; no exploitation."},
                        "unknown_device_hunter": {"state": "ONLINE",
                                                   "reason": "Evidence-based inventory query."},
                        "dns": {"state": dns_s.get("status", "UNKNOWN"),
                                "reason": dns_s.get("error", ""),
                                "interface": dns_s.get("interface", "")},
                        "dhcp": {**dhcp_class, "raw_status": dhcp_s.get("status", "UNKNOWN")},
                        "arp": {"state": arp_s.get("status", "UNKNOWN"),
                                "reason": arp_s.get("error", ""),
                                "interface": arp_s.get("interface", "")},
                        "database": {"state": "ONLINE" if DB_MANAGER.health().get("running") else "FAILED",
                                     "detail": DB_MANAGER.health()},
                    }
                    engines["remote_agent_hub"] = start_agent_hub_status()
                    with NET_LOCK:
                        ctx = dict(NET_CTX)
                    engines["network_context"] = {
                        "state": ctx.get("auth_decision", "UNKNOWN"),
                        "reason": "; ".join(ctx.get("auth_reasons") or []),
                        "confidence": ctx.get("confidence", 0),
                    }
                    return self.send_json({"engines": engines, "timestamp": now_text()})

                if p.path == "/api/presence":
                    q = parse_qs(p.query)
                    device_id = q.get("device_id", [""])[0]
                    if not device_id:
                        return self.send_json({"error": "device_id required"}, 400)
                    rows = conn.execute("""
                        SELECT timestamp, state, prior_state, confidence, evidence_json
                        FROM device_presence_events WHERE device_id=?
                        ORDER BY id DESC LIMIT 100""", (device_id,)).fetchall()
                    return self.send_json([{
                        "timestamp": r[0], "state": r[1], "prior_state": r[2],
                        "confidence": r[3], "evidence": json.loads(r[4] or "{}")
                    } for r in rows])

                if p.path == "/api/identity/candidates":
                    status_filter = (parse_qs(p.query).get("status", ["PENDING"])[0]
                                     or "PENDING").upper()
                    rows = conn.execute("""
                        SELECT id, device_a, device_b, outcome, score,
                               explain_json, status, created_at, reviewed_at, reviewer
                        FROM identity_candidates WHERE status=?
                        ORDER BY score DESC LIMIT 200""", (status_filter,)).fetchall()
                    return self.send_json([{
                        "id": r[0], "device_a": r[1], "device_b": r[2],
                        "outcome": r[3], "score": r[4],
                        "explain": json.loads(r[5] or "{}"),
                        "status": r[6], "created_at": r[7],
                        "reviewed_at": r[8], "reviewer": r[9]
                    } for r in rows])

                if p.path == "/api/unknown-hunter":
                    return self.send_json(unknown_device_hunter(conn))

                if p.path == "/api/ipv6":
                    rows = conn.execute("""SELECT e.ipv6,e.mac,e.interface_index,e.interface_alias,e.state,e.timestamp,e.linked_device_id
                        FROM ipv6_observation_events e ORDER BY e.id DESC LIMIT 500""").fetchall()
                    return self.send_json([{"ipv6":r[0],"mac":r[1],"interface_index":r[2],
                        "interface_alias":r[3],"state":r[4],"timestamp":r[5],"linked_device_id":r[6]} for r in rows])

                if p.path == "/api/exposure":
                    rows = conn.execute("""SELECT ip,title,severity,confidence,observed_ports,
                        evidence,recommendation,first_seen,last_seen,status FROM exposure_findings
                        WHERE status IN ('OPEN','STALE') ORDER BY CASE severity WHEN 'HIGH' THEN 0
                        WHEN 'MEDIUM' THEN 1 ELSE 2 END,last_seen DESC LIMIT 300""").fetchall()
                    return self.send_json([{"ip":r[0],"title":r[1],"severity":r[2],
                        "confidence":r[3],"observed_ports":r[4],"evidence":r[5],
                        "recommendation":r[6],"first_seen":r[7],"last_seen":r[8],"status":r[9]}
                        for r in rows])

                if p.path == "/api/assistant":
                    question = parse_qs(p.query).get("q", [""])[0]
                    return self.send_json(intelligence_answer(conn, question))

                if p.path == "/api/network":
                    with NET_LOCK:
                        return self.send_json(dict(NET_CTX))

                if p.path == "/api/engines":
                    with DNS_STATE_LOCK:
                        dns_state = dict(DNS_STATE)
                    with DHCP_STATE_LOCK:
                        dhcp_state = dict(DHCP_STATE)
                    with ARP_STATE_LOCK:
                        arp_state = dict(ARP_STATE)
                    db_health = dict(DB_MANAGER.health_data)
                    engines = [
                        engine_record("database", "RUNNING" if db_health.get("running") else "STOPPED",
                                      last_error=db_health.get("last_error", ""), details=db_health),
                        engine_record("dns", dns_state.get("status", "UNKNOWN"),
                                      last_error=dns_state.get("error", ""), details=dns_state),
                        engine_record("dhcp", dhcp_state.get("status", "UNKNOWN"),
                                      last_error=dhcp_state.get("last_error") or dhcp_state.get("error", ""),
                                      details=dhcp_state),
                        engine_record("arp", arp_state.get("status", "UNKNOWN"),
                                      last_error=arp_state.get("error", ""), details=arp_state),
                    ]
                    return self.send_json({"engines": engines, "sampled_at": now_text()})

                if p.path == "/api/health":
                    with HEALTH_LOCK:
                        return self.send_json(dict(HEALTH))

                if p.path == "/api/progress":
                    with JOB_LOCK:
                        return self.send_json(dict(JOB_STATE))

                if p.path == "/api/threats":
                    rows = conn.execute("""SELECT timestamp, domain, client_ip,
                        (SELECT severity FROM threat_indicators WHERE
                        id=threat_matches.indicator_id), details
                        FROM threat_matches ORDER BY id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "domain": r[1],
                        "client_ip": r[2], "severity": r[3] or "MEDIUM",
                        "details": r[4]} for r in rows])

                if p.path == "/api/dhcp":
                    rows = conn.execute("""SELECT timestamp, msg_type, client_mac,
                        client_ip, server_ip, hostname, is_rogue FROM dhcp_events
                        ORDER BY id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "msg_type": r[1],
                        "client_mac": r[2], "client_ip": r[3], "server_ip": r[4],
                        "hostname": r[5], "is_rogue": r[6]} for r in rows])

                if p.path == "/api/arp":
                    rows = conn.execute("""SELECT timestamp, opcode, sender_ip,
                        sender_mac, is_gratuitous, change_type FROM arp_observations
                        ORDER BY id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "opcode": r[1],
                        "sender_ip": r[2], "sender_mac": r[3],
                        "is_gratuitous": r[4], "change_type": r[5]} for r in rows])

                if p.path == "/api/devices":
                    rows = conn.execute("""SELECT ip, manufacturer, hostname, mac,
                        status, last_seen, device_name, device_type,
                        identification_confidence, os_guess, model, open_ports,
                        manual_name, trust_state, identity_basis, device_id,
                        friendly_name, service_summary, risk_score, risk_band
                        FROM devices ORDER BY CASE status WHEN 'ONLINE' THEN 0
                        ELSE 1 END, ip""").fetchall()
                    return self.send_json([{"ip": r[0], "manufacturer": r[1],
                        "hostname": r[2], "mac": r[3], "status": r[4],
                        "last_seen": r[5], "device_name": r[6] or "Unidentified",
                        "device_type": r[7] or "Unclassified",
                        "identification_confidence": r[8] or 0,
                        "os_guess": r[9] or "Unknown", "model": r[10] or "",
                        "open_ports": r[11] or "", "manual_name": r[12] or "",
                        "trust_state": r[13] or "UNREVIEWED",
                        "identity_basis": r[14] or "", "device_id": r[15] or "",
                        "friendly_name": r[16] or "",
                        "service_summary": r[17] or "",
                        "risk_score": r[18] or 0,
                        "risk_band": r[19] or "UNKNOWN"} for r in rows])

                if p.path == "/api/identity/continuity/summary":
                    tracked = conn.execute("SELECT COUNT(*) FROM identity_continuity_registry").fetchone()[0]
                    stable = conn.execute("SELECT COUNT(*) FROM identity_continuity_registry WHERE anchor_type='GLOBAL_MAC'").fetchone()[0]
                    ip_scoped = conn.execute("SELECT COUNT(*) FROM identity_continuity_registry WHERE anchor_type='IP_MAC_SCOPED_OBSERVATION'").fetchone()[0]
                    randomised = conn.execute("SELECT COUNT(DISTINCT continuity_id) FROM identity_continuity_observations WHERE mac_class='RANDOMISED_OR_LOCAL'").fetchone()[0]
                    events = conn.execute("SELECT COUNT(*) FROM identity_continuity_events").fetchone()[0]
                    integrations = conn.execute("SELECT integration_id,integration_type,display_name,status,endpoint,last_seen,notes FROM identity_integration_registry ORDER BY integration_id").fetchall()
                    return self.send_json({"tracked": tracked, "stable_anchors": stable,
                        "ip_scoped": ip_scoped, "randomised_observations": randomised,
                        "events": events,
                        "integrations": [{"id": r[0], "type": r[1], "name": r[2],
                                          "status": r[3], "endpoint": r[4],
                                          "last_seen": r[5], "notes": r[6]}
                                         for r in integrations]})

                if p.path == "/api/identity/continuity/devices":
                    rows = conn.execute("""SELECT r.continuity_id,r.anchor_type,r.current_ip,r.current_mac,r.hostname,r.vendor_class,r.device_type,r.confidence,r.first_seen,r.last_seen,
                        (SELECT COUNT(*) FROM identity_continuity_observations o WHERE o.continuity_id=r.continuity_id)
                        FROM identity_continuity_registry r ORDER BY r.last_seen DESC LIMIT 500""").fetchall()
                    return self.send_json([{"id": r[0], "anchor_type": r[1],
                        "ip": r[2], "mac": r[3], "hostname": r[4],
                        "vendor_class": r[5], "device_type": r[6],
                        "confidence": r[7], "first_seen": r[8],
                        "last_seen": r[9], "observations": r[10]}
                        for r in rows])

                if p.path == "/api/identity/continuity/events":
                    rows = conn.execute("SELECT timestamp,event_type,severity,ip,old_value,new_value,confidence,details FROM identity_continuity_events ORDER BY id DESC LIMIT 150").fetchall()
                    return self.send_json([{"timestamp": r[0], "event": r[1],
                        "severity": r[2], "ip": r[3], "old": r[4],
                        "new": r[5], "confidence": r[6], "details": r[7]}
                        for r in rows])

                if p.path == "/api/identity/summary":
                    counts = conn.execute("""SELECT COUNT(DISTINCT ip),COUNT(*),
                        SUM(CASE WHEN attribute='Device category' THEN 1 ELSE 0 END)
                        FROM device_identity_evidence""").fetchone()
                    latest = conn.execute("SELECT timestamp,devices_processed,evidence_added,identified,unknown FROM identity_engine_runs ORDER BY id DESC LIMIT 1").fetchone()
                    return self.send_json({"devices_with_evidence": counts[0] or 0,
                        "evidence_records": counts[1] or 0,
                        "category_evidence": counts[2] or 0,
                        "last_run": ({"timestamp": latest[0], "devices": latest[1],
                                      "evidence": latest[2], "identified": latest[3],
                                      "unknown": latest[4]} if latest else None),
                        "oui_entries": len(load_oui_cache())})

                if p.path == "/api/identity/unknown":
                    rows = conn.execute("""SELECT d.ip,d.mac,d.hostname,d.manufacturer,d.device_type,d.os_guess,d.last_seen,
                        COUNT(e.id) AS evidence_count,MAX(e.confidence) AS max_conf
                        FROM devices d LEFT JOIN device_identity_evidence e ON e.ip=d.ip
                        WHERE d.status='ONLINE' AND (d.device_type LIKE '%Unclass%'
                            OR d.device_type='Unidentified network device'
                            OR COALESCE(d.identification_confidence,0)<35)
                        GROUP BY d.ip ORDER BY evidence_count ASC,d.last_seen DESC LIMIT 200""").fetchall()
                    return self.send_json([{"ip": r[0], "mac": r[1], "hostname": r[2],
                        "manufacturer": r[3], "device_type": r[4],
                        "os_guess": r[5], "last_seen": r[6],
                        "evidence_count": r[7], "max_confidence": r[8] or 0}
                        for r in rows])

                if p.path == "/api/device":
                    params = parse_qs(p.query)
                    ip = params.get("ip", [""])[0]
                    d = conn.execute("""SELECT ip, mac, manufacturer, hostname,
                        first_seen, last_seen, status, device_name, friendly_name,
                        device_type, os_guess, model, identification_confidence,
                        identification_methods, open_ports, service_summary,
                        last_identified, device_id, identity_basis, manual_name,
                        trust_state, notes, risk_score, risk_band FROM devices
                        WHERE ip=?""", (ip,)).fetchone()
                    if not d:
                        return self.send_json({"device": None, "dns_events": [],
                            "alerts": [], "events": [], "observations": [],
                            "ip_history": [], "behaviour": []})
                    did = d[17]
                    extra = conn.execute("SELECT oui_manufacturer,reported_manufacturer,identity_conflicts,identity_category_confidence,identity_last_assessed,recognition_json FROM devices WHERE ip=?", (ip,)).fetchone()
                    identity_rows = conn.execute("""SELECT last_seen,source,attribute,observed_value,confidence,evidence_class
                        FROM device_identity_evidence WHERE ip=? ORDER BY confidence DESC,last_seen DESC LIMIT 200""", (ip,)).fetchall()
                    # RADAR IDENTITY 11.1.0: collect related records from the existing
                    # append-only intelligence tables. Each query is isolated so an
                    # optional subsystem/table issue cannot break the core device view.
                    def _rows_or_empty(sql, args=()):
                        try:
                            return conn.execute(sql, args).fetchall()
                        except sqlite3.Error:
                            return []
                    assessments = _rows_or_empty("""SELECT attribute,assessed_value,confidence,status,
                        supporting_sources,conflicting_values,evidence_count,independent_sources,
                        rationale,last_seen FROM identity_assessments WHERE ip=?
                        ORDER BY confidence DESC,last_seen DESC LIMIT 80""", (ip,))
                    identity_history = _rows_or_empty("""SELECT timestamp,attribute,old_value,new_value,reason
                        FROM device_identity_history WHERE ip=? ORDER BY timestamp DESC LIMIT 100""", (ip,))
                    dhcp_rows = _rows_or_empty("""SELECT timestamp,msg_type,hostname,vendor_class,
                        client_mac,client_ip,server_ip,details FROM dhcp_events
                        WHERE client_ip=? OR client_mac=? ORDER BY timestamp DESC LIMIT 60""",
                        (ip, d[1] or ""))
                    dns_rows = _rows_or_empty("""SELECT timestamp,domain,query_type,response_code,answers
                        FROM dns_events WHERE client_ip=? ORDER BY timestamp DESC LIMIT 100""", (ip,))
                    observation_rows = _rows_or_empty("""SELECT timestamp,method,observation,confidence
                        FROM device_observations WHERE ip=? ORDER BY timestamp DESC LIMIT 100""", (ip,))
                    behaviour_rows = _rows_or_empty("""SELECT timestamp,metric,observed,baseline,severity,details,status
                        FROM behavior_alerts WHERE ip=? ORDER BY timestamp DESC LIMIT 80""", (ip,))
                    exposure_rows = _rows_or_empty("""SELECT first_seen,last_seen,rule_id,title,severity,
                        confidence,observed_ports,evidence,recommendation,status FROM exposure_findings
                        WHERE ip=? ORDER BY last_seen DESC LIMIT 80""", (ip,))
                    alert_rows = _rows_or_empty("""SELECT timestamp,source,rule_id,severity,title,details,status
                        FROM alerts WHERE ip=? ORDER BY timestamp DESC LIMIT 80""", (ip,))
                    investigation_rows = _rows_or_empty("""SELECT id,timestamp,title,severity,confidence,status,
                        description,closure_reason FROM investigations WHERE affected_ip=? OR affected_device_id=?
                        ORDER BY updated_at DESC LIMIT 60""", (ip, did or ""))
                    port_scan_rows = _rows_or_empty("""SELECT timestamp,completed,open_ports,scan_method,detail
                        FROM port_scan_observations WHERE ip=? ORDER BY timestamp DESC LIMIT 60""", (ip,))
                    relationship_rows = _rows_or_empty("""SELECT timestamp,source_ip,target_ip,relationship_type,
                        evidence,confidence,last_seen FROM device_relationships
                        WHERE source_ip=? OR target_ip=? ORDER BY last_seen DESC LIMIT 100""", (ip, ip))
                    topology_rows = _rows_or_empty("""SELECT timestamp,source,target,kind,evidence,confidence,last_seen
                        FROM topology_relationships WHERE source=? OR target=? ORDER BY last_seen DESC LIMIT 100""",
                        (ip, ip))
                    iph = conn.execute("""SELECT ip, first_seen, last_seen, mac
                        FROM device_ip_history WHERE device_id=?
                        ORDER BY last_seen DESC""", (did,)).fetchall() if did else []
                    risk_expl = ""
                    tr = ir = hr = 0
                    if did:
                        rr = conn.execute("""SELECT explanation, threat_risk,
                            identification_uncertainty, operational_health
                            FROM device_risk_scores WHERE device_id=?""", (did,)).fetchone()
                        if rr:
                            risk_expl = rr[0] or ""
                            tr, ir, hr = rr[1] or 0, rr[2] or 0, rr[3] or 0
                    return self.send_json({
                        "device": {"ip": d[0], "mac": d[1], "manufacturer": d[2],
                            "hostname": d[3], "first_seen": d[4], "last_seen": d[5],
                            "status": d[6], "device_name": d[7],
                            "friendly_name": d[8], "device_type": d[9],
                            "os_guess": d[10], "model": d[11],
                            "identification_confidence": d[12],
                            "identification_methods": d[13], "open_ports": d[14],
                            "service_summary": d[15], "last_identified": d[16],
                            "device_id": d[17] or "", "identity_basis": d[18] or "",
                            "manual_name": d[19] or "",
                            "trust_state": d[20] or "UNREVIEWED",
                            "notes": d[21] or "", "risk_score": d[22] or 0,
                            "risk_band": d[23] or "UNKNOWN",
                            "oui_manufacturer": extra[0] if extra else "",
                            "reported_manufacturer": extra[1] if extra else "",
                            "identity_conflicts": json.loads(extra[2] or "[]") if extra else [],
                            "identity_category_confidence": extra[3] if extra else 0,
                            "identity_last_assessed": extra[4] if extra else "",
                            "recognition": (json.loads(extra[5] or "{}") if extra and extra[5] else {}),
                            "risk_explanation": risk_expl,
                            "threat_risk": tr, "identification_uncertainty": ir,
                            "operational_health": hr},
                        "ip_history": [{"ip": r[0], "first_seen": r[1],
                            "last_seen": r[2], "mac": r[3]} for r in iph],
                        "identity_evidence": [{"timestamp": r[0], "source": r[1],
                            "attribute": r[2], "value": r[3], "confidence": r[4],
                            "class": r[5]} for r in identity_rows],
                        "identity_assessments": [{"attribute":r[0],"value":r[1],"confidence":r[2],
                            "status":r[3],"sources":json.loads(r[4] or "[]"),
                            "conflicts":json.loads(r[5] or "[]"),"evidence_count":r[6],
                            "independent_sources":r[7],"rationale":r[8],"last_seen":r[9]} for r in assessments],
                        "identity_history": [{"timestamp":r[0],"attribute":r[1],"old":r[2],"new":r[3],"reason":r[4]} for r in identity_history],
                        "dhcp_history": [{"timestamp":r[0],"message":r[1],"hostname":r[2],"vendor_class":r[3],"mac":r[4],"client_ip":r[5],"server_ip":r[6],"details":r[7]} for r in dhcp_rows],
                        "dns_activity": [{"timestamp":r[0],"domain":r[1],"type":r[2],"rcode":r[3],"answers":r[4]} for r in dns_rows],
                        "observations": [{"timestamp":r[0],"method":r[1],"observation":r[2],"confidence":r[3]} for r in observation_rows],
                        "behaviour_alerts": [{"timestamp":r[0],"metric":r[1],"observed":r[2],"baseline":r[3],"severity":r[4],"details":r[5],"status":r[6]} for r in behaviour_rows],
                        "exposure_findings": [{"first_seen":r[0],"last_seen":r[1],"rule":r[2],"title":r[3],"severity":r[4],"confidence":r[5],"ports":r[6],"evidence":r[7],"recommendation":r[8],"status":r[9]} for r in exposure_rows],
                        "alerts": [{"timestamp":r[0],"source":r[1],"rule":r[2],"severity":r[3],"title":r[4],"details":r[5],"status":r[6]} for r in alert_rows],
                        "investigations": [{"id":r[0],"timestamp":r[1],"title":r[2],"severity":r[3],"confidence":r[4],"status":r[5],"description":r[6],"closure_reason":r[7]} for r in investigation_rows],
                        "port_scan_history": [{"timestamp":r[0],"completed":r[1],"ports":r[2],"method":r[3],"detail":r[4]} for r in port_scan_rows],
                        "relationships": [{"timestamp":r[0],"source_ip":r[1],"target_ip":r[2],"type":r[3],"evidence":r[4],"confidence":r[5],"last_seen":r[6]} for r in relationship_rows],
                        "topology": [{"timestamp":r[0],"source":r[1],"target":r[2],"kind":r[3],"evidence":r[4],"confidence":r[5],"last_seen":r[6]} for r in topology_rows]})

                if p.path == "/api/behaviour":
                    rows = conn.execute("""SELECT b.timestamp, b.ip, b.metric,
                        b.observed, b.baseline, b.severity, b.details, b.status,
                        COALESCE(NULLIF(d.manual_name,''),NULLIF(d.device_name,''),d.hostname)
                        FROM behavior_alerts b LEFT JOIN devices d ON d.ip=b.ip
                        ORDER BY b.id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "ip": r[1],
                        "metric": r[2], "observed": r[3], "baseline": r[4],
                        "severity": r[5], "details": r[6], "status": r[7],
                        "device_name": r[8] or r[1]} for r in rows])

                if p.path == "/api/investigations":
                    rows = conn.execute("""SELECT i.id, i.timestamp, i.title,
                        i.description, i.severity, i.status, i.affected_ip,
                        (SELECT COUNT(*) FROM evidence e WHERE
                        e.investigation_id=i.id) FROM investigations i
                        ORDER BY i.id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"id": r[0], "timestamp": r[1],
                        "title": r[2], "description": r[3] or "",
                        "severity": r[4], "status": r[5], "affected_ip": r[6],
                        "evidence_count": r[7]} for r in rows])

                if p.path == "/api/topology":
                    return self.send_json(topology_payload())

                if p.path == "/api/dns":
                    rows = conn.execute("""SELECT timestamp, client_ip, domain,
                        query_type, response_code FROM dns_events
                        WHERE is_response=0 ORDER BY id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "client_ip": r[1],
                        "domain": r[2], "query_type": r[3],
                        "response_code": r[4]} for r in rows])

                if p.path == "/api/domains":
                    rows = conn.execute("""SELECT domain, query_count, risk_level
                        FROM domain_intel
                        WHERE lower(domain) NOT LIKE '%.in-addr.arpa'
                          AND lower(domain) NOT LIKE '%.ip6.arpa'
                          AND lower(domain) NOT LIKE '%.local'
                          AND lower(domain) NOT LIKE '_%._tcp.local'
                          AND lower(domain) NOT LIKE '_%._udp.local'
                        ORDER BY query_count DESC LIMIT 100""").fetchall()
                    return self.send_json([{"domain": r[0], "query_count": r[1],
                        "risk_level": r[2]} for r in rows])

                if p.path == "/api/alerts":
                    rows = conn.execute("""SELECT timestamp, client_ip, domain,
                        rule_id, severity, score, details FROM dns_alerts
                        ORDER BY id DESC LIMIT 50""").fetchall()
                    return self.send_json([{"timestamp": r[0], "client_ip": r[1],
                        "domain": r[2], "rule_id": r[3], "severity": r[4],
                        "score": r[5], "details": r[6]} for r in rows])

                if p.path == "/api/alerts_stream":
                    rows = conn.execute("""SELECT id, timestamp, ip, device_id,
                        source, rule_id, severity, title, status, investigation_id,
                        first_seen,last_seen,occurrence_count FROM alerts
                        ORDER BY id DESC LIMIT 200""").fetchall()
                    return self.send_json([{"id": r[0], "timestamp": r[1],
                        "ip": r[2], "device_id": r[3], "source": r[4],
                        "rule_id": r[5], "severity": r[6], "title": r[7],
                        "status": r[8], "investigation_id": r[9],
                        "first_seen": r[10], "last_seen": r[11],
                        "occurrence_count": r[12]} for r in rows])

                if p.path == "/api/events":
                    rows = conn.execute("""SELECT timestamp, ip, event_type,
                        details, category, severity FROM network_events
                        ORDER BY id DESC LIMIT 100""").fetchall()
                    return self.send_json([{"timestamp": r[0], "ip": r[1],
                        "event_type": r[2], "details": r[3], "category": r[4],
                        "severity": r[5]} for r in rows])

                if p.path == "/api/changes":
                    rows = conn.execute("""SELECT id, timestamp, change_type,
                        category, severity, ip, device_id, details
                        FROM network_changes ORDER BY id DESC LIMIT 200""").fetchall()
                    return self.send_json([{"id": r[0], "timestamp": r[1],
                        "change_type": r[2], "category": r[3], "severity": r[4],
                        "ip": r[5], "device_id": r[6], "details": r[7]}
                        for r in rows])

                if p.path == "/api/config_findings":
                    rows = conn.execute("""SELECT id, timestamp, title, description,
                        severity, confidence, evidence, recommendation, first_seen,
                        last_seen, status FROM config_findings
                        ORDER BY CASE severity WHEN 'CRITICAL' THEN 0
                            WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW'
                            THEN 3 ELSE 4 END, last_seen DESC LIMIT 200""").fetchall()
                    return self.send_json([{"id": r[0], "timestamp": r[1],
                        "title": r[2], "description": r[3], "severity": r[4],
                        "confidence": r[5], "evidence": r[6],
                        "recommendation": r[7], "first_seen": r[8],
                        "last_seen": r[9], "status": r[10]} for r in rows])

                if p.path == "/api/profiles":
                    rows = conn.execute("""SELECT network, fingerprint, first_seen,
                        last_seen, interface, gateway, gateway_mac, ssid, approved,
                        profile_name, dns_servers, adapter_mac, confidence
                        FROM network_profiles ORDER BY last_seen DESC LIMIT 100""").fetchall()
                    with NET_LOCK:
                        cur_fp = NET_CTX.get("fingerprint", "")
                    return self.send_json([{"network": r[0], "fingerprint": r[1],
                        "first_seen": r[2], "last_seen": r[3], "interface": r[4],
                        "gateway": r[5], "gateway_mac": r[6], "ssid": r[7],
                        "approved": bool(r[8]), "profile_name": r[9],
                        "dns_servers": r[10], "adapter_mac": r[11],
                        "confidence": r[12] or 0,
                        "is_current": r[1] == cur_fp} for r in rows])

                if p.path == "/api/hunt/templates":
                    return self.send_json([{"key": k, "title": v["title"]}
                        for k, v in HUNT_TEMPLATES.items()])

                if p.path == "/api/hunt/run":
                    params = parse_qs(p.query)
                    key = params.get("template", [""])[0]
                    if not key:
                        return self.send_json({"error": "template required"}, 400)
                    return self.send_json(run_hunt(key))

                if p.path == "/api/saved_queries":
                    rows = conn.execute("""SELECT id, name, query_json, created_at,
                        last_run_at FROM saved_queries ORDER BY id DESC""").fetchall()
                    return self.send_json([{"id": r[0], "name": r[1],
                        "query_json": r[2], "created_at": r[3],
                        "last_run_at": r[4]} for r in rows])

        except Exception as e:
            return self.send_json({"error": _clean(e, 200)}, 500)

        if p.path == "/api/report":
            params = parse_qs(p.query)
            rt = params.get("type", ["daily"])[0]
            rf = params.get("format", ["json"])[0]
            if rf not in ("json", "csv", "html"):
                return self.send_json({"error": "unsupported format"}, 400)
            if rt not in ("daily", "devices", "investigations", "changes",
                          "threats", "health", "config"):
                return self.send_json({"error": "unsupported type"}, 400)
            try:
                body, mime, fname = generate_report(rt, rf)
                return self._send_bytes(
                    body, 200, mime,
                    {"Content-Disposition": f'attachment; filename="{fname}"'})
            except Exception as e:
                return self.send_json({"error": _clean(e, 200)}, 500)

        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if not self._local_request_allowed():
            return self.send_json({"error": "Local access only."}, 403)
        try:
            if self.path in ("/api/phantom-access/ssh/hostkey", "/api/phantom-access/ssh/trust", "/api/phantom-access/ssh/connect", "/api/phantom-access/ssh/close"):
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 16384:
                    return self.send_json({"error": "Invalid SSH request body."}, 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(payload, dict):
                    return self.send_json({"error": "JSON object required."}, 400)
                try:
                    if self.path.endswith("/hostkey"):
                        return self.send_json(phantom_ssh_hostkey_preview(payload.get("ip", ""), payload.get("port", 22)))
                    if self.path.endswith("/trust"):
                        return self.send_json(phantom_ssh_trust_hostkey(payload.get("ip", ""), payload.get("port", 22), payload.get("fingerprint", ""), payload.get("confirm") is True))
                    if self.path.endswith("/connect"):
                        return self.send_json(phantom_ssh_connect(payload.get("ip", ""), payload.get("username", ""), payload.get("port", 22), payload.get("auth_type", "agent"), payload.get("password"), payload.get("key_path"), payload.get("passphrase")))
                    return self.send_json(phantom_ssh_close(payload.get("session_token", "")))
                except ValueError as exc:
                    return self.send_json({"error": _clean(exc, 500)}, 400)
                except PermissionError as exc:
                    return self.send_json({"error": _clean(exc, 500)}, 403)
                except Exception as exc:
                    auth_error = getattr(paramiko, "AuthenticationException", ()) if paramiko else ()
                    if auth_error and isinstance(exc, auth_error):
                        return self.send_json({"error": "SSH authentication failed. Check the account, key or password."}, 401)
                    return self.send_json({"error": _clean(exc, 500)}, 502)
            if self.path in ("/api/phantom-access/probe", "/api/phantom-access/action", "/api/phantom-access/bulk"):
                length=int(self.headers.get("Content-Length","0"))
                if length<=0 or length>8192: return self.send_json({"error":"Invalid request body."},400)
                payload=json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(payload,dict): return self.send_json({"error":"JSON object required."},400)
                if self.path.endswith("/probe"):
                    if payload.get("confirm") is not True: return self.send_json({"error":"Explicit confirmation required."},400)
                    return self.send_json(phantom_probe_device(payload.get("ip","")))
                if self.path.endswith("/bulk"):
                    return self.send_json(phantom_access_bulk(payload.get("ips"), str(payload.get("action", "probe"))))
                result=phantom_agentless_action(payload.get("ip",""),str(payload.get("action","")),payload.get("args",{}),payload.get("confirm") is True)
                return self.send_json(result,200)
            if self.path == "/api/command/enrol-token":
                length=int(self.headers.get("Content-Length","0")); payload=json.loads(self.rfile.read(length).decode("utf-8")) if 0<length<=1024 else {}
                if payload.get("confirm") is not True: return self.send_json({"error":"Explicit confirmation required."},400)
                return self.send_json(create_agent_enrollment_token(_clean(payload.get("actor","local-user"),80)),201)
            if self.path.startswith("/api/command/agents/") and self.path.endswith("/revoke"):
                parts=self.path.strip("/").split("/"); agent_id=parts[3]
                length=int(self.headers.get("Content-Length","0")); payload=json.loads(self.rfile.read(length).decode("utf-8")) if 0<length<=1024 else {}
                if payload.get("confirm") is not True: return self.send_json({"error":"Explicit confirmation required."},400)
                def _revoke(conn):
                    cur=conn.execute("UPDATE remote_agents SET status='REVOKED',revoked_at=? WHERE agent_id=? AND status!='REVOKED'",(now_text(),agent_id))
                    conn.execute("UPDATE agent_commands SET status='CANCELLED' WHERE agent_id=? AND status='QUEUED'",(agent_id,))
                    conn.execute("INSERT INTO agent_audit_events(timestamp,agent_id,actor,action,outcome,details) VALUES(?,?,?,?,?,?)",(now_text(),agent_id,"local-user","REVOKE_AGENT","SUCCESS" if cur.rowcount else "NOOP","Agent credentials revoked."))
                    return cur.rowcount
                if not DB_MANAGER.write(_revoke): return self.send_json({"error":"Agent not found."},404)
                return self.send_json({"revoked":True})
            if self.path.startswith("/api/command/agents/") and self.path.endswith("/commands"):
                parts=self.path.strip("/").split("/"); agent_id=parts[3]
                length=int(self.headers.get("Content-Length","0"))
                if length<=0 or length>4096: return self.send_json({"error":"Invalid request."},400)
                payload=json.loads(self.rfile.read(length).decode("utf-8"))
                try:
                    result=queue_agent_command(agent_id,payload.get("action"),payload.get("args",{}),_clean(payload.get("actor","local-user"),80),payload.get("confirm") is True)
                    return self.send_json(result,202)
                except ValueError as exc: return self.send_json({"error":str(exc)},400)
            if self.path == "/api/unknown-hunter/investigate":
                length=int(self.headers.get("Content-Length","0"))
                payload=json.loads(self.rfile.read(length).decode("utf-8")) if 0<length<=4096 else {}
                if payload.get("confirm") is not True:
                    return self.send_json({"error":"Explicit confirmation required."},400)
                return self.send_json(investigate_unknown_devices(int(payload.get("limit",50))))

            if self.path == "/api/identity/continuity/run":
                length = int(self.headers.get("Content-Length", "0"))
                payload = (json.loads(self.rfile.read(length).decode("utf-8"))
                           if 0 < length <= 4096 else {})
                if payload.get("confirm") is not True:
                    return self.send_json({"error": "Explicit confirmation required."}, 400)
                return self.send_json({"ok": True, "result": run_identity_continuity()})

            if self.path == "/api/identity/candidates/review":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    return self.send_json({"error": "Invalid."}, 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                cand_id = int(payload.get("id", 0))
                action = str(payload.get("action", "")).upper()
                reviewer = _clean(payload.get("reviewer", "local-user"), 80)
                if action not in ("ACCEPT", "REJECT"):
                    return self.send_json({"error": "action must be ACCEPT or REJECT"}, 400)
                def _rev(conn):
                    row = conn.execute(
                        "SELECT outcome, status FROM identity_candidates WHERE id=?",
                        (cand_id,)).fetchone()
                    if not row:
                        raise ValueError("Candidate not found")
                    outcome, current_status = row
                    if current_status != "PENDING":
                        raise ValueError(f"Candidate already {current_status}")
                    if action == "ACCEPT" and outcome not in ("CONFIRMED_MATCH",
                                                              "STRONG_MATCH"):
                        raise ValueError(
                            f"Cannot accept {outcome}: only CONFIRMED_MATCH and "
                            f"STRONG_MATCH are mergeable. WEAK_MATCH and "
                            f"CONFLICTING_IDENTITY must remain split.")
                    new_status = "ACCEPTED" if action == "ACCEPT" else "REJECTED"
                    conn.execute("""UPDATE identity_candidates SET status=?,
                        reviewed_at=?, reviewer=? WHERE id=?""",
                        (new_status, now_text(), reviewer, cand_id))
                    conn.execute("""INSERT INTO identity_continuity_events(
                        timestamp, continuity_id, event_type, severity, confidence, details)
                        VALUES (?, '', ?, 'INFO', 100, ?)""",
                        (now_text(),
                         f"IDENTITY_CANDIDATE_{new_status}",
                         f"Candidate #{cand_id} {new_status} by {reviewer} "
                         f"(was {outcome})"))
                try:
                    DB_MANAGER.write(_rev)
                except ValueError as exc:
                    return self.send_json({"error": str(exc)}, 409)
                return self.send_json({"reviewed": True, "action": action})

            if self.path == "/api/network/authorize":
                length = int(self.headers.get("Content-Length", "0"))
                payload = (json.loads(self.rfile.read(length).decode("utf-8"))
                           if 0 < length <= 4096 else {})
                if payload.get("confirm") is not True:
                    return self.send_json({"error": "Confirm required."}, 400)
                try:
                    authorize_current()
                except RuntimeError as exc:
                    return self.send_json({"error": str(exc)}, 400)
                with NET_LOCK:
                    network = NET_CTX.get("network", "")
                return self.send_json({"authorized": True,
                    "message": f"Authorised for {network}."})

            if self.path == "/api/threat/import":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 65536:
                    return self.send_json({"error": "Invalid."}, 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                indicators = payload.get("indicators", [])
                if not isinstance(indicators, list) or len(indicators) > 500:
                    return self.send_json({"error": "Up to 500."}, 400)
                added = 0
                def _w(conn):
                    nonlocal added
                    for item in indicators:
                        if not isinstance(item, dict):
                            continue
                        value = _clean(item.get("value", ""), 253).lower().strip().rstrip(".")
                        kind = str(item.get("type", "DOMAIN")).upper()
                        if kind not in {"DOMAIN", "IP"} or not value:
                            continue
                        if kind == "DOMAIN":
                            if len(value) > 253 or not re.fullmatch(
                                r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
                                r"(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", value):
                                continue
                        else:
                            try:
                                ipaddress.ip_address(value)
                            except ValueError:
                                continue
                        sev = str(item.get("severity", "MEDIUM")).upper()
                        if sev not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                            sev = "MEDIUM"
                        cur = conn.execute("""INSERT OR IGNORE INTO threat_indicators(
                            indicator_type, indicator_value, source, severity,
                            description, created_at) VALUES (?, ?, ?, ?, ?, ?)""",
                            (kind, value, _clean(payload.get("source", "LOCAL"), 80),
                             sev, _clean(item.get("description", ""), 250), now_text()))
                        added += cur.rowcount
                DB_MANAGER.write(_w)
                return self.send_json({"added": added,
                    "message": f"Imported {added} new indicators."})

            if self.path == "/api/intelligence/update-oui":
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8")) if 0 < length <= 1024 else {}
                if payload.get("confirm") is not True:
                    return self.send_json({"error": "Explicit confirmation required."}, 400)
                result = update_oui_database()
                return self.send_json(result, 200 if result["updated"] else 502)

            if self.path == "/api/scan":
                SCAN_NOW_EVENT.set()
                return self.send_json({"queued": True}, 202)

            if self.path == "/api/config_findings/close":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1024:
                    return self.send_json({"error": "Invalid."}, 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                fid = int(payload.get("id", 0))
                def _w(conn):
                    conn.execute("UPDATE config_findings SET status='CLOSED' WHERE id=?", (fid,))
                DB_MANAGER.write(_w)
                return self.send_json({"closed": True})

            if self.path == "/api/evidence/verify":
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1024:
                    return self.send_json({"error": "Invalid."}, 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                return self.send_json(verify_evidence(int(payload.get("id", 0))))

        except Exception as e:
            return self.send_json({"error": _clean(e, 200)}, 400)

        self.send_json({"error": "Not found"}, 404)

# ============================================================
# STARTUP + MAIN
# ============================================================

def start_web():
    global WEB_PORT, WEB_URL
    raw_port = os.environ.get("NETWORKRADAR_PORT", str(WEB_PORT)).strip()
    try:
        port = int(raw_port)
        # 9.5.0: port 8766 is authoritative unless the operator explicitly opts in.
        # A conflict is never silently hidden by moving the dashboard to another port.
        allow_alt = "--allow-alt-port" in sys.argv
        server, bound_port = bind_local_server(
            Handler, WEB_HOST, port, allow_alternate=allow_alt, search_span=30
        )
    except (ValueError, StartupError) as exc:
        print(f"ERROR: web console startup failed: {exc}")
        sys.exit(2)
    WEB_PORT = bound_port
    WEB_URL = f"http://{WEB_HOST}:{WEB_PORT}"
    threading.Thread(target=server.serve_forever, name="NR-Web", daemon=True).start()
    print(f"LOCAL WEB CONSOLE ONLINE: {WEB_URL}")
    if WEB_PORT != port:
        print(f"WARNING: requested port {port} was unavailable; using {WEB_PORT}.")
    try:
        webbrowser.open(WEB_URL)
    except Exception:
        pass
    return server

def deep_fingerprint(devices):
    """Run authorised Nmap service discovery and persist per-host scan completeness."""
    if not devices or not is_authorized():
        return False
    for dev in devices:
        dev["_port_scan_complete"] = False
        dev["port_numbers"] = []
        dev["services_found"] = []
        dev["nmap_service_intel"] = []
    ips = [d["ip"] for d in devices if d.get("ip")]
    if not ips: return False
    base = [str(NMAP), "-sT", "-sV", "--version-intensity", "5", "--reason", "--top-ports",
            str(FINGERPRINT_TOP_PORTS), "-O", "--osscan-limit", "--max-os-tries", "1", "-oX", "-"]
    try:
        r = subprocess.run(base + ips, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=180)
        if r.returncode != 0 or not r.stdout.strip():
            fb = [str(NMAP), "-sT", "-sV", "--version-intensity", "5", "--reason", "--top-ports",
                  str(FINGERPRINT_TOP_PORTS), "-oX", "-"]
            r = subprocess.run(fb + ips, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=150)
        if not r.stdout.strip():
            ts=now_text()
            DB_MANAGER.write(lambda conn: [conn.execute(
                "INSERT INTO port_scan_observations(timestamp,ip,device_id,completed,open_ports,scan_method,detail) VALUES(?,?,?,?,?,?,?)",
                (ts,d["ip"],d.get("device_id", ""),0,"","nmap","Nmap returned no XML output")) for d in devices])
            return False
        root = ET.fromstring(r.stdout)
        by_ip = {d["ip"]: d for d in devices}
        for host in root.findall("host"):
            addr = host.find("./address[@addrtype='ipv4']")
            if addr is None: continue
            dev = by_ip.get(addr.get("addr"))
            if not dev: continue
            status = host.find("status")
            ports_node = host.find("./ports")
            # A host block with an explicit ports element is a completed result even if empty.
            if ports_node is None: continue
            dev["_port_scan_complete"] = True
            osms = host.findall("./os/osmatch")
            if osms:
                best = max(osms, key=lambda m: int(m.get("accuracy", "0")))
                name = _clean(best.get("name", "")); acc = int(best.get("accuracy", "0"))
                if name: dev["os_guess"] = f"{name} ({acc}% Nmap)"
            for port in ports_node.findall("./port"):
                st = port.find("state")
                if st is None or st.get("state") != "open": continue
                pid = port.get("portid", "")
                svc = port.find("service")
                sname = svc.get("name", "unknown") if svc is not None else "unknown"
                prod = svc.get("product", "") if svc is not None else ""
                ver = svc.get("version", "") if svc is not None else ""
                extra = svc.get("extrainfo", "") if svc is not None else ""
                try: dev["port_numbers"].append(int(pid))
                except ValueError: continue
                dev["services_found"].append(f"{pid}/{' '.join(x for x in (sname,prod,ver,extra) if x)}")
                dev.setdefault("nmap_service_intel", []).append({
                    "port": int(pid), "protocol": port.get("protocol", "tcp"),
                    "name": _clean(sname, 100), "product": _clean(prod, 160),
                    "version": _clean(ver, 100), "extrainfo": _clean(extra, 160),
                    "tunnel": _clean(svc.get("tunnel", "") if svc is not None else "", 40),
                    "method": _clean(svc.get("method", "") if svc is not None else "", 40),
                })
        for dev in devices:
            dev["port_numbers"] = sorted(set(dev.get("port_numbers", [])))
            dev["open_ports"] = ", ".join(map(str,dev["port_numbers"])) if dev["_port_scan_complete"] else ""
            dev["service_summary"] = "; ".join(dev.get("services_found", []))[:500]
        ts = now_text()
        def _save(conn):
            for dev in devices:
                did=dev.get("device_id", "")
                if not did:
                    match=conn.execute("SELECT device_id FROM devices WHERE ip=?",(dev["ip"],)).fetchone()
                    did=(match[0] or "") if match else ""
                if dev.get("_port_scan_complete"):
                    conn.execute("""INSERT INTO port_scan_observations(timestamp,ip,device_id,completed,open_ports,scan_method,detail)
                        VALUES(?,?,?,?,?,?,?)""",(ts,dev["ip"],did,1,
                        ",".join(map(str,dev.get("port_numbers",[]))),"nmap",
                        "Host returned explicit Nmap ports element"))
                else:
                    conn.execute("""INSERT INTO port_scan_observations(timestamp,ip,device_id,completed,open_ports,scan_method,detail)
                        VALUES(?,?,?,?,?,?,?)""",(ts,dev["ip"],did,0,"","nmap",
                        "No complete per-host port result; findings retained"))
        DB_MANAGER.write(_save)
        return all(d.get("_port_scan_complete") for d in devices)
    except Exception as e:
        NMAP_LOG.write_text(f"[{now_text()}] Deep fingerprint: {_clean(e,500)}",encoding="utf-8")
        return False


def refresh_device_relationships():
    added = 0
    def _w(conn):
        nonlocal added
        ts = now_text()
        conn.execute("DELETE FROM device_relationships WHERE target_ip IN "
                     "('224.0.0.251','ff02::fb','224.0.0.252') "
                     "AND relationship_type='DNS_RESOLVER'")
        dns = conn.execute("""SELECT client_ip,resolver_ip,query_type,COUNT(*) FROM dns_events
            WHERE timestamp>=datetime('now','-24 hours') AND client_ip<>'' AND resolver_ip<>''
            GROUP BY client_ip,resolver_ip,query_type HAVING COUNT(*)>=2 LIMIT 3000""").fetchall()
        dhcp = conn.execute("""SELECT client_ip,server_ip,COUNT(*) FROM dhcp_events
            WHERE timestamp>=datetime('now','-7 days') AND client_ip<>'' AND server_ip<>''
            GROUP BY client_ip,server_ip LIMIT 1000""").fetchall()
        for src, dst, qtype, count in dns:
            if src == dst:
                continue
            qtu = (qtype or "").upper()
            if qtu.startswith("REVERSE_DNS") or qtu.startswith("PTR"):
                continue
            if dst in {"224.0.0.251", "ff02::fb"} or qtu.startswith("MDNS/"):
                rel = "MDNS_DISCOVERY"
            elif dst in {"224.0.0.252", "ff02::1:3"} or qtu.startswith("LLMNR/"):
                rel = "LLMNR_DISCOVERY"
            else:
                try:
                    if ipaddress.ip_address(dst).is_multicast:
                        continue
                except ValueError:
                    continue
                rel = "DNS_RESOLVER"
            did = conn.execute("SELECT device_id FROM devices WHERE ip=?", (src,)).fetchone()
            cur = conn.execute("""INSERT INTO device_relationships(timestamp,source_device_id,source_ip,target_ip,
                relationship_type,evidence,confidence,last_seen) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(source_ip,target_ip,relationship_type) DO UPDATE SET
                timestamp=excluded.timestamp,last_seen=excluded.last_seen,evidence=excluded.evidence,
                confidence=MAX(device_relationships.confidence,excluded.confidence)""",
                (ts, (did[0] if did else "") or "", src, dst, rel,
                 f"Observed {count} {rel.replace('_', ' ').lower()} events in rolling 24h",
                 85 if rel != "DNS_RESOLVER" else 90, ts))
            added += max(0, cur.rowcount)
        for src, dst, count in dhcp:
            if src == dst:
                continue
            did = conn.execute("SELECT device_id FROM devices WHERE ip=?", (src,)).fetchone()
            cur = conn.execute("""INSERT INTO device_relationships(timestamp,source_device_id,source_ip,target_ip,
                relationship_type,evidence,confidence,last_seen) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(source_ip,target_ip,relationship_type) DO UPDATE SET
                timestamp=excluded.timestamp,last_seen=excluded.last_seen,evidence=excluded.evidence,
                confidence=MAX(device_relationships.confidence,excluded.confidence)""",
                (ts, (did[0] if did else "") or "", src, dst, "DHCP_SERVER",
                 f"Observed {count} DHCP messages in rolling 7d", 95, ts))
            added += max(0, cur.rowcount)
    DB_MANAGER.write(_w)
    return added

def mdns_passive_snapshot(duration=3):
    if not TSHARK.exists():
        return []
    iface = choose_iface()
    if not iface:
        return []
    fields = ["ip.src", "eth.src", "dns.qry.name", "dns.resp.name",
              "dns.ptr.domain_name", "dns.srv.target", "dns.txt"]
    cmd = [str(TSHARK), "-n", "-i", str(iface),
           "-a", f"duration:{max(1, min(5, int(duration)))}",
           "-f", "udp port 5353", "-Y", "mdns", "-T", "fields",
           "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a"]
    for field in fields:
        cmd.extend(["-e", field])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=duration + 8, encoding="utf-8", errors="replace")
        out = []
        for line in (r.stdout or "").splitlines()[:1000]:
            row = next(csv.reader([line], delimiter="\t", quotechar='"'))
            row += [""] * (len(fields) - len(row))
            ip, mac, qname, rname, ptr, srv, txt = row[:7]
            values = [x for x in (qname, rname, ptr, srv, txt) if x]
            if ip and values:
                out.append({"ip": ip, "mac": mac,
                            "records": _clean(" | ".join(values), 500)})
        return out
    except Exception:
        return []

DHCP_ENGINE = None  # global, set by main() so /api/engine_diagnostics can reach it

def _main_inner():
    global DHCP_ENGINE
    print(f"\nINITIALISING NETWORKRADAR {APP_VERSION}...")
    if not NMAP.exists():
        print(f"ERROR: Nmap not found: {NMAP}")
        sys.exit(1)
    if not TSHARK.exists():
        print(f"ERROR: TShark not found: {TSHARK}")
        sys.exit(1)

    initialize_database()
    repair_dns_domain_classification()
    load_oui_cache()
    try:
        refresh_network_context()
    except Exception as e:
        print("NET CONTEXT WARNING:", _clean(e, 220))
    # Network approval must be loaded before the optional management listener
    # evaluates whether endpoint management is permitted on this network.
    try:
        print("ENDPOINT AGENT HUB:", json.dumps(start_agent_hub()))
    except Exception as _agent_exc:
        print("ENDPOINT AGENT HUB STARTUP WARNING:", _clean(_agent_exc, 240))
    print("DATABASE INITIALISED (serialized writer active).")

    web = start_web()
    dns = DNSEngine()
    dhcp = DHCPEngine()
    arp = ARPEngine()
    DHCP_ENGINE = dhcp
    dns.start()
    dhcp.start()
    arp.start()

    scan_n = 0
    last_dash = last_scan = last_health = last_corr = last_risk = last_audit = 0
    update_job(state="READY", phase="Waiting", message="Engines starting.")

    try:
        while not STOP_EVENT.is_set():
            now = time.monotonic()

            if now - last_health >= 60:
                try:
                    if not NETWORK_OVERRIDE:
                        refresh_network_context()
                    health_sample()
                except Exception as e:
                    with HEALTH_LOCK:
                        HEALTH.update({"status": "ERROR", "notes": [_clean(e, 180)]})
                last_health = now

            if now - last_corr >= 90:
                try:
                    correlate()
                    refresh_device_relationships()
                    # D13: evaluate presence for all devices
                    def _presence_pass(conn):
                        rows = conn.execute(
                            "SELECT device_id FROM devices WHERE device_id<>'' "
                            "AND status='ONLINE' LIMIT 500").fetchall()
                        prior = {}
                        for r in conn.execute(
                                "SELECT DISTINCT device_id, state FROM device_presence_events "
                                "WHERE id IN (SELECT MAX(id) FROM device_presence_events "
                                "GROUP BY device_id)").fetchall():
                            prior[r[0]] = r[1]
                        for (did,) in rows:
                            try:
                                evaluate_presence_for_device(conn, did, prior.get(did))
                            except Exception:
                                pass
                    try:
                        DB_MANAGER.write(_presence_pass)
                    except Exception:
                        pass
                except Exception as e:
                    print("CORRELATION:", _clean(e, 150))
                last_corr = now

            if now - last_risk >= 120:
                try:
                    compute_risk()
                except Exception as e:
                    print("RISK:", _clean(e, 150))
                last_risk = now

            if now - last_audit >= 180:
                try:
                    audit_config()
                except Exception as e:
                    print("AUDIT:", _clean(e, 150))
                last_audit = now

            manual = SCAN_NOW_EVENT.is_set()
            if manual:
                SCAN_NOW_EVENT.clear()

            if manual or now - last_scan >= SCAN_INTERVAL:
                try:
                    changed, approved = refresh_network_context()
                    if changed:
                        def _w(conn):
                            record_event(conn, "-", "NETWORK_CHANGED",
                                         f"Changed to {current_network()}",
                                         category="network", severity="MEDIUM")
                        DB_MANAGER.write(_w)
                    if not approved:
                        update_job(state="WAITING_AUTHORIZATION",
                                   phase="Authorisation required",
                                   message=f"Passive only on {current_network()}.")
                        last_scan = time.monotonic()
                        STOP_EVENT.wait(2)
                        continue
                except Exception as e:
                    update_job(state="ERROR", phase="Network detection",
                               message="Could not determine network.",
                               error=_clean(e, 400))
                    STOP_EVENT.wait(5)
                    continue

                scan_n += 1
                started = time.monotonic()
                update_job(state="RUNNING", phase="Discovery", percent=8,
                           message=f"Scanning {current_network()}.",
                           scan_number=scan_n, error="")
                try:
                    prev = {}
                    with DB_MANAGER.read() as c:
                        for r in c.execute("""SELECT ip, mac, hostname,
                            open_ports FROM devices WHERE status='ONLINE'""").fetchall():
                            prev[r[0]] = {"mac": r[1] or "",
                                          "hostname": r[2] or "",
                                          "open_ports": r[3] or ""}
                    devices, _dur = discover_devices()
                    update_job(phase="Inventory", percent=20,
                               message=f"{len(devices)} hosts responded.")
                    new, ret, off = update_inventory(devices)
                    audit_arp_cache()
                    deep = (scan_n == 1 or scan_n % FINGERPRINT_EVERY_N_SCANS == 0)
                    update_job(phase="Identification", percent=45,
                               message="Multi-signal identification.")
                    mdns_rows = []
                    if scan_n == 1 or scan_n % 5 == 0:
                        try:
                            mdns_rows = mdns_passive_snapshot(duration=2)
                        except Exception:
                            mdns_rows = []
                    devices = enrich_devices(devices, deep=deep, mdns_rows=mdns_rows)
                    # Keep Phantom Track in step with the completed inventory run.
                    # Offline devices are not re-observed; their anchors remain historical.
                    try:
                        run_identity_continuity()
                    except Exception as continuity_error:
                        print("PHANTOM TRACK:", _clean(continuity_error, 180))
                    update_job(phase="Phantom intelligence", percent=62,
                               message="Updating IPv6 neighbours and observed service exposure.")
                    try:
                        if scan_n == 1 or scan_n % 3 == 0:
                            persist_ipv6_observations(collect_ipv6_neighbours())
                        refresh_exposure_intelligence()
                    except Exception as intel_error:
                        print("PHANTOM INTELLIGENCE:", _clean(intel_error, 180))
                    update_job(phase="Behaviour", percent=70, message="Comparing baselines.")
                    behaviour_snapshot()
                    update_job(phase="Correlation", percent=82, message="Clustering alerts.")
                    correlate()
                    update_job(phase="Risk", percent=90, message="Computing risk.")
                    compute_risk()
                    try:
                        curr = {d["ip"]: {"mac": d.get("mac", ""),
                                          "hostname": d.get("hostname", ""),
                                          "open_ports": d.get("open_ports", ""),
                                          "_ports_complete": bool(d.get("_port_scan_complete", False))}
                                for d in devices}
                        detect_changes(prev, curr, ports_complete=deep)
                        audit_config()
                    except Exception as e:
                        print("CHANGES:", _clean(e, 150))
                    total = round(time.monotonic() - started, 2)
                    def _w(conn):
                        conn.execute("""INSERT INTO scans(timestamp, network,
                            hosts_up, duration) VALUES (?, ?, ?, ?)""",
                            (now_text(), current_network(), len(devices), total))
                        record_event(conn, "-", "SCAN_COMPLETED",
                                     f"{len(devices)} hosts in {total}s; deep={deep}",
                                     category="discovery")
                    DB_MANAGER.write(_w)
                    last_scan = time.monotonic()
                    update_job(state="COMPLETED", phase="Scan completed",
                               percent=100,
                               message=f"Scan {scan_n}: {len(devices)} hosts in {total}s.",
                               scan_number=scan_n)
                except Exception as e:
                    msg = _clean(e, 400)
                    update_job(state="ERROR", phase="Scan error", percent=0,
                               message="Scan failed; inventory retained.",
                               scan_number=scan_n, error=msg)
                    try:
                        def _w(conn):
                            record_event(conn, "-", "SCAN_ERROR", msg,
                                         category="discovery", severity="MEDIUM")
                        DB_MANAGER.write(_w)
                    except Exception:
                        pass
                    print("SCAN ERROR:", msg)
                    last_scan = time.monotonic()

            STOP_EVENT.wait(1)

    except KeyboardInterrupt:
        print("\nShutdown requested.")
    finally:
        STOP_EVENT.set()
        dns.stop()
        dhcp.stop()
        arp.stop()
        dns.join(timeout=5)
        dhcp.join(timeout=5)
        arp.join(timeout=5)
        print("Flushing database...")
        DB_MANAGER.flush(timeout=10)
        DB_MANAGER.stop(timeout=10)
        stop_agent_hub()
        web.shutdown()
        web.server_close()
        print(f"NETWORKRADAR {APP_VERSION} STOPPED.")

def main():
    try:
        acquire_instance_lock()
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        sys.exit(2)
    try:
        _main_inner()
    finally:
        release_instance_lock()

if __name__ == "__main__":
    main()