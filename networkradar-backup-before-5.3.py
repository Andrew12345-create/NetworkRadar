import os
import sys
import time
import json
import webbrowser
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import csv
import math
import re
import threading
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path
from datetime import datetime

# ============================================================
# NETWORKRADAR 5.3 | CYBER INTELLIGENCE CENTRE
# Additive upgrade: DNS capture, domain intelligence, heuristics
# ============================================================

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
LOG_DIR = DATA / "logs"
DB = ROOT / "database" / "networkradar.db"
NMAP_LOG = LOG_DIR / "nmap-latest.log"
DNS_LOG = LOG_DIR / "tshark-dns.log"

NMAP = Path(r"C:\Program Files (x86)\Nmap\nmap.exe")
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")

NETWORK = "192.168.100.0/24"
SCAN_INTERVAL = 30
DASHBOARD_REFRESH = 5
WEB_HOST = "127.0.0.1"  # Local machine only; do not expose the control panel to the LAN.
WEB_PORT = 8765
WEB_URL = f"http://{WEB_HOST}:{WEB_PORT}"
DNS_CAPTURE_FILTER = "udp port 53 or tcp port 53"

# Set this environment variable if automatic Wi-Fi interface detection
# does not select the correct TShark interface:
#   $env:NETWORKRADAR_TSHARK_INTERFACE = "6"
PREFERRED_INTERFACE = os.environ.get("NETWORKRADAR_TSHARK_INTERFACE", "").strip()

DATA.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
DB.parent.mkdir(parents=True, exist_ok=True)

STOP_EVENT = threading.Event()
SCAN_NOW_EVENT = threading.Event()
DNS_STATE = {
    "status": "STARTING",
    "interface": "Not selected",
    "queries": 0,
    "responses": 0,
    "alerts": 0,
    "last_event": "Waiting for capture",
    "error": "",
}
DNS_STATE_LOCK = threading.Lock()

DNS_TYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
    "15": "MX", "16": "TXT",
    "28": "AAAA", "33": "SRV", "35": "NAPTR", "65": "HTTPS",
    "41": "OPT", "43": "DS", "46": "RRSIG", "47": "NSEC",
    "48": "DNSKEY", "52": "TLSA", "255": "ANY",
}
DNS_RCODE_NAMES = {
    "0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL",
    "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED",
}


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect_db():
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def initialize_database():
    """Create the original 5.0 tables and additive 5.1 DNS tables."""
    with connect_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                manufacturer TEXT,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                event_type TEXT,
                details TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                network TEXT,
                hosts_up INTEGER,
                duration REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT,
                resolver_ip TEXT,
                domain TEXT,
                query_type TEXT,
                is_response INTEGER DEFAULT 0,
                response_code TEXT,
                response_time REAL,
                answers TEXT,
                interface TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_intel (
                domain TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                query_count INTEGER DEFAULT 0,
                unique_clients INTEGER DEFAULT 0,
                last_response_code TEXT,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'INFO'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT,
                domain TEXT,
                rule_id TEXT,
                severity TEXT,
                score INTEGER,
                details TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dns_client_domains (
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                query_count INTEGER DEFAULT 0,
                PRIMARY KEY (client_ip, domain)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_events_time ON dns_events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_events_client ON dns_events(client_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_events_domain ON dns_events(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_alerts_time ON dns_alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)")


def record_event(conn, ip, event_type, details):
    conn.execute("""
        INSERT INTO events (timestamp, ip, event_type, details)
        VALUES (?, ?, ?, ?)
    """, (now_text(), ip or "-", event_type, details))


# ------------------------- NMAP DISCOVERY -------------------------

def discover_devices():
    command = [
        str(NMAP), "-sn", "-n", "-oX", "-", NETWORK
    ]
    started = time.time()
    result = subprocess.run(
        command, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120
    )
    duration = round(time.time() - started, 2)
    NMAP_LOG.write_text(result.stderr or "", encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed: {(result.stderr or '')[-1000:]}")

    root = ET.fromstring(result.stdout)
    devices = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip, mac, vendor, hostname = "", "Unavailable", "Unknown", "-"
        for address in host.findall("address"):
            if address.get("addrtype") == "ipv4":
                ip = address.get("addr", "")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr", "Unavailable")
                vendor = address.get("vendor") or "Unknown"

        names = host.find("hostnames")
        if names is not None:
            name = names.find("hostname")
            if name is not None:
                hostname = name.get("name") or "-"

        if ip:
            devices.append({
                "ip": ip, "mac": mac, "vendor": vendor,
                "hostname": hostname
            })

    return devices, duration


def update_inventory(devices):
    now = now_text()
    current_ips = {device["ip"] for device in devices}
    new_devices = returned_devices = offline_devices = 0

    with connect_db() as conn:
        previous = {
            row[0]: row[1]
            for row in conn.execute("SELECT ip, status FROM devices").fetchall()
        }

        for device in devices:
            ip = device["ip"]
            old_status = previous.get(ip)

            if old_status is None:
                new_devices += 1
                record_event(conn, ip, "NEW_DEVICE", "Device discovered for the first time.")
            elif old_status == "OFFLINE":
                returned_devices += 1
                record_event(conn, ip, "DEVICE_RETURNED", "Previously discovered device is responding again.")

            conn.execute("""
                INSERT INTO devices
                (ip, mac, manufacturer, hostname, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, 'ONLINE')
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac,
                    manufacturer=excluded.manufacturer,
                    hostname=excluded.hostname,
                    last_seen=excluded.last_seen,
                    status='ONLINE'
            """, (
                ip, device["mac"], device["vendor"], device["hostname"],
                now, now
            ))

        for ip, status in previous.items():
            if status == "ONLINE" and ip not in current_ips:
                offline_devices += 1
                conn.execute("UPDATE devices SET status='OFFLINE' WHERE ip=?", (ip,))
                record_event(conn, ip, "DEVICE_OFFLINE",
                             "Previously responding device did not respond to this scan.")

    return new_devices, returned_devices, offline_devices


# ------------------------- DNS INTELLIGENCE -------------------------

def choose_tshark_interface():
    if PREFERRED_INTERFACE:
        return PREFERRED_INTERFACE

    result = subprocess.run(
        [str(TSHARK), "-D"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError("TShark could not enumerate capture interfaces.")

    for line in result.stdout.splitlines():
        if re.search(r"\(Wi-?Fi\)", line, re.IGNORECASE):
            match = re.match(r"\s*(\d+)\.", line)
            if match:
                return match.group(1)

    # Known interface from the initial NetworkRadar host inspection.
    # Override with NETWORKRADAR_TSHARK_INTERFACE if it changes.
    return "6"


def shannon_entropy(value):
    if not value:
        return 0.0
    length = len(value)
    return -sum((value.count(char) / length) * math.log2(value.count(char) / length)
                for char in set(value))


def normalized_domain(domain):
    return (domain or "").strip().rstrip(".").lower()


def domain_heuristics(domain):
    """Return conservative heuristic indicators; these are not verdicts."""
    labels = [part for part in normalized_domain(domain).split(".") if part]
    if not labels:
        return []
    first = labels[0]
    findings = []

    if len(domain) >= 90:
        findings.append(("DNS_LONG_NAME", "MEDIUM", 35,
                         f"Very long DNS name ({len(domain)} characters)."))
    if len(first) >= 50 and shannon_entropy(first) >= 3.7:
        findings.append(("DNS_TUNNEL_INDICATOR", "HIGH", 70,
                         "Long, high-entropy first label; investigate possible DNS tunnelling."))
    elif len(first) >= 30 and shannon_entropy(first) >= 3.8:
        findings.append(("DNS_HIGH_ENTROPY_LABEL", "MEDIUM", 40,
                         "High-entropy DNS label may be generated or encoded."))
    return findings


class DNSCaptureEngine(threading.Thread):
    def __init__(self):
        super().__init__(name="NetworkRadar-DNS", daemon=True)
        self.process = None
        self.interface = "Not selected"
        self.pending = {}
        self.query_windows = defaultdict(deque)
        self.nxdomain_windows = defaultdict(deque)
        self.alert_cooldowns = {}

    def set_state(self, **kwargs):
        with DNS_STATE_LOCK:
            DNS_STATE.update(kwargs)

    def stop(self):
        STOP_EVENT.set()
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=4)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

    def run(self):
        while not STOP_EVENT.is_set():
            try:
                self.interface = choose_tshark_interface()
                self.set_state(status="ONLINE", interface=self.interface, error="")
                self.capture_loop()
                if not STOP_EVENT.is_set():
                    self.set_state(status="RESTARTING",
                                   error="Capture process ended; restarting.")
                    STOP_EVENT.wait(5)
            except Exception as error:
                self.set_state(status="DEGRADED", error=str(error))
                STOP_EVENT.wait(10)

    def capture_loop(self):
        fields = [
            "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
            "dns.id", "dns.flags.response", "dns.flags.rcode",
            "dns.qry.name", "dns.qry.type", "dns.time",
            "dns.a", "dns.aaaa", "dns.cname"
        ]
        command = [
            str(TSHARK), "-l", "-n", "-i", self.interface,
            "-f", DNS_CAPTURE_FILTER, "-T", "fields",
            "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"
        ]
        for field in fields:
            command.extend(["-e", field])

        with open(DNS_LOG, "a", encoding="utf-8", errors="replace") as error_log:
            error_log.write(f"\n[{now_text()}] Starting DNS capture on interface {self.interface}\n")
            error_log.flush()
            self.process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=error_log,
                text=True, encoding="utf-8", errors="replace", bufsize=1
            )
            try:
                for line in self.process.stdout:
                    if STOP_EVENT.is_set():
                        break
                    self.process_packet(line)
            finally:
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                self.process = None

    def process_packet(self, line):
        try:
            row = next(csv.reader([line.rstrip("\r\n")],
                                  delimiter="\t", quotechar='"'))
            row += [""] * (14 - len(row))
            (epoch, ip_src, ipv6_src, ip_dst, ipv6_dst, dns_id,
             is_response, rcode, domain, qtype, dns_time,
             answer_a, answer_aaaa, answer_cname) = row[:14]

            domain = normalized_domain(domain)
            if not domain:
                return

            packet_src = ip_src or ipv6_src
            packet_dst = ip_dst or ipv6_dst
            if not packet_src or not packet_dst:
                return

            timestamp = datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S") if epoch else now_text()
            response = is_response.strip().lower() in {"1", "true", "yes"}
            query_type = DNS_TYPE_NAMES.get(qtype.strip(), f"TYPE{qtype}" if qtype else "UNKNOWN")
            answers = "; ".join(value for value in (answer_a, answer_aaaa, answer_cname) if value)

            if response:
                client_ip, resolver_ip = packet_dst, packet_src
                key = (dns_id, domain, resolver_ip)
                pending = self.pending.pop(key, None)
                response_time = None
                if pending:
                    client_ip = pending["client"]
                    response_time = round((time.monotonic() - pending["clock"]) * 1000, 2)
                response_code = DNS_RCODE_NAMES.get(rcode.strip(), f"RCODE{rcode}" if rcode else "UNKNOWN")
                self.store_dns_event(timestamp, client_ip, resolver_ip, domain,
                                     query_type, 1, response_code, response_time, answers)
                if response_code == "NXDOMAIN":
                    self.track_nxdomain(client_ip, domain)
                return

            client_ip, resolver_ip = packet_src, packet_dst
            key = (dns_id, domain, resolver_ip)
            self.pending[key] = {"client": client_ip, "clock": time.monotonic()}
            # Expire stale query correlations.
            cutoff = time.monotonic() - 15
            self.pending = {k: v for k, v in self.pending.items()
                            if v["clock"] >= cutoff}
            self.store_dns_event(timestamp, client_ip, resolver_ip, domain,
                                 query_type, 0, "", None, "")
            self.track_query_rate(client_ip, domain)
            self.inspect_domain(client_ip, domain)
        except Exception as error:
            self.set_state(error=f"Packet parse/store issue: {error}")

    def store_dns_event(self, timestamp, client_ip, resolver_ip, domain,
                        query_type, is_response, response_code, response_time, answers):
        is_new = False
        with connect_db() as conn:
            existing = conn.execute(
                "SELECT domain FROM domain_intel WHERE domain=?", (domain,)
            ).fetchone()
            if not is_response:
                is_new = existing is None
                conn.execute("""
                    INSERT INTO domain_intel
                    (domain, first_seen, last_seen, query_count, unique_clients,
                     last_response_code, risk_score, risk_level)
                    VALUES (?, ?, ?, 1, 1, '', 0, 'INFO')
                    ON CONFLICT(domain) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        query_count=domain_intel.query_count+1
                """, (domain, timestamp, timestamp))
                conn.execute("""
                    INSERT INTO dns_client_domains
                    (client_ip, domain, first_seen, last_seen, query_count)
                    VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(client_ip, domain) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        query_count=dns_client_domains.query_count+1
                """, (client_ip, domain, timestamp, timestamp))
                clients = conn.execute(
                    "SELECT COUNT(*) FROM dns_client_domains WHERE domain=?", (domain,)
                ).fetchone()[0]
                conn.execute("UPDATE domain_intel SET unique_clients=? WHERE domain=?",
                             (clients, domain))
            elif response_code:
                conn.execute("""
                    UPDATE domain_intel SET last_response_code=?, last_seen=?
                    WHERE domain=?
                """, (response_code, timestamp, domain))

            conn.execute("""
                INSERT INTO dns_events
                (timestamp, client_ip, resolver_ip, domain, query_type,
                 is_response, response_code, response_time, answers, interface)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, client_ip, resolver_ip, domain, query_type,
                  is_response, response_code, response_time, answers, self.interface))

            if is_new:
                record_event(conn, client_ip, "DNS_NEW_DOMAIN",
                             f"First observed domain: {domain}")

        with DNS_STATE_LOCK:
            if is_response:
                DNS_STATE["responses"] += 1
            else:
                DNS_STATE["queries"] += 1
            DNS_STATE["last_event"] = f"{client_ip} -> {domain}"

    def create_alert(self, client_ip, domain, rule_id, severity, score, details):
        cooldown_key = (client_ip, rule_id, domain if rule_id != "DNS_QUERY_BURST" else "")
        now = time.monotonic()
        if now - self.alert_cooldowns.get(cooldown_key, 0) < 300:
            return
        self.alert_cooldowns[cooldown_key] = now

        with connect_db() as conn:
            conn.execute("""
                INSERT INTO dns_alerts
                (timestamp, client_ip, domain, rule_id, severity, score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (now_text(), client_ip, domain, rule_id, severity, score, details))
            record_event(conn, client_ip, "DNS_ALERT",
                         f"{severity} {rule_id}: {details}")
            if domain:
                conn.execute("""
                    UPDATE domain_intel SET
                        risk_score=MAX(risk_score, ?),
                        risk_level=CASE
                            WHEN MAX(risk_score, ?) >= 70 THEN 'HIGH'
                            WHEN MAX(risk_score, ?) >= 35 THEN 'MEDIUM'
                            ELSE 'INFO' END
                    WHERE domain=?
                """, (score, score, score, domain))

        with DNS_STATE_LOCK:
            DNS_STATE["alerts"] += 1
            DNS_STATE["last_event"] = f"ALERT {rule_id} from {client_ip}"

    def inspect_domain(self, client_ip, domain):
        for rule_id, severity, score, details in domain_heuristics(domain):
            self.create_alert(client_ip, domain, rule_id, severity, score, details)

    def track_query_rate(self, client_ip, domain):
        now = time.monotonic()
        window = self.query_windows[client_ip]
        window.append(now)
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= 120:
            self.create_alert(
                client_ip, "", "DNS_QUERY_BURST", "MEDIUM", 45,
                f"{len(window)} DNS queries observed from this device within 60 seconds."
            )

    def track_nxdomain(self, client_ip, domain):
        now = time.monotonic()
        window = self.nxdomain_windows[client_ip]
        window.append(now)
        while window and window[0] < now - 300:
            window.popleft()
        if len(window) >= 10:
            self.create_alert(
                client_ip, domain, "DNS_NXDOMAIN_BURST", "MEDIUM", 40,
                f"{len(window)} NXDOMAIN responses observed from this device within 5 minutes."
            )




# ------------------------- LOCAL WEB COMMAND CENTRE -------------------------

WEB_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetworkRadar | Cyber Intelligence Centre</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2c;--panel2:#10243a;--line:#1c3853;--text:#e8f1fb;--muted:#91a8bf;--blue:#45a5ff;--green:#35d39a;--amber:#f5bd4f;--red:#ff6878}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0%,#102c49 0,#07111f 42%);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}
header{padding:25px 4vw 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}
.brand{display:flex;gap:14px;align-items:center}.logo{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#1679d5,#43d6c5);display:grid;place-items:center;font-size:23px;font-weight:800;color:#03111e}
h1{font-size:22px;letter-spacing:1.5px;margin:0}.sub{color:var(--muted);font-size:12px;letter-spacing:2px}
.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}button{border:0;border-radius:9px;padding:11px 16px;font-weight:700;cursor:pointer;background:var(--blue);color:#03111e}button.secondary{background:#1b334b;color:var(--text);border:1px solid var(--line)}
main{padding:24px 4vw 40px;max-width:1600px;margin:auto}.meta{color:var(--muted);font-size:12px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:18px}
.card{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;padding:17px;min-width:0;box-shadow:0 8px 24px #0002}
.label{color:var(--muted);font-size:11px;letter-spacing:1.3px;text-transform:uppercase}.value{font-size:29px;font-weight:750;margin-top:5px}.hint{color:var(--muted);font-size:12px;margin-top:3px}
.section{margin-top:18px}.section h2{font-size:13px;letter-spacing:1.5px;color:#b8d7f3;margin:0 0 11px}
.split{display:grid;grid-template-columns:1.25fr .75fr;gap:14px}
.statusline{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid #1a3148}.statusline:last-child{border:0}
.pill{font-size:11px;font-weight:800;padding:4px 8px;border-radius:99px;background:#153d35;color:var(--green)}.pill.warn{background:#493819;color:var(--amber)}.pill.bad{background:#48232b;color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:var(--muted);font-weight:600;padding:10px 8px;border-bottom:1px solid var(--line)}td{padding:10px 8px;border-bottom:1px solid #172b40;overflow-wrap:anywhere}tbody tr:hover{background:#ffffff08}.scroll{overflow:auto;max-height:390px}
.mono{font-family:Consolas,monospace}.muted{color:var(--muted)}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}
.notice{border:1px solid #57451f;background:#211c12;color:#f5d58c;padding:12px 14px;border-radius:10px;font-size:12px;margin:15px 0}
footer{padding:20px 4vw;color:var(--muted);border-top:1px solid var(--line);font-size:11px}

.modal{display:none;position:fixed;inset:0;background:#020812dd;z-index:50;padding:3vh 3vw;overflow:auto}
.modal.open{display:flex;align-items:flex-start;justify-content:center}
.modalbox{width:min(1100px,100%);background:#0b1a2b;border:1px solid #31506e;border-radius:16px;padding:22px;box-shadow:0 20px 80px #000b}
.modalhead{display:flex;justify-content:space-between;align-items:center;gap:15px;border-bottom:1px solid var(--line);padding-bottom:14px}
.modalhead h2{margin:5px 0 0;font-size:22px}.modalcontent{padding-top:15px}
.profilegrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.profileitem{background:#10243a;border:1px solid var(--line);border-radius:10px;padding:12px;min-width:0}
.profileitem .label{font-size:10px}.profileitem .value{font-size:15px;overflow-wrap:anywhere;margin-top:5px}
.modalsection{margin-top:20px}.modalsection h3{font-size:12px;letter-spacing:1.2px;color:#b8d7f3}
.clickrow{cursor:pointer}.clickrow:hover{background:#173653!important}.clickhint{color:var(--blue);font-size:11px}
@media(max-width:950px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.split{grid-template-columns:1fr}}
@media(max-width:520px){.grid{grid-template-columns:1fr 1fr}.value{font-size:23px}header{padding:18px 5vw}main{padding:18px 5vw}}
</style>
</head>
<body>
<header>
 <div class="brand"><div class="logo">NR</div><div><h1>NETWORKRADAR 5.3</h1><div class="sub">CYBER INTELLIGENCE COMMAND CENTRE</div></div></div>
 <div class="actions"><span id="connection" class="pill warn">CONNECTING</span><button id="scanButton" onclick="scanNow()">SCAN NETWORK NOW</button><button class="secondary" onclick="refreshAll()">REFRESH</button></div>
</header>
<main>
 <div class="meta">LOCAL CONSOLE · <span id="network">Network loading...</span> · <span id="updated">Waiting for telemetry</span></div>
 <div class="grid">
  <div class="card"><div class="label">Devices online</div><div class="value" id="online">—</div><div class="hint" id="deviceHint">Live network inventory</div></div>
  <div class="card"><div class="label">Historical devices</div><div class="value" id="historical">—</div><div class="hint">Persisted in local SQLite</div></div>
  <div class="card"><div class="label">DNS queries observed</div><div class="value" id="queries">—</div><div class="hint" id="dnsHint">Visible port 53 traffic</div></div>
  <div class="card"><div class="label">DNS alerts</div><div class="value" id="alerts">—</div><div class="hint">Heuristic indicators, not verdicts</div></div>
 </div>
 <div class="split">
  <section class="card">
   <h2>ENGINE HEALTH</h2>
   <div class="statusline"><span>Network discovery (Nmap)</span><span class="pill" id="nmapStatus">ONLINE</span></div>
   <div class="statusline"><span>Device history / SQLite</span><span class="pill">ONLINE</span></div>
   <div class="statusline"><span>DNS packet capture (TShark)</span><span class="pill warn" id="dnsStatus">STARTING</span></div>
   <div class="statusline"><span>Capture interface</span><span class="mono" id="interface">—</span></div>
   <div class="statusline"><span>Last scan duration</span><span class="mono" id="duration">—</span></div>
   <div class="statusline"><span>Last DNS activity</span><span class="mono" id="lastDns">—</span></div>
  </section>
  <section class="card">
   <h2>DNS TELEMETRY</h2>
   <div class="statusline"><span>Unique domains</span><strong id="domains">—</strong></div>
   <div class="statusline"><span>Observed client devices</span><strong id="clients">—</strong></div>
   <div class="statusline"><span>NXDOMAIN responses</span><strong id="nxdomain">—</strong></div>
   <div class="statusline"><span>DNS responses captured</span><strong id="responses">—</strong></div>
   <div class="statusline"><span>Latest capture note</span><span class="muted" id="dnsError">None</span></div>
  </section>
 </div>
 <div class="notice">Visibility boundary: this dashboard shows traffic visible to this computer's capture interface. A normal switched Wi-Fi network usually does not expose every other device's unicast DNS traffic to this laptop. The dashboard does not decrypt HTTPS or encrypted DNS.</div>
 <section class="section card"><h2>LIVE DEVICE INVENTORY</h2><div class="scroll"><table><thead><tr><th>IP ADDRESS</th><th>MANUFACTURER</th><th>HOSTNAME</th><th>MAC</th><th>STATUS</th><th>LAST SEEN</th></tr></thead><tbody id="deviceRows"><tr><td colspan="6" class="muted">Loading inventory...</td></tr></tbody></table></div></section>
 <div class="split section">
  <section class="card"><h2>TOP OBSERVED DOMAINS</h2><div class="scroll"><table><thead><tr><th>DOMAIN</th><th>QUERIES</th><th>RISK</th></tr></thead><tbody id="domainRows"><tr><td colspan="3" class="muted">No DNS observations yet.</td></tr></tbody></table></div></section>
  <section class="card"><h2>RECENT DNS ALERTS</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE</th><th>RULE</th><th>SEVERITY</th></tr></thead><tbody id="alertRows"><tr><td colspan="4" class="muted">No alerts recorded.</td></tr></tbody></table></div></section>
 </div>
 <section class="section card"><h2>RECENT DNS LOOKUPS — VISIBLE DOMAIN ACTIVITY</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE</th><th>DOMAIN REQUESTED</th><th>TYPE</th><th>RESULT</th></tr></thead><tbody id="dnsRows"><tr><td colspan="5" class="muted">Waiting for visible DNS queries...</td></tr></tbody></table></div></section>
 <section class="section card"><h2>RECENT NETWORK EVENTS</h2><div class="scroll"><table><thead><tr><th>TIME</th><th>DEVICE</th><th>EVENT</th><th>DETAILS</th></tr></thead><tbody id="eventRows"><tr><td colspan="4" class="muted">Loading events...</td></tr></tbody></table></div></section>
</main>
<div id="deviceModal" class="modal" onclick="if(event.target===this)closeDevice()">
 <div class="modalbox">
  <div class="modalhead"><div><div class="sub">DEVICE INTELLIGENCE PROFILE</div><h2 id="modalTitle">Device details</h2></div><button class="secondary" onclick="closeDevice()">CLOSE ✕</button></div>
  <div id="modalContent" class="modalcontent">Loading device intelligence...</div>
 </div>
</div>
<footer>NETWORKRADAR LOCAL WEB CONSOLE · Bound to 127.0.0.1 only · Data stored locally in database/networkradar.db</footer>
<script>
const $=id=>document.getElementById(id);
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
async function getJSON(path){const r=await fetch(path,{cache:"no-store"});if(!r.ok)throw new Error("HTTP "+r.status);return r.json();}
function pill(el,text,state){el.textContent=text;el.className="pill"+(state==="bad"?" bad":state==="warn"?" warn":"");}

function closeDevice(){$("deviceModal").classList.remove("open");}
async function openDevice(ip){
 $("deviceModal").classList.add("open");
 $("modalTitle").textContent="Device: "+ip;
 $("modalContent").innerHTML="Loading device intelligence...";
 try{
  const p=await getJSON("/api/device?ip="+encodeURIComponent(ip));
  const d=p.device;
  if(!d){$("modalContent").textContent="No device record found.";return;}
  const profile=[
   ["IP ADDRESS",d.ip],["STATUS",d.status],["MANUFACTURER",d.manufacturer],
   ["HOSTNAME",d.hostname],["MAC ADDRESS",d.mac],["FIRST SEEN",d.first_seen],
   ["LAST SEEN",d.last_seen],["DNS LOOKUPS",p.dns_query_count]
  ];
  let html='<div class="profilegrid">'+profile.map(([k,v])=>`<div class="profileitem"><div class="label">${esc(k)}</div><div class="value">${esc(v||"Unknown")}</div></div>`).join("")+'</div>';
  html+='<div class="notice">This profile shows network metadata visible to NetworkRadar. Domain lookups are not the same as the exact words typed into a search engine. HTTPS and encrypted DNS generally prevent this sensor from seeing search terms or page contents.</div>';
  html+='<div class="modalsection"><h3>DOMAIN ACTIVITY OBSERVED FOR THIS DEVICE</h3><div class="scroll"><table><thead><tr><th>TIME</th><th>DOMAIN</th><th>TYPE</th><th>RESPONSE</th><th>ANSWER</th></tr></thead><tbody>';
  html+=p.dns_events.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.domain)}</td><td>${esc(x.query_type)}</td><td>${esc(x.response_code||"QUERY")}</td><td class="mono">${esc(x.answers||"—")}</td></tr>`).join("")||'<tr><td colspan="5">No DNS activity captured for this device yet.</td></tr>';
  html+='</tbody></table></div></div>';
  html+='<div class="modalsection"><h3>DEVICE ALERTS</h3><div class="scroll"><table><thead><tr><th>TIME</th><th>RULE</th><th>SEVERITY</th><th>DETAILS</th></tr></thead><tbody>';
  html+=p.alerts.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.rule_id)}</td><td>${esc(x.severity)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="4">No alerts for this device.</td></tr>';
  html+='</tbody></table></div></div>';
  html+='<div class="modalsection"><h3>DEVICE EVENT HISTORY</h3><div class="scroll"><table><thead><tr><th>TIME</th><th>EVENT</th><th>DETAILS</th></tr></thead><tbody>';
  html+=p.events.map(x=>`<tr><td>${esc(x.timestamp)}</td><td>${esc(x.event_type)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="3">No historical events.</td></tr>';
  html+='</tbody></table></div></div>';
  $("modalContent").innerHTML=html;
 }catch(err){$("modalContent").textContent="Could not load device profile: "+err.message;}
}

async function refreshAll(){
 try{
  const [s,d,domains,a,e,dnsEvents]=await Promise.all([getJSON("/api/status"),getJSON("/api/devices"),getJSON("/api/domains"),getJSON("/api/alerts"),getJSON("/api/events"),getJSON("/api/dns")]);
  pill($("connection"),"CONNECTED","ok");$("network").textContent=s.network;$("updated").textContent="Updated "+s.timestamp;
  $("online").textContent=s.online;$("historical").textContent=s.historical;$("queries").textContent=s.dns_queries;$("alerts").textContent=s.alert_count;
  $("deviceHint").textContent=s.offline+" currently offline";$("dnsHint").textContent=s.dns_responses+" responses captured";
  $("domains").textContent=s.unique_domains;$("clients").textContent=s.dns_clients;$("nxdomain").textContent=s.nxdomain;$("responses").textContent=s.dns_responses;
  pill($("dnsStatus"),s.dns_status,s.dns_status==="ONLINE"?"ok":"warn");$("interface").textContent=s.interface;$("duration").textContent=s.last_scan_duration+" s";$("lastDns").textContent=s.last_dns_event;$("dnsError").textContent=s.dns_error||"None";
  $("deviceRows").innerHTML=d.map(x=>`<tr class="clickrow" title="Click to inspect this device" onclick="openDevice('${esc(x.ip)}')"><td class="mono">${esc(x.ip)}<div class="clickhint">VIEW PROFILE ↗</div></td><td>${esc(x.manufacturer)}</td><td>${esc(x.hostname)}</td><td class="mono">${esc(x.mac)}</td><td class="${x.status==="ONLINE"?"green":"muted"}">${esc(x.status)}</td><td>${esc(x.last_seen)}</td></tr>`).join("")||'<tr><td colspan="6">No devices recorded.</td></tr>';
  $("domainRows").innerHTML=domains.map(x=>`<tr><td class="mono">${esc(x.domain)}</td><td>${x.query_count}</td><td>${esc(x.risk_level)}</td></tr>`).join("")||'<tr><td colspan="3">No DNS observations yet.</td></tr>';
  $("dnsRows").innerHTML=dnsEvents.map(x=>`<tr class="clickrow" onclick="openDevice('${esc(x.client_ip)}')"><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.client_ip)}<div class="clickhint">OPEN DEVICE ↗</div></td><td class="mono">${esc(x.domain)}</td><td>${esc(x.query_type)}</td><td>${esc(x.response_code||"QUERY OBSERVED")}</td></tr>`).join("")||'<tr><td colspan="5">No DNS queries captured yet.</td></tr>';

  $("alertRows").innerHTML=a.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.client_ip)}</td><td>${esc(x.rule_id)}</td><td class="${x.severity==="HIGH"?"red":"amber"}">${esc(x.severity)}</td></tr>`).join("")||'<tr><td colspan="4">No alerts recorded.</td></tr>';
  $("eventRows").innerHTML=e.map(x=>`<tr><td>${esc(x.timestamp)}</td><td class="mono">${esc(x.ip)}</td><td>${esc(x.event_type)}</td><td>${esc(x.details)}</td></tr>`).join("")||'<tr><td colspan="4">No events recorded.</td></tr>';
 }catch(err){pill($("connection"),"DISCONNECTED","bad");$("updated").textContent=err.message;}
}
async function scanNow(){
 const b=$("scanButton");b.disabled=true;b.textContent="SCAN REQUESTED...";
 try{await fetch("/api/scan",{method:"POST"});$("updated").textContent="Manual scan queued...";}
 catch(e){$("updated").textContent="Could not queue scan: "+e.message;}
 finally{setTimeout(()=>{b.disabled=false;b.textContent="SCAN NETWORK NOW";},2500);}
}
refreshAll();setInterval(refreshAll,3000);
</script>
</body></html>"""


class NetworkRadarWebHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Keep the terminal command centre readable.
        return

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index.html"):
            body = WEB_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        with connect_db() as conn:
            if self.path == "/api/status":
                online, historical, offline = conn.execute("""
                    SELECT
                    SUM(CASE WHEN status='ONLINE' THEN 1 ELSE 0 END),
                    COUNT(*),
                    SUM(CASE WHEN status='OFFLINE' THEN 1 ELSE 0 END)
                    FROM devices
                """).fetchone()
                dns_queries, unique_domains, dns_clients, nxdomain, dns_responses, alert_count = conn.execute("""
                    SELECT
                    (SELECT COUNT(*) FROM dns_events WHERE is_response=0),
                    (SELECT COUNT(*) FROM domain_intel),
                    (SELECT COUNT(DISTINCT client_ip) FROM dns_client_domains),
                    (SELECT COUNT(*) FROM dns_events WHERE response_code='NXDOMAIN'),
                    (SELECT COUNT(*) FROM dns_events WHERE is_response=1),
                    (SELECT COUNT(*) FROM dns_alerts)
                """).fetchone()
                scan = conn.execute("SELECT duration FROM scans ORDER BY id DESC LIMIT 1").fetchone()
                with DNS_STATE_LOCK:
                    dns = dict(DNS_STATE)
                return self.send_json({
                    "network": NETWORK, "timestamp": now_text(),
                    "online": online or 0, "historical": historical or 0,
                    "offline": offline or 0, "dns_queries": dns_queries,
                    "unique_domains": unique_domains, "dns_clients": dns_clients,
                    "nxdomain": nxdomain, "dns_responses": dns_responses,
                    "alert_count": alert_count, "dns_status": dns["status"],
                    "interface": dns["interface"], "dns_error": dns["error"],
                    "last_dns_event": dns["last_event"],
                    "last_scan_duration": scan[0] if scan else 0
                })

            if self.path == "/api/devices":
                rows = conn.execute("""
                    SELECT ip, manufacturer, hostname, mac, status, last_seen
                    FROM devices ORDER BY
                    CASE status WHEN 'ONLINE' THEN 0 ELSE 1 END, ip
                """).fetchall()
                return self.send_json([
                    {"ip":r[0],"manufacturer":r[1],"hostname":r[2],
                     "mac":r[3],"status":r[4],"last_seen":r[5]} for r in rows
                ])

            parsed = urlparse(self.path)
            if parsed.path == "/api/device":
                params = parse_qs(parsed.query)
                ip = params.get("ip", [""])[0]
                device_row = conn.execute("""
                    SELECT ip, mac, manufacturer, hostname, first_seen, last_seen, status
                    FROM devices WHERE ip=?
                """, (ip,)).fetchone()
                if not device_row:
                    return self.send_json({"device": None, "dns_events": [], "alerts": [], "events": []})
                dns_rows = conn.execute("""
                    SELECT timestamp, domain, query_type, response_code, answers, is_response
                    FROM dns_events WHERE client_ip=?
                    ORDER BY id DESC LIMIT 100
                """, (ip,)).fetchall()
                dns_count = conn.execute("""
                    SELECT COUNT(*) FROM dns_events
                    WHERE client_ip=? AND is_response=0
                """, (ip,)).fetchone()[0]
                alert_rows = conn.execute("""
                    SELECT timestamp, rule_id, severity, score, details
                    FROM dns_alerts WHERE client_ip=? ORDER BY id DESC LIMIT 50
                """, (ip,)).fetchall()
                event_rows = conn.execute("""
                    SELECT timestamp, event_type, details
                    FROM events WHERE ip=? ORDER BY id DESC LIMIT 50
                """, (ip,)).fetchall()
                return self.send_json({
                    "device": {"ip":device_row[0],"mac":device_row[1],
                               "manufacturer":device_row[2],"hostname":device_row[3],
                               "first_seen":device_row[4],"last_seen":device_row[5],
                               "status":device_row[6]},
                    "dns_query_count": dns_count,
                    "dns_events": [{"timestamp":r[0],"domain":r[1],"query_type":r[2],
                                    "response_code":r[3],"answers":r[4],
                                    "is_response":r[5]} for r in dns_rows],
                    "alerts": [{"timestamp":r[0],"rule_id":r[1],"severity":r[2],
                                "score":r[3],"details":r[4]} for r in alert_rows],
                    "events": [{"timestamp":r[0],"event_type":r[1],"details":r[2]}
                               for r in event_rows]
                })

            if parsed.path == "/api/dns":
                rows = conn.execute("""
                    SELECT timestamp, client_ip, domain, query_type, response_code
                    FROM dns_events
                    WHERE is_response=0
                    ORDER BY id DESC LIMIT 100
                """).fetchall()
                return self.send_json([
                    {"timestamp":r[0],"client_ip":r[1],"domain":r[2],
                     "query_type":r[3],"response_code":r[4]} for r in rows
                ])

            if self.path == "/api/domains":
                rows = conn.execute("""
                    SELECT domain, query_count, risk_level FROM domain_intel
                    ORDER BY query_count DESC LIMIT 100
                """).fetchall()
                return self.send_json([
                    {"domain":r[0],"query_count":r[1],"risk_level":r[2]} for r in rows
                ])

            if self.path == "/api/alerts":
                rows = conn.execute("""
                    SELECT timestamp, client_ip, domain, rule_id, severity, score, details
                    FROM dns_alerts ORDER BY id DESC LIMIT 50
                """).fetchall()
                return self.send_json([
                    {"timestamp":r[0],"client_ip":r[1],"domain":r[2],
                     "rule_id":r[3],"severity":r[4],"score":r[5],"details":r[6]}
                    for r in rows
                ])

            if self.path == "/api/events":
                rows = conn.execute("""
                    SELECT timestamp, ip, event_type, details
                    FROM events ORDER BY id DESC LIMIT 50
                """).fetchall()
                return self.send_json([
                    {"timestamp":r[0],"ip":r[1],"event_type":r[2],"details":r[3]}
                    for r in rows
                ])

        self.send_json({"error":"Not found"}, 404)

    def do_POST(self):
        if self.path == "/api/scan":
            SCAN_NOW_EVENT.set()
            return self.send_json({"queued": True, "message": "Network scan queued."}, 202)
        self.send_json({"error":"Not found"}, 404)


def start_web_console():
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), NetworkRadarWebHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="NetworkRadar-Web", daemon=True)
    thread.start()
    print(f"LOCAL WEB CONSOLE ONLINE: {WEB_URL}")
    try:
        webbrowser.open(WEB_URL)
    except Exception:
        pass
    return server


# ------------------------- DASHBOARD -------------------------

def show_dashboard(devices, duration, new, returned, offline, scan_number):
    os.system("cls" if os.name == "nt" else "clear")

    with connect_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        online = conn.execute("SELECT COUNT(*) FROM devices WHERE status='ONLINE'").fetchone()[0]
        history = conn.execute("""
            SELECT ip, manufacturer, status FROM devices ORDER BY ip
        """).fetchall()
        events = conn.execute("""
            SELECT timestamp, ip, event_type, details
            FROM events ORDER BY id DESC LIMIT 10
        """).fetchall()
        dns_totals = conn.execute("""
            SELECT
                (SELECT COUNT(*) FROM dns_events WHERE is_response=0),
                (SELECT COUNT(DISTINCT domain) FROM domain_intel),
                (SELECT COUNT(DISTINCT client_ip) FROM dns_client_domains),
                (SELECT COUNT(*) FROM dns_events WHERE response_code='NXDOMAIN'),
                (SELECT COUNT(*) FROM dns_alerts)
        """).fetchone()
        top_domains = conn.execute("""
            SELECT domain, query_count FROM domain_intel
            ORDER BY query_count DESC LIMIT 5
        """).fetchall()
        alerts = conn.execute("""
            SELECT timestamp, client_ip, rule_id, severity, details
            FROM dns_alerts ORDER BY id DESC LIMIT 5
        """).fetchall()

    with DNS_STATE_LOCK:
        dns = dict(DNS_STATE)

    print("=" * 76)
    print("                    NETWORKRADAR 5.3")
    print("                 CYBER INTELLIGENCE CENTRE")
    print("=" * 76)
    print(f"\n NETWORK       : {NETWORK}")
    print(f" COMPUTER      : {os.environ.get('COMPUTERNAME', 'Unknown')}")
    print(f" TIMESTAMP     : {now_text()}")
    print(f" SCAN NUMBER   : {scan_number}")

    print("\n" + "=" * 76)
    print("                       NETWORK INTELLIGENCE")
    print("=" * 76)
    print(f"\n ACTIVE DEVICES       : {online}")
    print(f" HISTORICAL DEVICES   : {total}")
    print(f" NEW DEVICES          : {new}")
    print(f" RETURNED DEVICES     : {returned}")
    print(f" OFFLINE DEVICES      : {offline}")
    print(f" LAST SCAN DURATION   : {duration}s")

    print("\n" + "=" * 76)
    print("                        DEVICE INVENTORY")
    print("=" * 76)
    print(f"\n {'IP ADDRESS':<18} {'MANUFACTURER':<29} STATUS")
    print(" " + "-" * 72)
    for ip, vendor, status in history:
        print(f" {ip:<18} {vendor[:27]:<29} {status}")

    print("\n" + "=" * 76)
    print("                     DNS INTELLIGENCE")
    print("=" * 76)
    print(f"\n DNS ENGINE           : {dns['status']}")
    print(f" CAPTURE INTERFACE    : {dns['interface']}")
    print(f" DNS QUERIES          : {dns_totals[0]}")
    print(f" UNIQUE DOMAINS       : {dns_totals[1]}")
    print(f" OBSERVED CLIENTS     : {dns_totals[2]}")
    print(f" NXDOMAIN RESPONSES   : {dns_totals[3]}")
    print(f" DNS ALERTS           : {dns_totals[4]}")
    print(f" CAPTURED RESPONSES   : {dns['responses']}")
    print(f" LAST DNS ACTIVITY    : {dns['last_event'][:65]}")
    if dns["error"]:
        print(f" CAPTURE NOTE         : {dns['error'][:65]}")

    print("\n TOP OBSERVED DOMAINS")
    if top_domains:
        for domain, count in top_domains:
            print(f"  {count:>6} queries | {domain[:58]}")
    else:
        print("  No DNS queries captured yet.")

    print("\n RECENT DNS ALERTS")
    if alerts:
        for timestamp, client, rule, severity, details in alerts:
            print(f"  [{severity:<6}] {client or '-':<16} {rule}: {details[:55]}")
    else:
        print("  No heuristic alerts recorded.")

    print("\n" + "=" * 76)
    print("                       LIVE EVENT STREAM")
    print("=" * 76)
    if not events:
        print("\n No events recorded yet.")
    for timestamp, ip, event, details in reversed(events):
        print(f"\n {timestamp} | {event:<18} | {ip} | {details[:48]}")

    print("\n" + "=" * 76)
    print("                         ENGINE STATUS")
    print("=" * 76)
    print("\n [ONLINE]  Network Discovery")
    print(" [ONLINE]  Device Intelligence")
    print(" [ONLINE]  SQLite Intelligence Database")
    print(" [ONLINE]  Historical Monitoring")
    print(f" [{'ONLINE' if dns['status'] == 'ONLINE' else 'CHECK'}]  DNS Packet Capture")
    print(" [ONLINE]  Domain Intelligence")
    print(" [ONLINE]  DNS Behaviour Heuristics")
    print(" [PENDING] Advanced Traffic Classification")
    print(" [PENDING] Threat Correlation and Reputation Feeds")
    print("\n" + "=" * 76)
    print(" MONITORING ACTIVE | CTRL+C TO STOP")
    print("=" * 76)


# ------------------------- APPLICATION -------------------------

def main():
    print("\nINITIALISING NETWORKRADAR 5.1...")
    if not NMAP.exists():
        print(f"ERROR: Nmap executable not found: {NMAP}")
        sys.exit(1)
    if not TSHARK.exists():
        print(f"ERROR: TShark executable not found: {TSHARK}")
        sys.exit(1)

    initialize_database()
    print("DATABASE INITIALISED (existing 5.0 data preserved).")
    print("NMAP DISCOVERY ENGINE READY.")
    print("DNS INTELLIGENCE ENGINE STARTING...")

    web_server = start_web_console()
    dns_engine = DNSCaptureEngine()
    dns_engine.start()
    scan_number = 0
    last_dashboard = 0
    last_scan = 0
    last_scan_data = ([], 0.0, 0, 0, 0)

    try:
        while not STOP_EVENT.is_set():
            now = time.monotonic()
            manual_scan = SCAN_NOW_EVENT.is_set()
            if manual_scan:
                SCAN_NOW_EVENT.clear()
            if manual_scan or now - last_scan >= SCAN_INTERVAL:
                scan_number += 1
                devices, duration = discover_devices()
                new, returned, offline = update_inventory(devices)
                with connect_db() as conn:
                    conn.execute("""
                        INSERT INTO scans (timestamp, network, hosts_up, duration)
                        VALUES (?, ?, ?, ?)
                    """, (now_text(), NETWORK, len(devices), duration))
                last_scan_data = (devices, duration, new, returned, offline)
                last_scan = time.monotonic()

            if time.monotonic() - last_dashboard >= DASHBOARD_REFRESH:
                show_dashboard(*last_scan_data, scan_number)
                last_dashboard = time.monotonic()

            STOP_EVENT.wait(1)

    except KeyboardInterrupt:
        print("\n\nShutdown requested.")
    except Exception as error:
        print(f"\nFATAL APPLICATION ERROR: {error}")
        raise
    finally:
        STOP_EVENT.set()
        dns_engine.stop()
        dns_engine.join(timeout=5)
        if "web_server" in locals():
            web_server.shutdown()
            web_server.server_close()
        print("\nNETWORKRADAR 5.3 STOPPED.")


if __name__ == "__main__":
    main()
