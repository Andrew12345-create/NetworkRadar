import os
import sys
import time
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
# NETWORKRADAR 5.1 | CYBER INTELLIGENCE CENTRE
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
DNS_CAPTURE_FILTER = "udp port 53 or tcp port 53"

# Set this environment variable if automatic Wi-Fi interface detection
# does not select the correct TShark interface:
#   $env:NETWORKRADAR_TSHARK_INTERFACE = "6"
PREFERRED_INTERFACE = os.environ.get("NETWORKRADAR_TSHARK_INTERFACE", "").strip()

DATA.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
DB.parent.mkdir(parents=True, exist_ok=True)

STOP_EVENT = threading.Event()
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
    "28": "AAAA", "33": "SRV", "35": "NAPTR", "https": "HTTPS",
    "41": "OPT", "43": "DS", "46": "RRSIG", "47": "NSEC",
    "48": "DNSKEY", "52": "TLSA", "65": "HTTPS", "255": "ANY",
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
            response = is_response.strip() == "1"
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
    print("                    NETWORKRADAR 5.1")
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

    dns_engine = DNSCaptureEngine()
    dns_engine.start()
    scan_number = 0
    last_dashboard = 0
    last_scan = 0
    last_scan_data = ([], 0.0, 0, 0, 0)

    try:
        while not STOP_EVENT.is_set():
            now = time.monotonic()
            if now - last_scan >= SCAN_INTERVAL:
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
        print("\nNETWORKRADAR 5.1 STOPPED.")


if __name__ == "__main__":
    main()
