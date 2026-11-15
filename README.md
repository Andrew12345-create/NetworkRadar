# NetworkRadar 12.3.0

NetworkRadar is a Windows-focused, local-first network discovery and device-intelligence application. It combines authorised network discovery, device inventory, DNS/DHCP/ARP observations, identity evidence, historical tracking, exposure observations, investigations and a localhost dashboard. Optional management features include SSH terminal access and Windows/endpoint-management integrations.

> **Project status:** Active development. The repository contains a large application core and a growing modular package. The current snapshot has not yet completed a full Windows end-to-end security and compatibility test cycle. Treat remote-management features as advanced functionality and use them only on systems and networks you own or are explicitly authorised to administer.

## Current application version

The application version is defined once in `networkradar_modules/__init__.py` and exposed to the dashboard and logs by `networkradar.py`.

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer.
- Nmap installed and available on PATH, or configured with `NETWORKRADAR_NMAP`.
- Wireshark/TShark installed and available on PATH, or configured with `NETWORKRADAR_TSHARK`.
- Capture permissions and a compatible Npcap installation may be required for packet-observation features.

The core application uses the Python standard library. Paramiko is optional and required only for the SSH terminal.

## Installation

1. Clone or download the complete repository. Do not copy only `networkradar.py`; the application imports the `networkradar_modules` package.
2. Open PowerShell in the repository directory.
3. Create and activate a virtual environment:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   ```

4. Install optional SSH support if you intend to use Phantom Terminal:

   ```powershell
   python -m pip install -r requirements-ssh.txt
   ```

5. Install Nmap and Wireshark/TShark separately and confirm that `nmap --version` and `tshark --version` work in PowerShell.
6. Start NetworkRadar:

   ```powershell
   .\NetworkRadar.ps1
   ```

   If PowerShell blocks the launcher, you may temporarily permit scripts in the current PowerShell process only:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\NetworkRadar.ps1
   ```

The dashboard opens at **http://127.0.0.1:8766** by default.


## Multi-network workspaces (12.2.0)

NetworkRadar now records separately identified network workspaces using opaque IDs and fingerprint history. Different networks using the same private subnet are kept separate in the workspace directory. Active adapters are collected independently and classified as Wi-Fi, Ethernet, VPN, virtual or other; the selected primary adapter remains the only network used by the current active-discovery and authorisation loop.

Active discovery also requires a strong network anchor (gateway MAC or interface-specific BSSID); a high fingerprint score based only on shared network settings cannot authorise scanning. The dashboard Network Workspaces explorer is a historical, read-only view. It shows observed interfaces and device sightings for each workspace. Selecting a historical workspace does not switch the active scanner or grant authorisation. Existing legacy inventory and history tables are retained; the new workspace and sighting tables are additive.

After upgrading to 12.2.0, approve each network again before active discovery. Workspace-specific approval records start unapproved because legacy subnet-keyed approvals cannot be safely assigned to individual workspaces. A fingerprint change currently creates a separate workspace rather than automatically merging networks. This is intentional: roaming access points, changing gateways and overlapping subnets need conservative correlation and explicit review before workspaces are merged.

## Packet-capture interface selection

NetworkRadar first identifies the active Windows adapter using route metrics, then matches that adapter to TShark by interface GUID/name/description. This avoids silently capturing on a different Wi-Fi or Ethernet adapter when several are present.

To inspect TShark's interface list:

```powershell
tshark -D
```

If automatic matching cannot identify the active adapter, set the TShark interface number (or a matching displayed name) for the current PowerShell session:

```powershell
$env:NETWORKRADAR_TSHARK_INTERFACE = "3"
.\NetworkRadar.ps1
```

## Port configuration

Set a specific port for the current PowerShell session:

```powershell
$env:NETWORKRADAR_PORT = "8767"
.\NetworkRadar.ps1
```

NetworkRadar does not silently change ports. To explicitly permit a search of the next 30 ports:

```powershell
.\NetworkRadar.ps1 --allow-alt-port
```

The primary dashboard is intended to bind to loopback (`127.0.0.1`). Do not expose it through port forwarding or a reverse proxy without a separate security review.

## Authenticated endpoint inventory agent (12.3.0)

NetworkRadar now includes an optional Windows endpoint inventory client in `agent/networkradar_agent.py`. It complements network-based fingerprinting with device-reported manufacturer, exact system model/family, CPU, RAM, BIOS version, disks, OS build and network-adapter details. This is the recommended route to exact hardware identification when the device owner can explicitly enrol the endpoint.

The client is inventory-only. It does not execute remote commands, install itself as a service, enumerate user files, collect browser history or capture packets. BIOS and disk serial numbers are omitted unless the operator explicitly supplies `--include-serial`.

The agent hub remains disabled by default. To use the client, configure `NETWORKRADAR_AGENT_ENABLED=1`, a TLS certificate/key, an explicit LAN bind address and a firewall rule limited to the endpoints you administer. Generate a one-time enrolment token in the dashboard, calculate the SHA-256 fingerprint of the hub's DER leaf certificate, then enrol the target using the instructions in [agent deployment guide](agent/README.md). The endpoint validates the pinned certificate before sending requests, authenticates inventory reports with its per-agent HMAC key, and stores that key with Windows DPAPI for the current Windows user.

New inventory reports are associated with the network device dossier using the observed source IP, with hostname as a secondary clue. Device details show endpoint-reported hardware separately from network-derived guesses. The endpoint agent advertises only the `inventory-report` capability; the server rejects commands that the enrolled agent has not advertised. The agent does not poll the remote command queue.

The client reports immediately and then every five minutes by default. It requires Windows 10/11 and Python 3.10+. It does not automatically install or start itself; run it manually or configure a reviewed Task Scheduler job under the intended Windows account.

## Data and database

On startup, the application creates its local `data/` and `database/` directories when needed. These directories are intentionally excluded from Git because they contain local network inventory, observations, captures, credentials/trust material and runtime database files.

- Back up your own `data/` and `database/` folders before upgrading.
- When updating application code, retain your existing local database and data folders.
- After upgrading to 12.2.0, re-authorise each network you intend to scan. Workspace-specific approvals start unapproved because legacy subnet-keyed approvals cannot be safely assigned to individual networks.
- Do not commit scan output, packet captures, database files, SSH known-host records, agent secrets, certificates or private keys.

This repository does **not** ship a live SQLite database.

## Run tests

From the repository root:

```powershell
python -m unittest discover -s tests -v
```

The suite includes isolated tests for startup, SQLite database management, identity, diagnostics, Nmap XML parsing, ARP parsing, adapter selection, device-family classification, identity evidence coverage, mDNS/DNS-SD packet parsing, SSDP URL validation, endpoint-agent TLS pin and HMAC protocol handling, and per-agent capability boundaries, plus application regression tests for identity scoring and network-approval freshness. UPnP descriptions are capped at 256 KiB, DTD/entity declarations are rejected, and description URLs/redirects are restricted to the responding private IP; advertised model strings remain unverified observations. IEEE MAC identity uses the MA-L, MA-M and MA-S public listings with longest-prefix matching; the assignee is not treated as definitive device-manufacturer evidence. Device-category rules also enforce source-family compatibility so a NIC registrant cannot, by itself, classify a router, phone or computer. Actual Windows discovery, packet capture, browser and remote-management behaviour still requires testing on a real Windows host.

## Security and authorised use

- Only scan networks for which you have permission.
- Active discovery and endpoint management are gated by a locally approved network profile.
- Open ports and service banners are observations, not proof of vulnerabilities or compromise.
- SSH host keys must be reviewed and explicitly trusted before authentication.
- Remote actions can affect availability. Review targets and confirm disruptive actions carefully.
- The optional endpoint-agent hub is disabled by default and requires TLS configuration, certificate pinning, a one-time enrolment token and a firewall rule restricted to authorised endpoint devices. The supplied client is inventory-only and does not implement remote command execution.

## Project structure

- `networkradar.py` — application runtime, API and orchestration.
- `index.html` — dashboard markup and page structure. The page uses external CSS/JS assets and contains no inline style attributes.
- `networkradar.css` — standalone responsive dashboard stylesheet.
- `dashboard.js` — standalone dashboard client and interactions.
- `agent/` — opt-in Windows endpoint inventory client and deployment instructions.\n- `networkradar_modules/` — reusable identity, startup, database, diagnostics and discovery components. Identity quality reporting provides domain-level evidence coverage for hardware, OS, network identity, services, classification and evidence diversity; coverage is explicitly not a probability of correct identification. Discovery modules cover Nmap XML/scanning, ARP parsing, adapter selection, evidence-based device-family classification, reverse-DNS/NetBIOS probes, SSDP/UPnP discovery with bounded device-description parsing (manufacturer, model, UDN and embedded-device records), and bounded active mDNS/DNS-SD browsing.
- `migrations/` — additive database schema migrations.
- `tests/` — unit and application regression tests.
- `docs/` — architecture and audit notes.

See [Architecture](docs/ARCHITECTURE.md), [Release Notes](RELEASE_NOTES.md), and [Audit History](AUDIT_AND_TEST_RESULTS.md).

## License

No license file has been selected yet. Public visibility on GitHub does not by itself grant permission to copy, modify or redistribute this project. Add an explicit license before presenting NetworkRadar as an open-source release.
