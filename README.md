# NetworkRadar 14.0.0

## Adaptive fingerprint scheduling (14.0.0)

- Adds a pure, testable scheduler that prioritises never-fingerprinted devices, then weak identities after a 15-minute retry cooldown, medium-confidence identities after 6 hours, and established identities after 24 hours.
- Uses the latest Nmap attempt timestamp, including incomplete attempts, so filtered or slow devices are not immediately hammered again.
- Hydrates confidence from the persistent inventory and freshness from port-scan history; it does not confuse the frequently refreshed `last_identified` field with an actual Nmap run.
- Caps a main deep-fingerprint pass at 8 selected private IPv4 hosts and targeted UDP discovery at the 3 highest-priority selected hosts.
- Leaves deferred devices in the inventory and preserves their existing port/service observations; the low-priority identity subscan remains responsible for one-host follow-up work.
- Tightens TCP/OS, fallback and UDP process/per-host budgets. The existing authorisation gate and safe Nmap script allow-list remain unchanged.
- Adds regression tests for priority ordering, cooldowns, refresh intervals, private-address filtering, deduplication and hard target limits.
- No database migration or new network protocol is introduced.

## Embedded OS identity recognition (13.8.0)

- Recognises embedded RTOS fingerprints including VxWorks, QNX, eCos, ThreadX, FreeRTOS and Zephyr.
- Adds a broad "Embedded / appliance device" hypothesis when Nmap OS or safe script evidence supports that family.
- Reports the OS family as "Embedded / appliance OS" without guessing a physical manufacturer, exact product role or hardware model.
- Keeps the NIC/OUI registrant separate from the device manufacturer.
- Adds regression coverage for the observed VxWorks case. No database migration or new network probes are introduced.

## Dashboard consistency and accessibility (13.7.0)

- Adds a final, additive dashboard styling layer for consistent focus visibility, keyboard navigation and touch interaction.
- Prevents grid and workspace children from forcing horizontal page overflow.
- Improves horizontal table scrolling on narrow screens while preserving readable table columns.
- Extends reduced-motion support across all animated and transitioning components.
- Keeps existing dashboard structure, scan orchestration, identity logic and database schema unchanged.


## Separate identity subscan progress (13.6.1)

- Adds an independent active-device progress bar with the current IP, investigation stage and status message; the main network scan monitor is no longer overwritten by targeted subscans.
- Adds a separate queue-completion bar counting devices that have reached a terminal resolved or retry-exhausted state.
- Uses stage-based progress because Nmap does not expose a dependable percentage for its in-flight subprocess; the active bar animates while that stage runs.
- Adds atomic scan/subscan slot reservation so a full network scan and targeted identity subscan cannot start at the same time.
- Keeps the existing one-host-at-a-time queue, retry limits, exponential backoff and authorisation boundaries.


## Continuous identity investigation (13.6.0)

- Adds a dedicated low-priority identity subscan worker that queues currently observed, unidentified private IPv4 devices and investigates one host at a time.
- The worker remains available while NetworkRadar is running, but it does not probe continuously: each target has a three-attempt limit, exponential backoff, a six-hour exhausted-target cooldown, and evidence-change reopening.
- Targeted scans run only when the current network is explicitly authorised, only for addresses inside the authorised private subnet, and never overlap a full scan.
- Adds a dashboard queue with queued/running/resolved/exhausted counts, per-device attempt history and next-attempt timing.
- The queue is rebuilt from the live inventory after application restart; no historical inventory is deleted.
- Adds tests for deduplication, retry limits, backoff, evidence-change reopening and private-address scoping.

## Scan observability and unknown-device investigation (13.5.0)

- Measures wall-clock time for discovery, Nmap TCP/OS, fallback, UDP, service enrichment, identity fusion and post-scan analytics.
- Adds a local Scan Performance panel and `/api/scan_performance` endpoint; timings are measured, not estimated.
- Adds evidence-specific next actions to Unknown Device Hunter. Suggestions never launch probes automatically and active actions remain conditional on network authorisation.
- Exact model/manufacturer claims remain limited to authenticated endpoint inventory or explicit device/service-reported fields.
- Adds regression tests for scan profiling and evidence-gap guidance. No database migration is required.

## Bounded deep discovery and identity diagnostics (13.4.0)

- Adapts Nmap TCP/OS/service port volume and wall-clock budgets to the number of discovered hosts.
- Applies explicit per-host timeouts, bounded retries and a reduced service-only fallback when a full fingerprint pass is slow.
- Bounds targeted UDP discovery separately so filtered devices cannot hold a scan open for several minutes.
- Runs independent, read-only TLS, SNMPv3 and service-banner enrichment concurrently across devices while preserving per-device results and errors.
- Improves DHCP no-traffic diagnostics by showing the capture interface and filter, and explaining the limits of passive DHCP visibility on switched/Wi-Fi networks.
- Preserves explicit network authorisation gates, the local-only dashboard, existing inventory history and conservative identity evidence rules.
- No destructive database migration or automatic firewall changes.

## Current release

NetworkRadar 14.0.0 adds adaptive evidence-aware fingerprint scheduling on top of the 13.8.0 embedded OS recognition. Main Nmap work is limited to the highest-priority live private IPv4 targets, recent attempts are cooled down, and TCP/UDP process budgets are tightened. Existing inventory and deferred targets are retained; explicit authorisation and conservative identity claims remain unchanged. Windows/Nmap live validation is required.

NetworkRadar 13.8.0 adds evidence-backed recognition for embedded real-time operating-system fingerprints, including VxWorks, QNX, eCos, ThreadX, FreeRTOS and Zephyr. It can classify a device broadly as an embedded/appliance device when an Nmap OS or script fingerprint supports that family; it does not infer the device manufacturer, product role or exact model. The release preserves existing database records and network-authorisation boundaries. Windows/Nmap live validation remains required.

## Windows dashboard startup reliability (13.1.1)

- Diagnoses Windows WSAEACCES/10013 bind failures and checks IPv4/IPv6 TCP excluded-port ranges with netsh when available.
- Distinguishes a port already in use from a Windows-reserved/excluded port; a reserved port can fail even when no process is listening.
- Closes partially created HTTP server sockets after bind or activation failures.
- Keeps port 8766 authoritative by default. A different port is used only when explicitly configured or when `--allow-alt-port` is supplied.



## Identity coverage and operational health (13.1.0)

- Device identity now consumes observed inventory/device names when the DHCP hostname field is empty, while filtering generated "Unidentified device at ..." labels.
- Device-name clues remain one evidence family and do not become confirmed identity or exact hardware-model claims by themselves.
- Scan quality now has a true 100-point maximum, includes scan recency, and shows component-level discovery, network-context, authorisation and telemetry health.
- Identity coverage is reported separately from discovery/telemetry quality, excludes legacy unclassified/ambiguous labels and generated placeholder names, and includes classified/unclassified counts and average confidence. Unavailable coverage is not misreported as zero.
- The status endpoint isolates optional summary-query failures and returns partial status plus explicit error details instead of failing the entire dashboard status response.
- The dashboard labels partial status accurately and displays identity coverage alongside scan quality.


## Evidence-fused device intelligence (13.0.0)

The identity engine scores independent evidence families rather than adding points for every field. Repeated hostnames, banners or observations from one protocol family are capped so they cannot masquerade as independent confirmations.

Supported evidence families include:
- DHCP client vendor class, hostname, user class and FQDN observations.
- Nmap TCP/IP OS fingerprints, service/version results and selected safe NSE discovery scripts.
- Targeted UDP discovery for common management, UPnP and mDNS/DNS-SD services.
- SSDP/UPnP device descriptions, mDNS/DNS-SD service advertisements, SNMPv3, LLDP/CDP and active service metadata.
- Explicitly enrolled endpoint inventory, when available.

The dossier now presents ranked device-family hypotheses, competing classifications, independent source families, OS-family evidence, observed TCP/UDP ports, Nmap script coverage and collection limitations. The dashboard separates the reported device manufacturer/model from the IEEE NIC address-block registrant.

Important interpretation safeguards:
- OUI/NIC registrant, locally administered MAC, IP address and open ports cannot by themselves establish a physical device model.
- A Google Cast advertisement identifies a media-receiver capability, not necessarily a television or Android handset.
- DHCP vendor classes and names are client-supplied and can be absent or changed.
- Exact model/manufacturer claims require explicit endpoint or service-reported fields; authenticated endpoint inventory is the strongest available option.
- Confidence is an explainable heuristic evidence score, not a statistical probability.
- The last strong profile is retained when a shallow scan has insufficient new evidence. Close competing hypotheses are withheld rather than forced into one category.

Deep scans use selected Nmap safe/discovery scripts only; NetworkRadar does not enable the broad default script set or vulnerability/exploit categories.

## Multi-source Android-friendly discovery (12.9.0)

The discovery pass now explicitly uses Nmap ARP host discovery (-PR) and
disables per-address reverse-DNS lookups during the host sweep. It also reads
the Windows IPv4 neighbour table and supplements the scan only with entries
currently in the Reachable state. Stale neighbour entries are not promoted
to online inventory.

Locally administered MAC addresses (including common Android Wi-Fi randomized
addresses) remain visible as observed link-layer addresses. NetworkRadar does
not attempt to recover a device's factory MAC and does not merge two randomized
addresses based on OUI, hostname similarity, TTL, or weak fingerprints.

DHCP capture now checks the installed TShark field registry before launching.
Optional fields that are missing in a particular Wireshark build are omitted
without shifting the DHCP event columns; required-field incompatibilities are
reported explicitly rather than causing a silent restart loop.

These sources improve discovery, not guaranteed identification. Wi-Fi client
isolation, VLAN boundaries, AP policies, and the scanner's network vantage
point can still prevent peer discovery. Router/AP association-table integration
remains vendor-specific and requires an explicitly configured, read-only
integration.


NetworkRadar is a Windows-focused, local-first network discovery and device-intelligence application. It combines authorised network discovery, device inventory, DNS/DHCP/ARP observations, identity evidence, historical tracking, exposure observations, investigations and a localhost dashboard. Optional management features include SSH terminal access and Windows/endpoint-management integrations.

> **Project status:** Active development. The repository contains a large application core and a growing modular package. The current snapshot has not yet completed a full Windows end-to-end security and compatibility test cycle. Treat remote-management features as advanced functionality and use them only on systems and networks you own or are explicitly authorised to administer.

## Current application version

The application version is defined once in `networkradar_modules/__init__.py` and exposed to the dashboard and logs by `networkradar.py`.

## Dashboard workspaces (12.7.0)

The dashboard is organised into six switchable workspaces. The workspace shell groups existing panels; it does not remove their DOM IDs, API calls, database records, or feature handlers.

- **Command Centre:** Nightwatch overview, scan progress, live topology, activity feed, engine health and network context.
- **Devices & Identity:** Device inventory, identity evidence, continuity tracking, manual identity candidates, unknown-device review and IPv6 neighbour observations.
- **Network Activity:** Network workspaces and profiles, DNS, DHCP, ARP, behaviour baselines and network changes.
- **Security & Investigations:** Local firewall visibility, investigations, alert stream, configuration audit, threat hunts and exposure observations.
- **Remote Management:** Phantom Access and explicitly enrolled managed endpoints.
- **Intelligence & Reports:** Local intelligence assistant, recent events and report generation.

The sidebar and workspace tabs provide the same six destinations. Tabs support keyboard navigation and adapt to smaller screens. Existing feature panels remain available inside their corresponding workspace.

## DHCP identity enrichment (12.8.0)

DHCP capture now records additional client-supplied identity metadata where present:

- **Option 93 — Client System Architecture:** parsed as a PXE/pre-boot architecture observation. It is not interpreted as the installed operating system or hardware model.
- **Option 77 — User Class:** retained as an observed client-supplied label.
- **Option 81 — Client FQDN:** retained as an observed client-supplied name.

These fields are stored additively in `dhcp_events`, included in the device dossier's DHCP history, and passed to the DHCP fingerprint interpreter. Existing DHCP rows remain valid and display blank values for fields that were not captured. The option 97 machine GUID is intentionally not collected by default because it is a stable endpoint identifier and is not necessary for this discovery increment.

Option 93 semantics follow [RFC 4578](https://www.rfc-editor.org/rfc/rfc4578.html); the capture field names are checked against the [Wireshark DHCP display-filter reference](https://www.wireshark.org/docs/dfref/d/dhcp.html).

## RADAR IDENTITY foundation

The identity package includes bounded parsers for captured SSDP headers and mDNS/DNS-SD service observations. These parsers produce evidence and capability hints; advertisements are not treated as proof of physical hardware identity. SSDP LOCATION values are retained as observations and are not fetched by the parser. The parsers do not themselves start multicast discovery or packet capture; collection and end-to-end integration remain separate work.

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


## Strong network anchor detection fix (12.4.0)

NetworkRadar 12.4.0 fixes two Windows evidence-collection defects that could prevent a correctly connected laptop from being recognised as being on a specific network:

- Gateway MAC collection no longer passes the unsupported `-IPAddress` parameter to `Get-NetNeighbor`. It queries the selected default-route interface and matches the exact gateway IP and interface index in the returned neighbour rows.
- The WLAN parser recognises Windows' actual `AP BSSID` label as well as `BSSID`, and still requires that the interface is connected and the address is a valid unicast MAC.

Network fingerprint diagnostics are exposed by `/api/network`. If `NETWORKRADAR_NETWORK` is set, it acts only as a manual scan-scope override and automatic network fingerprinting/authorisation remain disabled. Remove it from the current PowerShell session with `Remove-Item Env:NETWORKRADAR_NETWORK -ErrorAction SilentlyContinue`, then restart NetworkRadar to restore automatic detection.

The active-discovery authorisation gate remains strict: a strong anchor, adequate fingerprint confidence and explicit fresh network approval are all still required.

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
- The optional endpoint-agent hub is disabled by default and requires TLS configuration, certificate pinning, verified certificate-pin rotation, a one-time enrolment token and a firewall rule restricted to authorised endpoint devices. The supplied client is inventory-only and does not implement remote command execution.

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


## Windows dashboard startup reliability (13.1.1)

- Diagnoses Windows WSAEACCES/10013 bind failures and checks IPv4/IPv6 TCP excluded-port ranges with netsh when available.
- Distinguishes a port already in use from a Windows-reserved/excluded port; a reserved port can fail even when no process is listening.
- Closes partially created HTTP server sockets after bind or activation failures.
- Keeps port 8766 authoritative by default. A different port is used only when explicitly configured or when `--allow-alt-port` is supplied.



## Identity coverage and operational health (13.1.0)

- Device identity now consumes observed inventory/device names when the DHCP hostname field is empty, while filtering generated "Unidentified device at ..." labels.
- Device-name clues remain one evidence family and do not become confirmed identity or exact hardware-model claims by themselves.
- Scan quality now has a true 100-point maximum, includes scan recency, and shows component-level discovery, network-context, authorisation and telemetry health.
- Identity coverage is reported separately from discovery/telemetry quality, excludes legacy unclassified/ambiguous labels and generated placeholder names, and includes classified/unclassified counts and average confidence. Unavailable coverage is not misreported as zero.
- The status endpoint isolates optional summary-query failures and returns partial status plus explicit error details instead of failing the entire dashboard status response.
- The dashboard labels partial status accurately and displays identity coverage alongside scan quality.


## Evidence-fused device intelligence (13.0.0)

The identity engine scores independent evidence families rather than adding points for every field. Repeated hostnames, banners or observations from one protocol family are capped so they cannot masquerade as independent confirmations.

Supported evidence families include:
- DHCP client vendor class, hostname, user class and FQDN observations.
- Nmap TCP/IP OS fingerprints, service/version results and selected safe NSE discovery scripts.
- Targeted UDP discovery for common management, UPnP and mDNS/DNS-SD services.
- SSDP/UPnP device descriptions, mDNS/DNS-SD service advertisements, SNMPv3, LLDP/CDP and active service metadata.
- Explicitly enrolled endpoint inventory, when available.

The dossier now presents ranked device-family hypotheses, competing classifications, independent source families, OS-family evidence, observed TCP/UDP ports, Nmap script coverage and collection limitations. The dashboard separates the reported device manufacturer/model from the IEEE NIC address-block registrant.

Important interpretation safeguards:
- OUI/NIC registrant, locally administered MAC, IP address and open ports cannot by themselves establish a physical device model.
- A Google Cast advertisement identifies a media-receiver capability, not necessarily a television or Android handset.
- DHCP vendor classes and names are client-supplied and can be absent or changed.
- Exact model/manufacturer claims require explicit endpoint or service-reported fields; authenticated endpoint inventory is the strongest available option.
- Confidence is an explainable heuristic evidence score, not a statistical probability.
- The last strong profile is retained when a shallow scan has insufficient new evidence. Close competing hypotheses are withheld rather than forced into one category.

Deep scans use selected Nmap safe/discovery scripts only; NetworkRadar does not enable the broad default script set or vulnerability/exploit categories.

## Multi-source Android-friendly discovery (12.9.0)

The discovery pass now explicitly uses Nmap ARP host discovery (-PR) and
disables per-address reverse-DNS lookups during the host sweep. It also reads
the Windows IPv4 neighbour table and supplements the scan only with entries
currently in the Reachable state. Stale neighbour entries are not promoted
to online inventory.

Locally administered MAC addresses (including common Android Wi-Fi randomized
addresses) remain visible as observed link-layer addresses. NetworkRadar does
not attempt to recover a device's factory MAC and does not merge two randomized
addresses based on OUI, hostname similarity, TTL, or weak fingerprints.

DHCP capture now checks the installed TShark field registry before launching.
Optional fields that are missing in a particular Wireshark build are omitted
without shifting the DHCP event columns; required-field incompatibilities are
reported explicitly rather than causing a silent restart loop.

These sources improve discovery, not guaranteed identification. Wi-Fi client
isolation, VLAN boundaries, AP policies, and the scanner's network vantage
point can still prevent peer discovery. Router/AP association-table integration
remains vendor-specific and requires an explicitly configured, read-only
integration.


NetworkRadar is a Windows-focused, local-first network discovery and device-intelligence application. It combines authorised network discovery, device inventory, DNS/DHCP/ARP observations, identity evidence, historical tracking, exposure observations, investigations and a localhost dashboard. Optional management features include SSH terminal access and Windows/endpoint-management integrations.

> **Project status:** Active development. The repository contains a large application core and a growing modular package. The current snapshot has not yet completed a full Windows end-to-end security and compatibility test cycle. Treat remote-management features as advanced functionality and use them only on systems and networks you own or are explicitly authorised to administer.

## Current application version

The application version is defined once in `networkradar_modules/__init__.py` and exposed to the dashboard and logs by `networkradar.py`.

## Dashboard workspaces (12.7.0)

The dashboard is organised into six switchable workspaces. The workspace shell groups existing panels; it does not remove their DOM IDs, API calls, database records, or feature handlers.

- **Command Centre:** Nightwatch overview, scan progress, live topology, activity feed, engine health and network context.
- **Devices & Identity:** Device inventory, identity evidence, continuity tracking, manual identity candidates, unknown-device review and IPv6 neighbour observations.
- **Network Activity:** Network workspaces and profiles, DNS, DHCP, ARP, behaviour baselines and network changes.
- **Security & Investigations:** Local firewall visibility, investigations, alert stream, configuration audit, threat hunts and exposure observations.
- **Remote Management:** Phantom Access and explicitly enrolled managed endpoints.
- **Intelligence & Reports:** Local intelligence assistant, recent events and report generation.

The sidebar and workspace tabs provide the same six destinations. Tabs support keyboard navigation and adapt to smaller screens. Existing feature panels remain available inside their corresponding workspace.

## DHCP identity enrichment (12.8.0)

DHCP capture now records additional client-supplied identity metadata where present:

- **Option 93 — Client System Architecture:** parsed as a PXE/pre-boot architecture observation. It is not interpreted as the installed operating system or hardware model.
- **Option 77 — User Class:** retained as an observed client-supplied label.
- **Option 81 — Client FQDN:** retained as an observed client-supplied name.

These fields are stored additively in `dhcp_events`, included in the device dossier's DHCP history, and passed to the DHCP fingerprint interpreter. Existing DHCP rows remain valid and display blank values for fields that were not captured. The option 97 machine GUID is intentionally not collected by default because it is a stable endpoint identifier and is not necessary for this discovery increment.

Option 93 semantics follow [RFC 4578](https://www.rfc-editor.org/rfc/rfc4578.html); the capture field names are checked against the [Wireshark DHCP display-filter reference](https://www.wireshark.org/docs/dfref/d/dhcp.html).

## RADAR IDENTITY foundation

The identity package includes bounded parsers for captured SSDP headers and mDNS/DNS-SD service observations. These parsers produce evidence and capability hints; advertisements are not treated as proof of physical hardware identity. SSDP LOCATION values are retained as observations and are not fetched by the parser. The parsers do not themselves start multicast discovery or packet capture; collection and end-to-end integration remain separate work.

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


## Strong network anchor detection fix (12.4.0)

NetworkRadar 12.4.0 fixes two Windows evidence-collection defects that could prevent a correctly connected laptop from being recognised as being on a specific network:

- Gateway MAC collection no longer passes the unsupported `-IPAddress` parameter to `Get-NetNeighbor`. It queries the selected default-route interface and matches the exact gateway IP and interface index in the returned neighbour rows.
- The WLAN parser recognises Windows' actual `AP BSSID` label as well as `BSSID`, and still requires that the interface is connected and the address is a valid unicast MAC.

Network fingerprint diagnostics are exposed by `/api/network`. If `NETWORKRADAR_NETWORK` is set, it acts only as a manual scan-scope override and automatic network fingerprinting/authorisation remain disabled. Remove it from the current PowerShell session with `Remove-Item Env:NETWORKRADAR_NETWORK -ErrorAction SilentlyContinue`, then restart NetworkRadar to restore automatic detection.

The active-discovery authorisation gate remains strict: a strong anchor, adequate fingerprint confidence and explicit fresh network approval are all still required.

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
- The optional endpoint-agent hub is disabled by default and requires TLS configuration, certificate pinning, verified certificate-pin rotation, a one-time enrolment token and a firewall rule restricted to authorised endpoint devices. The supplied client is inventory-only and does not implement remote command execution.

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
