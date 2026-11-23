# NetworkRadar architecture — repository snapshot 15.11.1

## Dashboard information architecture (15.11.1)

The dashboard uses a premium warm-light design system with responsive workspace surfaces, accessible focus states and reduced-motion support. A searchable command palette provides workspace navigation and operator shortcuts. The device dossier can be exported locally as JSON after explicit privacy confirmation.

The dashboard presents five workspaces: Command Centre; Devices & Identity; Network Activity; Network Control; and Security & Investigations. Endpoint-agent and SSH management are grouped with Devices & Identity. The local intelligence assistant and reports are grouped with Security & Investigations. These are navigation groupings only: underlying modules, APIs, persisted records and safety gates remain unchanged.

## 13.5.0 scan observability and unknown-device guidance

The scan worker creates an in-memory `ScanProfiler` for each run. Named phases
accumulate wall-clock duration, call count, maximum/last duration and error
type. The latest completed or partial snapshot is available at
`GET /api/scan_performance` and is rendered in the Command Centre. Profiling
does not persist packet payloads, credentials or raw exception text.

Unknown Device Hunter uses `build_identity_next_steps` to explain missing
identity evidence and rank operator actions. This is advisory only: it never
initiates a network probe. Active-discovery recommendations are conditioned
on the current network's explicit authorisation state. Exact hardware model
claims remain evidence-backed and are not inferred from OUI or port numbers.

## Runtime overview

The application runtime is still centred on `networkradar.py`. It retains schema setup, network-context detection, discovery orchestration, passive capture engines, identity enrichment and persistence, intelligence workflows, the local HTTP API and application lifecycle. The migration to modules is incremental; the full application has not been split into independent services.

The dashboard markup lives in `index.html`; its responsive stylesheet and browser client live in `networkradar.css` and `dashboard.js`. The Python server reads the HTML template, substitutes the application version and serves the assets locally.

## Reusable modules

- `discovery.scan_budget` — adaptive TCP/OS and UDP deep-scan budgets with per-host and whole-process limits.

The `networkradar_modules` package contains components now used by the running application:

- `identity.fusion` — evidence-weighted identity scoring, source-independence caps, freshness decay, conflict detection and conservative merge decisions.
- `identity.dhcp` — conservative interpretation of DHCP vendor-class identifiers, hostnames and parameter-request lists. It produces explainable client-family/network-role hints and preserves PRL option names without treating overlapping option patterns as definitive OS or hardware identity.
- `core.startup` — OS-managed single-instance locking and bind-first local-server binding. The application delegates its startup lock and server binding to this module.
- `database.manager` — serialized SQLite writer queue, short-lived read connections, write batching and database-writer health state. The application uses this as its `DatabaseManager`.
- `diagnostics.status` — normalises engine status records; the application imports this helper for engine-health reporting.
- `discovery.nmap` — bounded Nmap host-discovery execution and Nmap XML parsing. The runtime supplies the current network scope, executable and diagnostic log path.
- `discovery.arp` — local ARP cache collection and Windows-style ARP output parsing.
- `discovery.adapters` — pure helpers for MAC normalisation, Windows IPv4 interface selection, default-route metric selection and exact TShark interface matching.
- `discovery.classification` — pure device-family classification using observed names, services, reported details, port observations and an explicitly supplied gateway address.
- `discovery.probes` — reverse-DNS and NetBIOS name probes, SSDP discovery and same-host validation for UPnP description URLs. Active SSDP multicast is bound to the selected workspace adapter, replies are restricted to the approved subnet, and redirects are rejected unless they remain on the same responding private host.
- `discovery.mdns` — bounded active mDNS/DNS-SD PTR browsing and defensive parsing of PTR, SRV, TXT, A and AAAA records. It requests unicast replies, limits query/packet volume, binds to the selected workspace IPv4 and rejects responders outside the approved subnet. It never follows advertised URLs.

All active operations require a fresh authorised network-context snapshot. Per-device reverse-DNS, NetBIOS, TLS certificate, SNMPv3, HTTP service metadata, deep Nmap fingerprinting and agentless management require a literal target address inside the currently approved private subnet. Endpoint-agent enrolment, reports and command delivery are likewise restricted to the approved subnet; loopback is allowed only when the agent hub is bound to loopback or an unspecified address. A device remaining in historical inventory is not, by itself, permission to probe or manage its old address.

The discovery package currently owns reusable collectors, parsers, selectors and classification logic. During the first and every fifth inventory cycle, NetworkRadar combines passive TShark mDNS observations with an approval-gated, rate-bounded active DNS-SD browse. Active results are associated by responder IP and treated as device-reported service evidence, not proof of an exact hardware model. The higher-level inventory workflow remains in `networkradar.py`: it coordinates Nmap, ARP, local identity, SSDP/mDNS, deeper fingerprinting, identity assessment and database persistence. This is deliberate so each next extraction can be tested against the existing orchestration without changing its API or stored data shape.

## Application layers

1. **Runtime and persistence** — application lifecycle, configuration, SQLite schema compatibility and append-only observations. The database writer is modular.
2. **Network context and authorisation** — adapter, subnet, gateway and network-fingerprint detection; active discovery and management are gated by a matching approved profile. When multiple adapters have default routes, the adapter with the lowest effective route metric is selected.
3. **Discovery and observation** — Nmap inventory, ARP cache observations, DNS/DHCP/ARP capture, TShark adapter selection and supplementary local-network observations.
4. **Identity and intelligence** — device identity evidence, continuity, behaviour, exposure observations, alert correlation and investigations.
5. **Management integrations** — optional SSH sessions, agentless Windows management and an opt-in TLS agent hub.
6. **Local interface** — HTTP API and dashboard intended to bind to loopback.

## Network approval freshness

A profile's routine `last_seen` timestamp is updated during network detection and therefore must not be used as the age of the user's approval. The authorisation policy evaluates `last_authorized`, fails closed when that value is missing or malformed, rejects materially future-dated approvals and requires re-approval after `PROFILE_MAX_AGE_DAYS`.

The `last_authorized` field is maintained through the application's additive schema-column migration path. Existing databases should be backed up before upgrading.

## Identity fusion

The main application's PHANTOM TRACK entry point delegates to `networkradar_modules.identity.fusion.score_evidence`. DHCP interpretation is handled by `identity.dhcp`: explicit vendor-class tokens (for example Android DHCP, Microsoft, BusyBox/udhcp, dhcpcd, PXEClient and iPXE) create bounded, explainable hints. Parameter-request-list values are decoded and retained as observable features, but are not independently mapped to an operating system because common option combinations overlap across client implementations. DHCP values are client-supplied and spoofable; they never establish an exact hardware model. Evidence from one independence group is capped; stale evidence decays; conflicting strong identity attributes produce `CONFLICTING_IDENTITY`; locally administered MAC observations are not valid merge anchors; and only a `CONFIRMED_MATCH` outcome can be auto-merge eligible.

Malformed timestamps are ignored as evidence. Materially future-dated observations receive no freshness credit.

## Local API and remote management

The packet-capture interface selector matches the selected Windows adapter by interface GUID, then adapter name/description, rather than blindly selecting the first Wi-Fi device. An explicit TShark interface override remains available. The main dashboard server is configured for loopback. Its request handler validates the Host header and, when present, the Origin header. The optional agent hub is a separate TLS listener, disabled unless explicitly enabled and configured with a certificate and private key. Its enrolment response provides a per-agent derived HMAC key; the server-wide pepper is never sent to endpoints. Enrolment, command polling and command queuing are blocked unless the current network profile is authorised.

Version 12.3.0 adds a separately packaged, inventory-only Windows endpoint client with certificate pinning, DPAPI-protected credentials, signed inventory reports and revocation support through the existing hub. The supplied client intentionally does not implement remote command execution; legacy server-side command capabilities remain available only to agents that explicitly advertise the required capability. The endpoint client/server lifecycle still requires a real Windows LAN enrolment and revocation smoke test.

Remote SSH and Windows-management functions are high-impact features. Their host validation, credentials, authorisation, confirmation gates, audit events and transport protections require ongoing security review. The localhost dashboard does not provide per-user login/authentication. Any local account or process able to connect to the loopback port may be able to reach its APIs. Treat it as a single-user workstation application, not a multi-user security boundary.


## Authenticated endpoint inventory (12.3.0)

The optional `agent/networkradar_agent.py` client provides an endpoint-reported hardware inventory for Windows computers that an administrator explicitly enrols. It is separate from network fingerprint inference. The client collects Windows CIM information (system manufacturer/model/family, CPU, memory, BIOS, disks, OS build and network adapters) and sends it to the existing agent hub.

The agent hub remains disabled by default and requires a configured TLS certificate/private key plus current network authorisation. The endpoint validates a configured SHA-256 pin of the presented DER leaf certificate before sending any HTTP request. Enrolment consumes a single-use, 15-minute token. Subsequent reports are authenticated using the per-agent HMAC key, timestamp and nonce; the server rejects invalid signatures, stale timestamps and replayed nonces. The endpoint stores its configuration encrypted with Windows DPAPI for the current user.

The supplied client advertises only the `inventory-report` capability. It does not poll the command queue and contains no remote command executor. The server stores an allowlisted capability set per agent, checks it before queuing a command, and filters unsupported queued actions before delivery. Legacy clients that omit the capability field retain the historical capability set for compatibility; new clients should always advertise their implemented capabilities.

The device dossier associates a non-revoked agent inventory by the server-observed source IP or a matching endpoint network-adapter MAC; hostname alone is never used as a join key. Endpoint-reported manufacturer/model and hardware details are displayed separately from network-derived identity assessments. They are stronger evidence of exact hardware than MAC OUI or port-based guesses, but remain self-reported by the endpoint and do not prove firmware integrity or resistance to a compromised host. Serial numbers are omitted unless the endpoint operator explicitly enables `--include-serial`.

The client does not install itself as a service or configure persistence. It must be run manually or placed in a separately reviewed Task Scheduler job by the endpoint administrator. The hub should bind to a specific LAN address and be protected by a firewall allowlist; it must not be exposed to the public internet.

## Data layout

The application creates local `data/` and `database/` directories. Runtime databases, scan outputs, packet captures, trust stores, tokens, certificates and other local state must remain outside version control. No live database is included in the source repository.

## Testing boundaries

The standard-library test suite covers isolated startup, database, identity, diagnostics, discovery parsing, adapter selection and classification behaviour, plus application-level regression checks. These tests do not establish that every API route, capture engine, Nmap/TShark integration, Windows remoting operation, or browser workflow is correct. Those require Windows integration and end-to-end tests.


### Structured Nmap OS fingerprint evidence

The deep Nmap service scan retains the highest-ranked `osmatch` together with
its Nmap match accuracy and any associated OS class/CPE observations. The
dashboard-facing `os_guess` remains a readable summary, while
`nmap_os_fingerprint` preserves the structured evidence for downstream
correlation. Nmap accuracy is explicitly a fingerprint-match score, not a
calibrated probability. OS fingerprints do not identify an exact device model,
and missing or malformed accuracy values are handled conservatively.


### IEEE MAC address-block intelligence

The identity package parses the IEEE MA-L, MA-M and MA-S public registries and
matches the most-specific assigned prefix (24, 28 or 36 bits). MA-M and MA-S
are not treated as ordinary 24-bit OUIs. The device profile retains the
assignment registry, prefix, prefix length, record update timestamp and registrant as provenance.
Locally administered and multicast MAC addresses are not attributed to a
global IEEE registrant. The registrant is labelled as an address-block
assignee, not asserted to be the device manufacturer; exact product identity
must come from independent device-reported or authenticated inventory data.


Device-category signatures are constrained to compatible evidence families.
For example, IEEE address-block registrants can enrich NIC attribution but
cannot independently satisfy product, OS, service-role or device-reported
identity rules. Product signatures may use explicit Nmap product, SNMP,
UPnP or DNS-SD product evidence; OS signatures use OS/passive TCP evidence;
DHCP signatures use DHCP observations. This prevents a NIC vendor such as an
adapter or chipset supplier from being mistaken for the device itself.


## Multi-network workspace foundation (12.2.0)

The workspace layer introduces a stable opaque network_id distinct from a CIDR/subnet and from a single observed fingerprint. network_fingerprint_history maps exact fingerprints to workspace IDs; network_interface_observations stores interface-specific snapshots; network_device_sightings stores device presence keyed by workspace plus IP and device identity. These tables are additive and do not rebuild or delete legacy tables.

Network detection now gathers each active IPv4 adapter independently. Route metrics, gateway-neighbour lookups scoped by interface index, DNS, DHCP and WLAN SSID/BSSID are collected per adapter. The default-route metric still selects the primary adapter for the existing active-discovery loop. Other interfaces are recorded as observations only; this release does not run concurrent active scans on them.

A fingerprint is a snapshot key, not a guaranteed permanent identity. Exact fingerprints reuse a workspace. A changed fingerprint currently creates a separate workspace pending future correlation or explicit merge. This avoids silently joining two networks merely because they share a subnet or SSID.

Active discovery now also requires a strong fingerprint anchor: a gateway MAC or interface-specific BSSID. Subnet, gateway IP, DNS, DHCP and SSID alone cannot authorise active discovery, even if their combined weight passes the older numeric threshold.

Authorisation authority now lives in network_workspace_authorizations, keyed by network_id plus fingerprint. A new workspace fingerprint starts unapproved. Existing legacy approval flags are not imported into this table because they may have been inherited by a different network sharing the same subnet; users must reapprove each network once after this migration. The legacy network_profiles table remains subnet-keyed for compatibility and is no longer authoritative for active-discovery permission. Its upsert now resets approved and last_authorized whenever the fingerprint changes. This is fail-closed and prevents approval transfer between different networks that reuse the same CIDR. The dashboard workspace selector is a historical read-only browser; it does not change the active scan target or authorisation context.

Legacy devices remains IP-keyed, and many historical event/telemetry queries are not yet workspace-scoped. New sightings are recorded separately to provide a safe foundation for the later full data-scope migration. Do not interpret this milestone as complete multi-network concurrent scanning.


## 13.7.0 dashboard presentation layer

The dashboard continues to use the standalone `index.html`, `networkradar.css` and `dashboard.js` assets. Version 13.7.0 adds an additive CSS consistency layer for visible keyboard focus, constrained grid children, horizontally scrollable data tables, touch interaction and broad reduced-motion handling. It does not alter dashboard APIs, scan scheduling, network authorisation, identity scoring or database storage.


## Network Control Engine (15.0.0)

The optional router-control subsystem is isolated under `networkradar_modules/control/`. Its first adapter targets MikroTik RouterOS 7+ through the HTTPS REST API. The REST client requires certificate verification, refuses redirects, uses bounded timeouts and exposes only fixed resource operations; arbitrary RouterOS console commands are not exposed.

Router credentials remain in process memory and are not written to SQLite, logs or the browser. The connection is bound to the exact currently authorised private IPv4 subnet. Every mutating API route refreshes the live Windows network context and checks the current authorisation again. New device restrictions additionally require an ONLINE inventory record. The dashboard remains loopback-only.

Bandwidth limits use one RouterOS Simple Queue per device. Upload/download ordering is translated explicitly, and FastTrack presence is reported because FastTrack can bypass Simple Queues. Existing FastTrack rules are never changed automatically.

Timed pauses use dedicated NetworkRadar-owned IPv4/IPv6 firewall address lists with RouterOS timeouts. A managed forward-chain drop rule is inserted before existing forward rules and matches only LAN-to-WAN traffic. This preserves local LAN communication and access to router management. IPv6 pauses use currently observed global device addresses or global prefixes assigned to the LAN interface that owns the currently authorised IPv4 subnet. If dual-stack coverage cannot be established, an IPv4-only action requires a separate explicit acknowledgement. IPv6 privacy-address rotation remains a coverage limitation.

Emergency restore removes only address-list entries, queues and firewall rules with exact NetworkRadar-owned comments. It does not reset the router, alter interface lists, disable FastTrack, or delete unrelated administrator policies. RouterOS is the only enabled control adapter in this release; other router brands are not guessed or modified.
