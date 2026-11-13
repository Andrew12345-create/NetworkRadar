# NetworkRadar architecture — repository snapshot 12.0.3

## Runtime overview

The application runtime is still centred on `networkradar.py`. It retains schema setup, network-context detection, discovery orchestration, passive capture engines, identity enrichment and persistence, intelligence workflows, the local HTTP API and application lifecycle. The migration to modules is incremental; the full application has not been split into independent services.

The dashboard markup lives in `index.html`; its responsive stylesheet and browser client live in `networkradar.css` and `dashboard.js`. The Python server reads the HTML template, substitutes the application version and serves the assets locally.

## Reusable modules

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
- `discovery.probes` — reverse-DNS and NetBIOS name probes, SSDP discovery and same-host validation for UPnP description URLs. Redirects are rejected unless they remain on the same responding private host.
- `discovery.mdns` — bounded active mDNS/DNS-SD PTR browsing and defensive parsing of PTR, SRV, TXT, A and AAAA records. It requests unicast replies, limits query/packet volume, binds to the selected local IPv4 where available, and never follows advertised URLs.

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

The endpoint-agent hub code is present, but this repository snapshot does not include a separately packaged endpoint-agent client/installer. Treat the client/server lifecycle as incomplete until the client is added, its certificate-pinning and request-signing protocol are documented, and the complete enrol/report/command/revocation flow is tested.

Remote SSH and Windows-management functions are high-impact features. Their host validation, credentials, authorisation, confirmation gates, audit events and transport protections require ongoing security review. The localhost dashboard does not provide per-user login/authentication. Any local account or process able to connect to the loopback port may be able to reach its APIs. Treat it as a single-user workstation application, not a multi-user security boundary.

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
assignment registry, prefix, prefix length and registrant as provenance.
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
