# NetworkRadar architecture — repository snapshot 12.0.3

## Runtime overview

The current runtime is centred on `networkradar.py`, which contains the application lifecycle, database manager, schema setup, network-context detection, discovery orchestration, passive capture engines, intelligence workflows, local HTTP API and dashboard. It is still a large monolithic file; a complete extraction into smaller services has **not** been completed.

The dashboard markup now lives in `index.html`; the responsive stylesheet and browser client live in `networkradar.css` and `dashboard.js`. The Python server reads the HTML template, substitutes the application version and serves the three assets locally. This keeps presentation and browser code out of the main Python file.

The dashboard's HTML template remains in the Python runtime, while its responsive stylesheet and browser client are standalone `networkradar.css` and `dashboard.js` files. The local HTTP server serves both through `/assets/` routes with no-store caching. This keeps presentation and browser behaviour out of the Python application source and makes each asset independently testable.

The `networkradar_modules` package contains reusable components:

- `identity.fusion` — evidence-weighted identity scoring, source-independence caps, freshness decay, conflict detection and conservative merge decisions. The application now calls this module directly.
- `core.startup` — independently tested OS-managed locking and bind-first local-server helpers. The application currently retains embedded startup implementations; this module is not yet the runtime's single source of truth.
- `diagnostics.status` — engine-state normalisation helper with unit tests. The application currently retains an embedded equivalent; extraction/integration remains future work.

This distinction is intentional: a module existing in the repository does not mean the running application imports or uses it. The identity scorer is integrated; startup and diagnostics still need consolidation.

## Application layers

1. **Runtime and persistence** — application configuration, SQLite database manager, schema compatibility and append-only observations.
2. **Network context and authorisation** — adapter, subnet, gateway and network-fingerprint detection; active discovery and management are gated by a matching approved profile. When multiple adapters have default routes, the adapter with the lowest effective route metric is selected.
3. **Discovery and observation** — Nmap inventory, DNS/DHCP/ARP capture and supplementary local-network observations.
4. **Identity and intelligence** — device identity evidence, continuity, behaviour, exposure observations, alert correlation and investigations.
5. **Management integrations** — optional SSH sessions, agentless Windows management and an opt-in TLS agent hub.
6. **Local interface** — HTTP API and dashboard intended to bind to loopback.

## Network approval freshness

A profile's routine `last_seen` timestamp is updated during network detection and therefore must not be used as the age of the user's approval. The authorisation policy now evaluates `last_authorized`, fails closed when that value is missing or malformed, rejects materially future-dated approvals and requires re-approval after `PROFILE_MAX_AGE_DAYS`.

The `last_authorized` field is maintained through the application's additive schema-column migration path. Existing databases should be backed up before upgrading.

## Identity fusion

The main application's PHANTOM TRACK entry point delegates to `networkradar_modules.identity.fusion.score_evidence`. Evidence from one independence group is capped; stale evidence decays; conflicting strong identity attributes produce `CONFLICTING_IDENTITY`; locally administered MAC observations are not valid merge anchors; and only a `CONFIRMED_MATCH` outcome can be auto-merge eligible.

Malformed timestamps are ignored as evidence. Materially future-dated observations receive no freshness credit.

## Local API and remote management

The packet-capture interface selector now matches the selected Windows adapter by interface GUID, then adapter name/description, rather than blindly selecting the first Wi-Fi device. An explicit TShark interface override remains available. The main dashboard server is configured for loopback. Its request handler validates the Host header and, when present, the Origin header. The optional agent hub is a separate TLS listener, disabled unless explicitly enabled and configured with a certificate and private key. Its enrolment response provides a per-agent derived HMAC key; the server-wide pepper is never sent to endpoints. Enrolment, command polling and command queuing are blocked unless the current network profile is authorised.

The endpoint-agent hub code is present, but this repository snapshot does not include a separately packaged endpoint-agent client/installer. Treat the client/server lifecycle as incomplete until the client is added, its certificate-pinning and request-signing protocol are documented, and the complete enrol/report/command/revocation flow is tested.

Remote SSH and Windows-management functions are high-impact features. Their host validation, credentials, authorisation, confirmation gates, audit events and transport protections require ongoing security review. The localhost dashboard does not provide per-user login/authentication. Any local account or process able to connect to the loopback port may be able to reach its APIs. Treat it as a single-user workstation application, not a multi-user security boundary.

## Data layout

The application creates local `data/` and `database/` directories. Runtime databases, scan outputs, packet captures, trust stores, tokens, certificates and other local state must remain outside version control. No live database is included in the source repository.

## Testing boundaries

The standard-library unit tests cover selected helper behaviour. They do not establish that every API route, capture engine, Nmap/TShark integration, Windows remoting operation, SSH interaction or browser workflow is correct. Those require Windows integration and end-to-end tests.
