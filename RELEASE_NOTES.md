# NetworkRadar 12.4.0 — Strong Network Anchor Detection Fix

## Delivered

- Fixed gateway MAC discovery on Windows. The previous implementation passed `-IPAddress` to `Get-NetNeighbor`, which is not a supported parameter; PowerShell returned an error and the helper silently treated the gateway MAC as missing.
- Gateway-neighbour collection now queries only the selected default-route interface, then filters returned neighbour records against the exact gateway IP and interface index. Existing unicast-MAC and Reachable/Stale/Permanent state checks remain in place.
- Fixed Wi-Fi BSSID extraction from real Windows output. `netsh wlan show interfaces` reports the access point address using the label `AP BSSID`; the parser previously accepted only `BSSID`.
- Added regression coverage for the actual `AP BSSID` output shape, strong-anchor recognition and the supported `Get-NetNeighbor` query form.
- No authorisation checks were weakened. Active discovery still requires a valid interface-specific gateway MAC or connected BSSID, sufficient fingerprint confidence and explicit fresh approval.

## Expected result on the reported laptop

The supplied diagnostics show:
- Active interface: `Wi-Fi`, interface index `8`.
- Default gateway: `192.168.100.1`.
- Gateway MAC: `F4-A4-D6-17-32-72`, state `Reachable`, interface index `8`.
- Connected SSID: `Andrew`.
- Access-point BSSID: `B0:19:21:4A:14:6F`.

Both the gateway MAC and BSSID are valid unicast anchors. After this fix, NetworkRadar should be able to observe at least one of them on this interface. The real Windows application must still be restarted and its runtime result verified locally.

## Validation boundary

Automated regression tests cover the corrected PowerShell query construction and actual WLAN parser output. CI must pass before merge. A live Windows re-run using the user-provided adapter remains necessary to confirm the complete runtime path.

---
# NetworkRadar 12.3.0 — Authenticated Endpoint Inventory

## Delivered

- Added an opt-in Windows endpoint inventory client at `agent/networkradar_agent.py`.
- Added read-only CIM collection for manufacturer, exact system model/family, CPU, physical memory, BIOS version, disks, OS version/build/architecture and network adapters.
- Serial numbers are excluded by default and are collected only when the operator explicitly supplies `--include-serial`.
- Added HTTPS leaf-certificate SHA-256 pinning. The agent verifies the configured pin before sending the HTTP request, including during enrolment, and supports verified pin rotation after a certificate renewal.
- Added single-use token enrolment using the existing 15-minute enrolment-token flow.
- Added signed inventory reports using the existing per-agent HMAC protocol, timestamp validation and replay-resistant nonce handling.
- Agent credentials are stored using Windows DPAPI for the current Windows user; the enrolment token is prompted for and is not persisted.
- Added per-agent capability allowlisting. The supplied client advertises only `inventory-report`; the server blocks unsupported command queueing and filters unsupported commands before delivery.
- Linked the latest non-revoked endpoint inventory to the device dossier by observed source IP, with hostname as a secondary association clue.
- Added a hardware dossier section that distinguishes authenticated endpoint-reported inventory from network-derived guesses.
- Added protocol, URL-validation, certificate-pin, HMAC and capability-boundary regression tests.
- Documented secure LAN deployment, certificate pin generation, enrolment, reporting and serial-number opt-in in `agent/README.md`.

## Security and privacy boundaries

- The endpoint agent is inventory-only. It does not poll the remote command queue, execute remote commands, install a service or modify endpoint settings.
- The hub remains disabled by default, requires TLS configuration and current network authorisation, and should be bound to a specific LAN address with a firewall allowlist.
- The endpoint validates a pinned certificate before transmitting data. A changed certificate causes a fail-closed error.
- Per-agent credentials are DPAPI-protected on the endpoint and HMAC-authenticated on every report.
- Exact hardware details are device-reported inventory, not proof against a compromised endpoint or malicious firmware.
- Serial-number collection is explicitly opt-in.

## Validation boundary

Automated CI checks syntax, unit tests, dashboard JavaScript and protocol helpers. A real Windows deployment, TLS certificate pin exercise, endpoint enrolment and hardware-inventory smoke test still need to be performed on the user's authorised LAN before production use.

---

# NetworkRadar 12.2.0 — Multi-Network Intelligence foundation

## Delivered

- Added stable opaque network workspace IDs separate from subnet strings.
- Added fingerprint-to-workspace history so distinct networks sharing a subnet remain separately represented.
- Added append-only interface observations and network-scoped device sightings without replacing legacy IP-keyed inventory.
- Enumerates each active IPv4 adapter independently and records interface name, GUID, description, media type, IP/subnet, route metric, gateway, gateway MAC, DNS, DHCP, Wi-Fi SSID/BSSID and interface classification.
- Parses multiple Windows WLAN interface blocks separately.
- Added a dashboard Network Workspaces explorer with a workspace selector, interface history and device-sighting view.
- Added read-only API routes for workspace directory, interface observations and workspace device sightings.
- Fixed a security-critical issue: when a subnet-keyed legacy profile receives a different fingerprint, its approval and approval timestamp are reset. A different network sharing the subnet cannot inherit approval.
- Tightened active-discovery authorisation to require an observed gateway MAC or interface-specific BSSID. A high score based only on subnet, gateway IP, DNS, DHCP or SSID is not enough to authorise a network.
- Moved approval authority to a network-workspace-and-fingerprint keyed table. Newly migrated workspaces start unapproved and require one-time reapproval; legacy subnet-keyed approval flags are no longer trusted for active discovery.
- Preserved existing database tables and records; workspace tables and indexes are additive.

## Upgrade note

After upgrading to 12.2.0, re-authorise each network you intend to scan. The new workspace-specific approval records intentionally start unapproved because older subnet-keyed approvals cannot be safely attributed when multiple networks share an address range.

## Important boundaries

- Active scanning and authorisation remain bound to the current primary network. Selecting a historical workspace is browse-only.
- Exact fingerprint matches reuse a workspace. Fingerprint drift currently creates a separate workspace; no automatic merge is attempted.
- Legacy device inventory remains IP-keyed. Network-scoped sightings are recorded separately, but full migration of every event, DNS, DHCP, alert, investigation and device query to workspace scope is a subsequent milestone.
- This is not concurrent active scanning across all adapters.
- No live Windows adapter, Nmap/TShark or browser smoke test has yet been performed for this commit.

## Validation status

Automated tests have been added for overlapping subnets, workspace reuse, missing fingerprints, WLAN parsing, interface classification, network-scoped interface observations and approval isolation. CI status and the full repository test run remain to be confirmed.

---

## Previous release notes



This file records the current repository snapshot's declared application version and the fixes prepared on the audit branch. It is not a claim that the full Windows application has passed end-to-end testing.

## Fixes in this audit branch

- Corrected primary network adapter selection to use the lowest effective Windows default-route metric, and bound TShark capture to that adapter by GUID/name/description. This prevents multi-adapter and hotspot sessions from silently capturing a different interface.
- Connected the production PHANTOM TRACK scorer to the tested `networkradar_modules.identity.fusion` implementation. The previous embedded scorer ignored conflict kinds and auto-merge policy, always reported `auto_merge_allowed: false`, and iterated thresholds in a way that could downgrade a confirmed match to a weaker label.
- Restored strong-identity conflict detection and the intended rule that only `CONFIRMED_MATCH` can be auto-merge eligible.
- Hardened identity evidence handling: blank values no longer create false conflicts, malformed timestamps are ignored, and materially future-dated evidence receives no freshness credit.
- Stop using locally administered/randomised MAC addresses as durable cross-IP device identity keys; retain same-IP continuity without treating the randomised address as a merge anchor.
- Removed disclosure of the server-wide agent HMAC pepper during enrolment; endpoints receive only their own derived authentication key.
- Gated agent-hub startup, endpoint enrolment, command polling and command queuing on current network authorisation.
- Corrected network approval expiry. Routine `last_seen` refreshes previously made old approvals appear fresh indefinitely. Authorisation now uses `last_authorized`, fails closed for missing/invalid/future timestamps, and requires re-approval after the configured 90-day period.
- Added a row-count check so a missing current network profile cannot be reported as successfully authorised.
- Made `networkradar_modules/__init__.py` the single source of the application version.
- Added the optional SSH dependency manifest referenced by the application.
- Extracted the dashboard markup, stylesheet and JavaScript from the Python monolith into `index.html`, `networkradar.css` and `dashboard.js`; the local server now reads and serves these assets directly. This removes roughly 86 KB of presentation code from `networkradar.py`.
- Consolidated repeated CSS foundation variables and duplicate mobile rules, then formatted the stylesheet into readable sections without changing the visual design tokens.
- Removed all 48 static inline style attributes from `index.html`; reusable layout, spacing, progress, toast and visibility styles now live in the external stylesheet. Runtime-controlled styles remain managed by the dashboard client.
- Updated installation, data-safety, version and architecture documentation to match the actual repository layout.
- Added application-level regression tests for identity scoring and approval freshness.

## Discovery-engine modularisation

The discovery refactor has begun without changing the public application entry points or device-record shape:

- Extracted Nmap host-discovery execution and XML parsing into `networkradar_modules/discovery/nmap.py`. The application supplies its current network scope, Nmap executable and log path.
- Extracted local ARP cache collection and Windows-compatible output parsing into `networkradar_modules/discovery/arp.py`.
- Extracted MAC normalisation, usable IPv4 selection, default-route adapter selection and TShark interface matching into `networkradar_modules/discovery/adapters.py`.
- Extracted device-family inference into `networkradar_modules/discovery/classification.py`. The helper is now independent of application locks and receives the gateway address explicitly.
- Extracted reverse-DNS, NetBIOS and SSDP probes into `networkradar_modules/discovery/probes.py`.
- Hardened SSDP description retrieval: the advertised URL must point to the responding private host, and HTTP redirects are revalidated to prevent a device from redirecting the fetch to another host or metadata endpoint.
- Added isolated tests for scanner execution, XML parsing, ARP parsing, interface selection and device classification.

The higher-level inventory orchestration, multi-source enrichment and database persistence remain in `networkradar.py` for the next refactor stage.

## Known limitations still under audit

- The application remains largely monolithic; startup and diagnostics helpers in the package are not yet the runtime's single source of truth.
- The repository contains the endpoint-agent hub server but no separately packaged endpoint-agent client/installer.
- Windows PowerShell, Nmap, TShark, packet capture, browser and remote-management integration tests must still be run on a Windows host.
- A complete route-by-route security review of the HTTP API, WebSocket bridge, SSH trust store, agent HMAC protocol and remote action flows remains in progress.
- No production-readiness claim is made.
