# NetworkRadar 13.1.1 — Windows Dashboard Port Binding

## Startup reliability
- Diagnoses Windows `WSAEACCES` / error 10013 bind failures and checks IPv4 and IPv6 TCP excluded-port ranges with `netsh` when available.
- Explains that Windows can reserve a TCP port even when `Get-NetTCPConnection` shows no listening process.
- Uses direct bind attempts rather than a check-then-bind probe, and closes partially-created HTTP server sockets after bind or activation failures.
- Preserves the existing security/operational policy: port 8766 remains authoritative; alternate ports are considered only with explicit `--allow-alt-port` consent.
- Adds regression tests for strict port selection, explicit alternate selection, cleanup, invalid ranges and Windows excluded-port diagnostics.

# NetworkRadar 13.1.0 — Identity Coverage and Operational Health

## Identity evidence
- Uses observed inventory/device names when DHCP hostname fields are absent.
- Filters generic database defaults such as `Unidentified device` and `Unclassified device` from identity evidence and evidence-coverage metrics.
- Replaces those generic display labels after a device is successfully classified, including case-insensitive legacy labels.
- Recognises computer-name, NetBIOS-name, DHCP-hostname and mDNS-hostname fields as one bounded reported-name evidence family.
- Filters generated unidentified-device labels and IP-address placeholders so the application does not manufacture identity evidence.
- Preserves conservative thresholds: a ThinkPad-like inventory name can support a laptop/computer hardware-class hypothesis without inferring Windows or an exact model.

## Operational health
- Reworks scan quality into a 100-point score with explicit component breakdown and a scan-recency component, so an old scan cannot receive full freshness credit.
- Separates discovery/telemetry quality from identity coverage; a high host-discovery score can no longer imply that most devices are identified.
- Reports inventory total, classified/unclassified counts, identity coverage percentage and average confidence; excludes legacy `Unclassified device`, `Unidentified device`, `Unknown` and `Ambiguous:` labels from classified totals.
- Marks identity coverage unavailable rather than displaying a false 0% when the backing query fails.
- Makes the status summary endpoint tolerant of individual optional-query failures and exposes the errors while preserving the rest of the dashboard status.
- Dashboard distinguishes connected/partial status from a complete API outage and displays identity coverage beside scan quality.

## Data safety and validation
- No destructive database migration.
- No device records, history, credentials or packet captures are deleted.
- Existing API fields are retained; new status and scan-quality fields are additive.
- Automated tests cover inventory-name fallback, rejection of generated placeholder names, legacy classification labels, exact 100-point scoring, scan freshness and unavailable identity metrics.
- A live Windows/TShark/browser run is still required to confirm local capture and API behaviour.

---

# NetworkRadar 13.0.0 — Evidence-fused Device Intelligence

## Identity engine
- Replaces additive MAC/hostname confidence with independent evidence-family scoring.
- Caps repeated observations from the same family to prevent confidence inflation.
- Ranks device-family hypotheses and retains close competitors as ambiguous instead of forcing a category.
- Separates device-reported manufacturer/model from the IEEE NIC address-block registrant.
- Uses explicit DHCP Android vendor-class evidence where present; hostnames alone remain low-confidence clues.
- Google Cast DNS-SD is reported as a media receiver/streamer capability, not proof of an Android phone or television.
- Exact model/manufacturer fields are populated only from explicit endpoint/service-reported model fields.

## Deep discovery
- Adds selected Nmap safe/discovery scripts for SMB OS discovery and TLS certificate metadata during deep TCP scans.
- Adds a bounded targeted UDP pass for common NetBIOS, SNMP, UPnP, WS-Discovery and mDNS ports.
- Adds safe UPnP and DNS-SD Nmap script observations to the identity evidence graph.
- Captures script IDs, outputs, TCP/UDP service details and scan collection notes.

## Dashboard
- Adds an evidence-fused profile panel with selected category, source-family diversity, OS-family candidates, ranked hypotheses, TCP/UDP ports and script coverage.
- Keeps the existing dossier and API field contracts.

## Confidence and history safeguards
- Weak shallow scans do not erase the last strong persisted profile.
- New strong classifications replace old scores; weak evidence does not inflate or overwrite confidence.
- Port-only and OUI-only clues remain contextual and cannot assert device type or model.

## Validation boundary
- Automated CI must pass on Python 3.10–3.13.
- Real Windows/Nmap/Npcap/TShark scans are still required to validate network visibility and script behaviour.
- Client isolation, VLANs and missing DHCP renewals can still limit visibility. Router/AP association integration remains the highest-value next step for Wi-Fi clients.

---

# NetworkRadar 12.9.0 — Multi-source ARP and DHCP Capture Compatibility

## Discovery improvements
- Explicit Nmap ARP host discovery (-PR) on the selected authorised local subnet.
- Reverse DNS disabled during the host sweep to avoid resolver delays; host enrichment remains separate.
- Windows IPv4 neighbour cache supplement, scoped to the selected subnet.
- Only Reachable neighbour entries can add a device to the current online inventory.
- Stale, incomplete, multicast, invalid, out-of-subnet and conflicting neighbour rows are rejected or retained as conflicts without overwriting the Nmap observation.
- Locally administered MAC addresses are labelled as potentially randomized or locally assigned, never as stable hardware identities.

## DHCP capture reliability
- TShark field registry is inspected at startup.
- Logical DHCP fields resolve against DHCP or legacy BOOTP field abbreviations.
- Missing optional fields are reported and safely left blank; required-field gaps produce an actionable startup error.
- DHCP row positions remain stable when optional fields are absent.

## Safety and limitations
- No attempt is made to recover factory MAC addresses.
- No identity merge is based solely on randomized MAC, OUI, hostname resemblance, TTL, or generic TCP/IP fingerprints.
- Router/AP association-table integration remains vendor-specific and requires an explicitly configured read-only interface.
- Client isolation and VLAN segmentation can still hide peers from a laptop-based scanner.

## Validation
- Added unit tests for neighbour parsing, scope/state filtering, randomized MAC handling, conflict preservation, and TShark field compatibility.
- CI validation is required before merge; live Windows/TShark and physical Wi-Fi smoke tests remain necessary.


## Delivered

- Extends the live TShark DHCP collector with DHCP option 93 (Client System Architecture), option 77 (User Class) and option 81 (Client FQDN).
- Adds additive SQLite columns for the new observations; existing DHCP event records and local databases are preserved.
- Parses known RFC 4578 option 93 architecture IDs into readable PXE/pre-boot labels and retains unknown numeric IDs as unknown observations.
- Explicitly prevents option 93 from being interpreted as the installed operating system, device model or manufacturer.
- Adds DHCP evidence to the identity dossier and exposes the new fields in the device detail DHCP history.
- Deliberately does not collect option 97's stable machine GUID by default.
- Adds unit tests for architecture parsing, unknown values, metadata preservation and conservative interpretation.

## Validation boundary

Automated unit tests and GitHub Actions must pass before merge. A live Windows/TShark smoke test is still required to confirm that the installed Wireshark build exposes the selected fields and that DHCP packets on the user's active adapter contain these options. Many ordinary clients will not send PXE option 93 or user class data; empty fields are expected and do not indicate a capture failure.

---

# NetworkRadar 12.5.0 — NIGHTWATCH Command Centre

## Delivered

- Adds a high-contrast NIGHTWATCH command-centre visual system with responsive SOC styling, animated radar motif, live operational status and telemetry cards.
- Adds a metrics strip driven by existing local inventory, DNS, alert and network APIs. Values are inventory counts or returned samples; no synthetic traffic or threat events are generated.
- Adds an interactive network observation map using `/api/topology`. Device nodes open the existing evidence-backed device dossier. Relationships are based on observed DNS, mDNS, LLMNR or DHCP traffic, not physical links.
- Adds a live activity feed built only from persisted network events and alert records. Empty states do not imply that the network is threat-free.
- Preserves the existing discovery engines, identity evidence/fusion, authorisation controls, endpoint inventory, investigations, reports and management APIs. This is an additive interface upgrade, not a backend replacement.
- Updates the package version to 12.5.0 and cache-busts dashboard assets.

## Validation boundary

Automated syntax and unit tests must pass. A Windows browser smoke test remains necessary to verify layout, topology interactions and live data on the user's network. The topology shows observed communication/discovery relationships only; it does not infer physical links or exact device locations.

---

# NetworkRadar 12.4.1 — Network Fingerprint Diagnostics and Safety Cleanup

## Delivered

- Diagnoses why an automatic network fingerprint is unavailable instead of returning only a generic authorisation error.
- Exposes observed and missing fingerprint components and bounded per-command Windows PowerShell collection results through the existing `/api/network` response.
- Explicitly identifies `NETWORKRADAR_NETWORK` as a manual scan-scope override, not proof of the currently connected network; the mode remains non-authorising.
- Provides a specific PowerShell recovery instruction when an operator tries to authorise while manual override mode is active.
- Removes an accidental hard-coded database update that reset approval for the single subnet `192.168.100.0/24` on every startup. Existing approvals for all networks are no longer modified by this unrelated migration code.
- Adds regression tests for manual override behaviour and the reported Windows adapter/gateway/BSSID evidence.
- Updates the launcher and application version to 12.4.1.

## Security

- No authorisation threshold or strong-anchor requirement has been weakened.
- Manual network overrides remain unable to authorise active discovery.
- Local PowerShell inventory queries no longer request `ExecutionPolicy Bypass`; they respect the host's configured policy.
- Includes `netsh wlan show interfaces` failures and adapter-name mismatches in the same fingerprint diagnostics, so missing Wi-Fi evidence is not silently hidden.
- PowerShell diagnostics record operation names, result state and bounded error text only; raw command output is not persisted.

## Validation boundary

Automated CI validates the regression tests. A live Windows restart is still required to confirm the user's current adapter state and determine whether a persistent `NETWORKRADAR_NETWORK` environment variable or a Windows collection failure caused the original message.

---

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
