# NetworkRadar 15.5.0 — Multi-source Gateway Identification

## Router identification improvements
- Connects the gateway MAC already collected by Windows network context to router identification.
- Reuses the existing IEEE MA-L, MA-M and MA-S cache with longest-prefix matching and exposes the registry owner and assignment type.
- Labels IEEE ownership as address-block registrant metadata, not proof of router manufacturer, model or firmware. OUI data never overrides protocol fingerprints.
- Adds bounded SSDP/UPnP M-SEARCH discovery. Only responses sourced from the authorised default gateway are retained; other LAN responders are discarded.
- Retains SSDP SERVER, service target, UUID and LOCATION as evidence. Advertised LOCATION URLs are never fetched.
- Combines gateway-scoped SSDP evidence with existing bounded HTTP/TLS metadata signatures.
- Preserves private-subnet validation, stale-context checks, no-credential discovery, no configuration writes and control_ready=false until an authenticated compatible adapter exists.

## Validation boundary
- Adds tests for OUI evidence qualification, gateway-only SSDP vendor evidence and the no-control-without-adapter invariant.
- This release improves identification evidence; it does not add router-control adapters or guarantee exact model/firmware identification.
- Windows live-network verification remains necessary. SSDP may be blocked by the router, host firewall or Wi-Fi isolation.

# NetworkRadar 15.4.0 — Network Control API Responsiveness

## Fixes for router identification and status timeouts
- Router identification and router status GET endpoints now use the latest background-refreshed network context instead of launching synchronous PowerShell discovery and database writes on every dashboard request.
- Router identification fails closed with a clear HTTP 503 response when the cached network context is older than 120 seconds; it does not probe a gateway using stale authorisation.
- Router status reports whether its network context is fresh. A stale context suspends the displayed session until the background refresh completes; it does not disconnect or alter the router session.
- MikroTik RouterOS status performs independent read-only REST reads concurrently, bounding worst-case wait to approximately one REST timeout rather than the sum of sequential request timeouts.
- Dashboard API errors surface the server's actual error message. Client-side aborts display an actionable timeout message instead of the opaque "signal is aborted without reason".
- Router identification and status receive bounded 9-second and 12-second browser deadlines respectively.
- Network-control write actions retain their explicit fresh network-context refresh and confirmation requirements. Router configuration safety checks are unchanged.

## Validation
- Added regression tests for cached network-context freshness.
- Existing router-control safety, discovery, JavaScript syntax and full regression suites remain required in CI.

# NetworkRadar 15.3.0 — Router Identification First

## Router identification foundation
- Adds an authorised-gateway-only discovery stage before credentials or control actions.
- Probes standard local HTTP/HTTPS management ports with strict timeouts and response-size limits; redirects are not followed.
- Extracts page title, server headers, redirect metadata and TLS certificate subject as evidence. Certificate metadata is explicitly untrusted and is never used to authenticate a control session.
- Matches observed evidence against vendor signatures for MikroTik, ASUS, TP-Link, UniFi/Ubiquiti, NETGEAR, D-Link, Linksys, Huawei, ZTE, OpenWrt, GL.iNet, DrayTek, Zyxel, Cisco and other common families.
- Shows confidence and unknown/ambiguous results rather than inventing a model.
- Shows adapter candidates separately from identity. This is a detection foundation, not a claim that every router is already controllable.
- No credentials are sent and no router settings are changed during identification.

# NetworkRadar 15.2.0 — Bandwidth Enforcement Integrity

## Critical bandwidth-control correction
- RouterOS FastTrack bypasses Simple Queues. The previous release warned about this but still allowed a queue write to be reported as successful.
- NetworkRadar now re-reads enabled FastTrack rules immediately before applying a per-device bandwidth limit and refuses the operation when FastTrack could bypass it. No ineffective queue is created or updated.
- After a queue write, NetworkRadar reads the queue back and verifies its target, requested upload/download rates, enabled state and validity before reporting configuration success.
- Router status now refreshes FastTrack state and exposes queue rate, byte, packet, queued-byte and drop counters where RouterOS returns them.
- NetworkRadar deliberately does not disable or rewrite existing FastTrack/firewall rules automatically. The router administrator must configure the affected traffic to bypass FastTrack, or disable FastTrack for that traffic, before a Simple Queue can enforce the cap.
- A verified queue configuration is not a substitute for a real throughput test from the limited client; ISP speed, other queues, VPNs, hardware offload and existing connections can affect observed results.

## Network Control Engine (15.1.0)

## Network Control Engine
- Adds user-selected whole-minute pause durations from 1 minute to 24 hours for device and network-wide restrictions, including minute/hour input, quick presets and an estimated restoration timestamp before confirmation.
- Removes the former fixed-duration-only restriction; backend validation accepts any integer minute in the bounded 1–1440 minute range and rejects decimals, booleans and out-of-range values.
- Adds the first managed router adapter for MikroTik RouterOS 7+ using HTTPS REST with strict certificate validation and no insecure TLS bypass.
- Adds a dedicated Network Control workspace with router capability status, online-device selection, bandwidth controls, timed pauses and emergency restore.
- Applies per-device upload/download limits using RouterOS Simple Queues. The UI reports detected FastTrack because FastTrack can bypass Simple Queues; NetworkRadar does not alter existing FastTrack rules.
- Applies temporary device/network restrictions using router-managed IPv4 and IPv6 address-list timeouts. Expiry is enforced by the router, not a local countdown thread.
- Uses LAN/WAN interface lists and inserts managed forward-chain rules before existing forward rules. Rules are scoped to LAN-to-WAN forwarding; local LAN and router-management traffic are not targeted.
- Requires the current network to be explicitly authorised, router IP to be inside the authorised private subnet, targets to be in the current online inventory, and explicit confirmation for changes.
- Emergency restore deletes only NetworkRadar-owned address-list entries, queues and firewall rules.
- Router credentials are memory-only. HTTPS certificate verification is mandatory; self-signed router certificates require a trusted CA certificate path.
- If dual-stack coverage cannot be established, the user must explicitly approve an IPv4-only action. Device IPv6 privacy-address rotation can create new addresses that are not yet observed.
- MikroTik RouterOS 7+ is the first managed adapter. OpenWrt, ASUS, TP-Link and UniFi are not yet enabled for control; unsupported routers remain unaffected.

## Validation boundary
- Adds isolated unit tests for scope validation, duration/rate validation, dual-stack timed pauses, Simple Queue direction, ownership-safe restore and network-session binding.
- Windows/Nmap/TShark live scans are unaffected. A real RouterOS integration test on the user's authorised router remains required before relying on traffic-control actions.

## Evidence intelligence and identity reconciliation
- Separates the latest device assessment from the accepted inventory identity.
- Retains a previously supported category when a scan returns no usable evidence, falls below the acceptance threshold, or proposes a conflicting category without the required confidence margin.
- Allows stronger new evidence to replace a retained category and records the decision plus a human-readable explanation in the recognition payload and identity assessment event.
- Adds timestamp-aware evidence scoring with half-life decay and a maximum age. Undated observations are not silently treated as fresh.
- Caps repeated observations from the same source family and keeps competing values visible for review.
- Improves Unknown Device Hunter guidance: DHCP collector errors and unsuccessful attempts no longer produce the same high-priority instruction repeatedly.
- Adds a planning-only investigation scheduler that distinguishes already-observed methods, cooldowns, exhausted attempts, offline waiting, authorisation requirements and unavailable collectors.
- The planner does not send packets. Active methods remain bounded, read-only and explicitly authorised; DHCP lease renewals are never forced.
- Adds regression coverage for evidence freshness, family deduplication, identity retention/replacement, retry cooldowns, offline deferral and authorisation.

## Validation boundary
- Automated tests are run by the repository's GitHub Actions matrix.
- Local Windows/Nmap/TShark and existing SQLite database validation remains necessary before treating the release as live-verified.

## Full TCP Port Intelligence
- Adds an explicit, opt-in full TCP scan for one currently ONLINE device at a time, covering ports 1–65,535.
- Requires current explicit network authorisation, a private IPv4 target inside the current authorised subnet, an ONLINE inventory record and an additional user confirmation.
- Uses TCP connect scanning, lightweight service detection, bounded retries, a 190-second process budget, a 180-second Nmap host timeout and a 200-packet-per-second cap.
- Persists append-only complete/incomplete scan observations and service metadata without silently replacing the routine inventory's bounded scan results.
- Feeds the full-range service fingerprints into the existing identity profiler and evidence store; stronger retained classifications are preserved when the new assessment is weak.
- Does not run a subnet-wide full-port sweep, UDP full-range scan, credential attempts, exploit scripts, stealth options or service changes.
- Adds a dashboard history view for full-port results. Open ports and service banners are evidence, not proof of device identity or vulnerability.

## Domain & Search-Provider Intelligence
- Adds a seven-day per-device DNS activity view with domain category, known provider, query count and last-observed time.
- Classifies known search, video/streaming, social, gaming, education and productivity domains; unknown domains remain OTHER.
- Clearly distinguishes search-provider domain activity from actual search phrases. DNS cannot reveal HTTPS search terms, page paths or typed queries.
- Does not intercept TLS, bypass encryption, collect browser history or attempt to reconstruct private search content.
- Encrypted DNS, VPNs, resolver caching, client isolation and missing DNS visibility remain explicit limitations.

## Identity and investigation observability
- Adds separate attempted-target and total-attempt queue metrics; queue completion remains based only on resolved or retry-exhausted targets.
- Adds a bounded TTL cache for positive and negative reverse-DNS/NetBIOS lookups, scoped to the current network to avoid carrying names across network changes.
- Serializes opt-in full-port scans against normal discovery and the identity worker through the existing atomic scan reservation gate.
- Adds a visible identity assessment timeline that contrasts the current assessment with the persisted best-known inventory identity, explaining when weaker evidence is retained.
- Keeps the legacy fingerprint event for existing presence/history consumers while adding the more precise DEVICE_IDENTITY_ASSESSED event.

## Earlier 14.1 roadmap work retained
- Preserves the 14.0 adaptive fingerprint planner and its strict target, cooldown and authorised-subnet bounds.
- Keeps optional UDP enrichment fail-soft: UDP timeout/failure must not discard successful TCP identity evidence.
- Retains historical identity continuity and avoids treating a randomized/local MAC as a stable device identity.
- Maintains one-at-a-time unknown-device investigations, bounded retries and backoff.

## Validation and limitations
- Adds deterministic unit tests for full-port target scope, Nmap XML parsing, full-range invocation, timeout handling, domain categorisation, per-device aggregation and investigation-attempt metrics.
- A full TCP scan is deliberately user-triggered and may take several minutes. Runtime behaviour and scan duration must be validated on the local Windows/Nmap installation.
- Domain classifications are heuristic labels based on queried domain names, not evidence of a specific person or exact activity.
- No destructive database migration or historical record deletion is introduced.

# NetworkRadar 14.0.0 — Adaptive Fingerprint Scheduling

## Performance and identity investigation
- Adds a deterministic, unit-tested target planner that prioritises new devices, then low-confidence identities after a 15-minute retry cooldown, medium-confidence identities after 6 hours and established identities after 24 hours.
- Uses the latest Nmap attempt timestamp, including incomplete attempts, so filtered devices are not immediately re-probed on every deep scan.
- Reads identity confidence from the persistent device inventory rather than assuming transient discovery records contain it.
- Caps each main deep-fingerprint pass at 8 selected private IPv4 targets and the targeted UDP pass at the 3 highest-priority targets.
- Leaves deferred devices in the inventory and does not clear their prior port/service observations.
- Tightens Nmap TCP/OS, reduced fallback and UDP process/per-host budgets; partial TCP results remain available if optional UDP enrichment times out.
- Keeps explicit network authorisation, the existing safe NSE script allow-list, read-only behaviour and local-only API boundaries unchanged.

## Validation
- Adds tests for deterministic priority, target caps, cooldowns, confidence-specific refresh windows, invalid/public/IPv6/multicast address rejection and duplicate suppression.
- Adds tests for all bounded scan-budget tiers.
- No database migration or new active protocol is introduced.
- A successful CI run and live Windows/Nmap verification are required before treating the release as production-validated.

# NetworkRadar 13.8.0 — Embedded OS Identity Recognition

## Device classification
- Adds a conservative "Embedded / appliance device" category for supported embedded real-time OS fingerprints from Nmap OS or safe script evidence.
- Recognises VxWorks, QNX, eCos, ThreadX, FreeRTOS and Zephyr as embedded OS-family indicators.
- Extends the OS-family dossier to report "Embedded / appliance OS" for these fingerprints.
- Does not infer a device manufacturer, exact product role, hardware model or serial number from an OS fingerprint or NIC/OUI registrant.
- No new network probes, database migrations, or authorisation changes are introduced.

## Validation
- Adds a regression test using the observed VxWorks fingerprint pattern from the current network inventory.
- GitHub Actions Windows/Python matrix and local Windows/Nmap verification are required before treating the release as fully validated.

# NetworkRadar 13.7.0 — Dashboard Consistency & Accessibility

## Frontend refinements
- Adds consistent keyboard focus indicators to interactive controls and links.
- Prevents nested dashboard grids and workspace panels from forcing page-level horizontal overflow.
- Improves horizontal table scrolling and touch interaction on compact screens.
- Applies reduced-motion preferences consistently to animations, transitions and smooth scrolling.
- This is an additive CSS-only presentation update; the Python discovery engine, API contracts, database schema and authorisation gates are unchanged.

## Validation
- Existing static-asset regression tests cover stylesheet presence and balanced CSS blocks.
- Full Windows CI, Node.js syntax validation and live browser checks remain required before calling the release fully verified.

# NetworkRadar 13.6.1 — Independent Subscan Progress & Scan Isolation

## Identity subscan progress
- Adds a dedicated active-device progress bar showing the current IP, current investigation stage, stage-based percentage and live status text.
- Adds a second queue progress bar showing the share of targets that have reached a terminal resolved or retry-exhausted state. Queued and backoff-waiting devices remain outstanding.
- The active bar animates while Nmap is running. Nmap does not expose a reliable live percentage for this subprocess, so the percentage advances by completed investigation stages rather than pretending to measure Nmap's internal work.
- Routes targeted subscan progress to its own coordinator state; it no longer writes the main scan progress endpoint or hijacks the main scan monitor.

## Scan coordination
- Adds an atomic reservation gate between the main discovery loop and identity worker. A full scan and a one-host identity subscan cannot claim the scanning slot at the same time.
- Preserves one-target-at-a-time scheduling, explicit network authorisation, authorised private-subnet checks, bounded retries and exponential backoff.

## Validation
- Adds tests for independent progress state and queue completion metrics. Full Python 3.10–3.13 CI and local Windows/Nmap validation are required before release use.

# NetworkRadar 13.6.0 — Continuous Identity Investigation & Scan Performance

## Continuous unknown-device subscans
- Adds a long-lived, low-priority identity subscan worker. Newly observed unidentified private IPv4 hosts are queued for separate one-host follow-up fingerprinting rather than forcing every host through the same deep scan in the main discovery cycle.
- The worker remains available for the lifetime of NetworkRadar, processes one device at a time, and yields to full network scans.
- Active follow-up requires explicit authorisation and verifies that each target remains inside the currently authorised private subnet.
- Each target receives at most three attempts per evidence signature, with exponential backoff (90 seconds, then 180 seconds) and a six-hour cooldown after exhaustion. New identity evidence can reopen an exhausted/resolved target.
- Adds a dashboard view for queue state, attempts, next retry and last error/result. The queue is rebuilt from current inventory after restart; device history remains in the database.
- This is persistent investigation scheduling, not an endless rapid scan loop. It avoids repeatedly hammering filtered/offline devices and preserves normal network availability.

## Main-scan performance and identity quality
- Retains the 13.5.0 phase profiler and evidence-aware identity next-step guidance.
- Separates quick network discovery from targeted deeper investigations of unresolved devices.
- Exact hardware model and serial number remain unclaimed unless explicit device-reported or authenticated endpoint evidence supports them.

## Validation
- Adds unit tests for deduplication, one-at-a-time claims, exponential backoff, retry exhaustion, evidence-change reopening and private IPv4 scoping.
- Full Windows/Nmap/Npcap live validation is still required to measure subscan duration and verify device-specific identity improvements.

# NetworkRadar 13.5.0 — Scan Observability and Evidence-Led Device Investigation

## Scan performance observability
- Adds bounded, thread-safe wall-clock measurement for scan phases, including host discovery, TCP reachability, Nmap TCP/OS/service detection, reduced fallback, targeted UDP, passive TCP, LLDP/CDP, parallel TLS/SNMP/service probes, inventory persistence and post-scan analytics.
- Exposes the latest scan profile through `GET /api/scan_performance` and a dashboard phase table.
- Records call counts, cumulative/last/max duration and error type without storing packet contents, credentials or raw exception text.
- Failed scans retain partial timing data to make bottlenecks diagnosable.

## Unknown-device investigation guidance
- Adds evidence-aware next actions based on which identity sources are actually present.
- Distinguishes DHCP, mDNS/DNS-SD, SSDP/UPnP, Nmap, SNMPv3, LLDP/CDP and enrolled endpoint inventory gaps.
- Active collection suggestions are shown only when the current network is authorised; guidance never triggers probes.
- Exact hardware model remains explicitly unestablished unless endpoint/service-reported evidence supports it.

## Validation
- Adds unit tests for profiler accumulation, error handling and unknown-device guidance.
- No destructive database migration, credential guessing, DHCP lease changes or automatic active probes are introduced.

# NetworkRadar 13.4.0 — Bounded Discovery and Faster Identity Enrichment

## Scan performance and reliability
- Replaces the fixed deep-scan budget with an adaptive profile based on the number of discovered hosts.
- Uses a smaller port set for larger inventories, bounded Nmap process timeouts, per-host timeouts and a reduced service-only fallback.
- Adds bounded retry behaviour and rate caps; TCP/OS and targeted UDP enrichment can no longer each consume the previous 180/150/100-second process budgets.
- Runs independent TLS certificate, explicitly configured SNMPv3 and service-banner enrichment concurrently across devices. Each module retains its own authorisation checks and per-device failures do not cancel other results.
- Keeps full identity evidence fusion and historical persistence intact.

## DHCP capture diagnostics
- Reports the selected TShark interface and capture filter when no DHCP frames have been observed.
- Explains that a healthy passive capture with zero frames is not necessarily broken: DHCP is most visible during acquisition/renewal, while switched Wi-Fi/client isolation can hide other clients.
- Records the timestamp of the latest observed DHCP message.

## Validation and limitations
- Adds unit coverage for adaptive scan budgets and clamping.
- Existing Windows CI remains the source of compile, dashboard syntax and regression-test results.
- A live authorised Windows scan is still required to measure real-world duration and confirm DHCP visibility on the selected adapter.
- No active DHCP lease requests, credential guessing, exploit probes, destructive database changes or automatic firewall policy changes are introduced.

# NetworkRadar 13.3.3 — Enforce Network Authorisation for Active Discovery

## Security and discovery-mode correctness
- Nmap ARP/host discovery now requires explicit approval of the current network workspace.
- When the network is not authorised, NetworkRadar uses only locally available Windows neighbour observations and passive packet observations.
- SSDP M-SEARCH, reverse-DNS/NetBIOS lookups, TLS certificate handshakes, SNMPv3 queries and service-banner probes are individually approval-gated.
- Existing TCP sweep, active mDNS browse and deep Nmap fingerprinting authorisation checks remain in place.
- Passive/partial observations no longer count as a complete subnet scan and cannot mark unobserved devices offline or advance workspace offline counters.
- The scan monitor now labels unauthorised discovery as passive/partial rather than implying an Nmap scan ran.

## Validation
- Adds regression tests for unauthorised and authorised discovery paths, active identity-probe gates and offline-state preservation on partial inventories.
- CI must pass on Python 3.10–3.13 and dashboard JavaScript validation before merge.

# NetworkRadar 13.3.2 — Firewall Snapshot Timeout Recovery

## Dashboard request reliability
- Batches Windows Defender Firewall profile collection and active-rule counting into one PowerShell process instead of two serial launches.
- Bounds the combined firewall collection to 20 seconds and returns a clear DEGRADED result on timeout; no firewall settings are modified.
- Gives only the dashboard's firewall API request a 30-second client timeout. All other dashboard API requests retain their existing 10-second timeout.
- The firewall inspection remains read-only and does not block or alter the active network authorisation decision.

## Validation
- Adds regression tests for the combined profile/rule response, single-process execution and timeout handling.
- Dashboard JavaScript syntax and the full Python test matrix are required before merge.

# NetworkRadar 13.3.1 — Windows Network Context Recovery

## Faster, more resilient network identification
- Replaces five serial PowerShell process launches with one bounded 25-second batched query for adapters, IPv4 addresses, default routes, DNS servers and DHCP state.
- Adds a native Windows `ipconfig /all` fallback when the PowerShell query times out or returns incomplete adapter/address data.
- Keeps adapter, address, route, DNS and DHCP evidence associated by interface; the native fallback only creates a gateway observation when Windows actually reports one.
- Gateway-neighbour lookup remains scoped to the exact observed gateway. The native fallback does not invent an interface index or gateway MAC.
- PowerShell timeouts are now reported as `TIMEOUT` diagnostics instead of generic errors.
- Active discovery authorisation thresholds and approval requirements are unchanged. If a sufficiently strong current network fingerprint cannot be established, active discovery remains disabled.

## Coverage and limitations
- The native parser currently targets English-language Windows `ipconfig /all` labels. Localised output that cannot be parsed is reported as unavailable rather than guessed.
- A fallback subnet/gateway observation is not by itself proof of network authorisation; a strong gateway-MAC or BSSID anchor and a current approved profile are still required.
- This is source-level and CI validation. A live Windows run is still required to confirm the behaviour on the affected laptop.

## Validation
- Adds tests for batched query composition, IPv4/subnet parsing, gateway and DNS extraction, DHCP state, virtual-interface separation and missing-gateway handling.

# NetworkRadar 13.3.0 — Layered Reachability Discovery

## Vigorous but bounded discovery
- Supplements the existing Nmap ARP/host-discovery pass with a bounded TCP connect sweep over a curated set of common service ports.
- TCP discovery can identify hosts that ignore ICMP/ARP discovery but accept a connection on an exposed service.
- Uses a maximum of 128 concurrent connection attempts, a short per-probe timeout, and a maximum of 512 IPv4 host addresses per pass.
- Rechecks active-network authorisation immediately before the TCP sweep; unauthorised scopes do not receive the additional active probes.
- Merges observations by IP without inventing a MAC address, manufacturer, model, operating system or device category.
- Preserves the exact tested ports and successful TCP ports as reachability evidence for subsequent service/identity enrichment.
- Exposes probe progress through the existing scan monitor and keeps TCP-sweep failures non-fatal to the Nmap and neighbour-table results.
- No password guessing, credential brute force, exploit payloads, stealth, or security-control bypass is performed.

## Important coverage limits
- This is not a guarantee that every physical device will be found. A host that is asleep, isolated, on another VLAN, or filters every selected probe may remain invisible.
- TCP acceptance proves only that a service accepted a connection; it does not identify the device or prove that the service is safe.
- The 512-host cap is intentional. Larger networks are rejected for this supplementary sweep rather than silently launching a very large scan.
- Router/AP association-table integration and richer exact hardware inventory remain future work and require an explicitly configured read-only interface.

## Validation
- Adds deterministic tests for private-scope enforcement, host caps, selected-port behaviour, connection cleanup, progress reporting and evidence-only device records.
- GitHub Actions validation is required before merge. A live Windows/Nmap/Npcap test is still needed to measure actual scan duration and visibility on the local Wi-Fi.

# NetworkRadar 13.2.0 — Persistent Scan Monitor and Discovery Telemetry

## Scan visibility
- Adds a compact live scan monitor to the sticky top navigation without expanding the navigation into a large banner.
- Shows current scan phase, percentage and a plain-language description of the operation.
- Adds a bounded recent-activity timeline to the command workspace.
- Records the last 12 progress updates in memory and exposes them through the existing progress API.
- Makes scan queue failures visible instead of treating every HTTP response as successful.

## Discovery transparency
- Separates Nmap host discovery, Windows neighbour-cache collection, inventory persistence, mDNS/DNS-SD service discovery and identity enrichment into visible progress stages.
- Refreshes the bounded local mDNS/DNS-SD browse on each authorised scan and runs the deeper selected-port/OS/service fingerprint pass every five scans instead of every ten, making new device details surface sooner while keeping heavier probing rate-limited.
- Makes it explicit when devices respond but cannot yet be confidently identified.
- Does not claim that every device can always be detected: sleeping/offline devices, client isolation, VLAN boundaries, firewalls, randomized MACs and devices that do not advertise services can limit visibility. Historical records and unknown classifications are retained rather than inventing names or models.
- Active discovery remains restricted to the application's existing network-authorisation gate and local network scope.

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
