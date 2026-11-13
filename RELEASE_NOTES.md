# NetworkRadar 12.0.3 — audit corrections

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
- Updated installation, data-safety, version and architecture documentation to match the actual repository layout.
- Added application-level regression tests for identity scoring and approval freshness.

## Known limitations still under audit

- The application remains largely monolithic; startup and diagnostics helpers in the package are not yet the runtime's single source of truth.
- The repository contains the endpoint-agent hub server but no separately packaged endpoint-agent client/installer.
- Windows PowerShell, Nmap, TShark, packet capture, browser and remote-management integration tests must still be run on a Windows host.
- A complete route-by-route security review of the HTTP API, WebSocket bridge, SSH trust store, agent HMAC protocol and remote action flows remains in progress.
- No production-readiness claim is made.
