# NetworkRadar 8.4.0 architecture

## Recovery baseline

This release is based on the supplied NetworkRadar 8.2.0 application and its
existing SQLite database. The established dashboard, API routes, discovery,
DNS/DHCP/ARP capture, investigations, reports, historical records and existing
schema are retained. This is a compatibility-first modularisation step, not a
claim that every subsystem has already been extracted from the legacy core.

## Integrated modules

- `networkradar_modules.core.startup`: OS-managed single-instance lock and
  bind-first localhost HTTP server startup. The server binds only to
  `127.0.0.1`; alternate ports are considered only with `--allow-alt-port`.
- `networkradar_modules.identity.fusion`: PHANTOM TRACK evidence scoring,
  freshness decay, independence-group caps, conflict detection and conservative
  auto-merge policy. The existing `phantom_score` entry point delegates here.
- `networkradar_modules.diagnostics.status`: truthful engine-state normalisation
  used by the new `/api/engines` endpoint.

## Compatibility and safety

- Existing database schema is not migrated by this release.
- The supplied live database is copied using SQLite's backup API to produce a
  consistent release copy; the original archive is not modified.
- Existing API endpoints remain in place; `/api/engines` is additive.
- Network operations remain for authorised networks only.
- SNMP credentials, endpoint agents and remote management are not enabled by
  default and are not introduced by this recovery build.

## Known scope boundary

The supplied archive contains an 8.2.0 monolithic application and three
flattened module files; it does not contain a working 8.3.0 modular package or
its launch traceback. Consequently, this release repairs the verifiable startup
and modular-integration risks in the supplied source. It does not claim to have
reconstructed code absent from the archive.
