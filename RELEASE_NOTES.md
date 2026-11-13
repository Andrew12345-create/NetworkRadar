# NetworkRadar 8.4.0 — Modular Intelligence Architecture

## Changes

- Recovered from the supplied 8.2.0 source archive.
- Replaced the PID-file-only instance guard with an OS-managed process lock.
- Removed the web startup check-then-bind race; the HTTP server now attempts the
  actual bind and reports a clear error if the configured port is occupied.
- Alternate ports remain opt-in through `--allow-alt-port`.
- Preserved localhost-only binding (`127.0.0.1`).
- Extracted PHANTOM TRACK evidence scoring into a real importable module and
  retained the existing function interface.
- Added an additive `/api/engines` diagnostics endpoint.
- Added automated tests for port conflicts, lock lifecycle, evidence fusion,
  local/randomised MAC handling and diagnostic state truthfulness.
- No database migration is required by this release.

## Important

The supplied archive's primary application identifies itself as 8.2.0. The
archive does not include the failed 8.3.0 launch logs or a complete 8.3.0 source
package. This release is therefore a tested 8.4.0 recovery build from the
provided 8.2.0 baseline, not a claim that missing 8.3.0 files were audited.
