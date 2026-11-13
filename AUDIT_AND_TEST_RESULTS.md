> **Historical report:** This document records verification of the earlier 8.4.0 recovery artifact based on an 8.2.0 source archive. It does not audit or certify the current 12.0.3 repository snapshot. The code has subsequently diverged; use the current README, architecture notes and audit-branch tests for the present state.

# NetworkRadar 8.4.0 — Recovery audit and verification

## Source examined

Uploaded archive: `networkradar_5_1(1).zip`.

The archive's primary `networkradar.py` identifies itself as **8.2.0 — PHANTOM
TRACK EVOLUTION**. It is approximately 316 KB of source, with the major runtime,
API, database, dashboard and intelligence functionality in one file. The
archive does **not** contain a complete 8.3.0 package or the 8.3.0 launch
traceback. The module-related files in the archive have flattened names such
as `networkradar_modulesstartup_guard.py`; they are not in a valid Python
package directory and the 8.2.0 application does not import them.

## Confirmed findings in supplied 8.2.0 source

| Severity | Location in supplied source | Finding | Correction in 8.4.0 |
|---|---|---|---|
| HIGH | `networkradar.py`, original lines 232–258 | Instance prevention used a read-check-write PID file. Two launches could pass the check concurrently; stale/corrupt lock handling was not process-atomic. | Replaced with an OS-managed byte-range lock. Windows releases the lock when the process exits. The new guard also recognises a live PID left by the previous PID-file implementation. |
| HIGH | `networkradar.py`, original lines 260–303 and 5427 onward | Port availability was checked before creating the HTTP server. The port could be claimed between the probe and bind (TOCTOU race). | Startup now attempts the actual bind directly. Alternate ports are only searched when `--allow-alt-port` is explicit. |
| MEDIUM | Archive root filenames | Three proposed module files were flattened into filenames rather than installed as `networkradar_modules/...`; they were not importable as the proposed package. | Added a real package structure and integrated core startup, identity fusion and diagnostics modules. Original flattened files are retained under `legacy_reference/`. |
| MEDIUM | `networkradar.py` header and archive contents | The application source reports 8.2.0; the uploaded archive does not provide the claimed failed 8.3.0 source/runtime evidence. | Built 8.4.0 from the actual supplied 8.2.0 baseline. No unsupported claim is made that missing 8.3.0 code was recovered. |

No duplicate top-level function definitions were found in the supplied main
source. Python compilation of the supplied main source passed after handling
its UTF-8 BOM correctly.

## Database preservation verification

The supplied SQLite database was opened read-only and copied using SQLite's
backup API. The source archive was not modified. Results:

- Source database `PRAGMA integrity_check`: `ok`
- Release database `PRAGMA integrity_check`: `ok`
- Application tables compared: 51
- Table row counts: identical across all 51 tables
- Key preserved records: 31 devices, 157,535 DNS events, 73,916 ARP observations,
  28 investigations, 4,649 events, 130 scans
- No migration was applied by this recovery build.

## Automated verification

- Python compilation: PASS for the main app, new package and test modules.
- AST parse: PASS for the main application.
- Unit tests: PASS — 9 tests covering lock lifecycle, occupied-port behaviour,
  explicit alternate-port selection, independent evidence scoring, source-group
  caps, identity conflicts, local/randomised MAC treatment, empty evidence and
  diagnostic state reporting.
- Dashboard JavaScript syntax (`node --check`): PASS.
- SQLite integrity and row-count preservation: PASS.
- Windows PowerShell 5.1 execution: NOT RUN (not available in this build
  environment).
- Live Nmap/TShark capture and Windows adapter integration: NOT RUN (requires
  the target Windows host, installed tools, capture permissions and authorised
  network).
- Full browser/API end-to-end test on Windows: NOT RUN.

The Python test runner emitted an unrelated environment spreadsheet warm-up
warning before the tests; the unittest process exited with code 0 and all nine
tests passed.

## Remaining work (not misrepresented as delivered)

This is a recovery and first modular extraction release, not the final
fully-extracted architecture. The discovery, DNS, DHCP, ARP, database,
behaviour, investigations, reporting and dashboard implementations remain in
the established application core. The RADAR IDENTITY research methods such as
full mDNS/DNS-SD, SSDP/UPnP, SNMPv3, LLDP/CDP, TLS certificate inventory and an
authenticated endpoint agent are not newly implemented in this 8.4.0 package.
They remain future modules and must be added with Windows integration tests,
consent/authorisation controls and additive database migrations.
