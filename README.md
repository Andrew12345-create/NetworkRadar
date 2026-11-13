# NetworkRadar 8.4.0

A compatibility-first recovery release of the supplied NetworkRadar platform.

## Requirements

- Windows 10/11
- Python 3.10 or newer
- Nmap (for discovery and service/OS fingerprinting)
- Wireshark/TShark (for packet-observation engines)
- PowerShell 5.1

The core Python runtime and automated tests use only the Python standard
library. Nmap and TShark are separate Windows installations.

## Install / run

1. Extract the complete ZIP to a writable folder, e.g. `C:\CyberLab\NetworkRadar`.
2. Keep the `database` and `data` folders beside `networkradar.py`.
3. Open PowerShell in that folder.
4. Run `Set-ExecutionPolicy -Scope Process Bypass` only if your local policy
   prevents running the launcher; this setting lasts only for that shell.
5. Run `./NetworkRadar.ps1`.
6. Open `http://127.0.0.1:8765` if the browser does not open automatically.

If port 8765 is occupied, NetworkRadar reports the bind failure. To explicitly
permit selection of the next available local port, run:

```powershell
./NetworkRadar.ps1 --allow-alt-port
```

Or choose a specific port for this session:

```powershell
$env:NETWORKRADAR_PORT = "8766"
./NetworkRadar.ps1
```

The web console remains bound to `127.0.0.1`.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Data safety

The included database is a consistent SQLite backup of the uploaded database.
The source database was not modified. The supplied database integrity check
passed and all 51 application table row counts match the source archive.
Always back up your active `database` and `data` folders before replacing an
existing installation. Do not overwrite a newer working database with this
archive's database; if updating an existing installation, replace application
code only and retain your current database/data folders.

## Version scope

See `RELEASE_NOTES.md` and `docs/ARCHITECTURE.md`. The supplied archive
contained an 8.2.0 application, not the failed 8.3.0 source or its runtime
traceback. This build makes the verified recovery improvements possible from
the files provided and does not claim to reconstruct unavailable code.
