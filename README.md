# NetworkRadar 12.0.3

NetworkRadar is a Windows-focused, local-first network discovery and device-intelligence application. It combines authorised network discovery, device inventory, DNS/DHCP/ARP observations, identity evidence, historical tracking, exposure observations, investigations and a localhost dashboard. Optional management features include SSH terminal access and Windows/endpoint-management integrations.

> **Project status:** Active development. The repository contains a large application core and a growing modular package. The current snapshot has not yet completed a full Windows end-to-end security and compatibility test cycle. Treat remote-management features as advanced functionality and use them only on systems and networks you own or are explicitly authorised to administer.

## Current application version

The application version is defined once in `networkradar_modules/__init__.py` and exposed to the dashboard and logs by `networkradar.py`.

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer.
- Nmap installed and available on PATH, or configured with `NETWORKRADAR_NMAP`.
- Wireshark/TShark installed and available on PATH, or configured with `NETWORKRADAR_TSHARK`.
- Capture permissions and a compatible Npcap installation may be required for packet-observation features.

The core application uses the Python standard library. Paramiko is optional and required only for the SSH terminal.

## Installation

1. Clone or download the complete repository. Do not copy only `networkradar.py`; the application imports the `networkradar_modules` package.
2. Open PowerShell in the repository directory.
3. Create and activate a virtual environment:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   ```

4. Install optional SSH support if you intend to use Phantom Terminal:

   ```powershell
   python -m pip install -r requirements-ssh.txt
   ```

5. Install Nmap and Wireshark/TShark separately and confirm that `nmap --version` and `tshark --version` work in PowerShell.
6. Start NetworkRadar:

   ```powershell
   .\NetworkRadar.ps1
   ```

   If PowerShell blocks the launcher, you may temporarily permit scripts in the current PowerShell process only:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\NetworkRadar.ps1
   ```

The dashboard opens at **http://127.0.0.1:8766** by default.

## Packet-capture interface selection

NetworkRadar first identifies the active Windows adapter using route metrics, then matches that adapter to TShark by interface GUID/name/description. This avoids silently capturing on a different Wi-Fi or Ethernet adapter when several are present.

To inspect TShark's interface list:

```powershell
tshark -D
```

If automatic matching cannot identify the active adapter, set the TShark interface number (or a matching displayed name) for the current PowerShell session:

```powershell
$env:NETWORKRADAR_TSHARK_INTERFACE = "3"
.\NetworkRadar.ps1
```

## Port configuration

Set a specific port for the current PowerShell session:

```powershell
$env:NETWORKRADAR_PORT = "8767"
.\NetworkRadar.ps1
```

NetworkRadar does not silently change ports. To explicitly permit a search of the next 30 ports:

```powershell
.\NetworkRadar.ps1 --allow-alt-port
```

The primary dashboard is intended to bind to loopback (`127.0.0.1`). Do not expose it through port forwarding or a reverse proxy without a separate security review.

## Data and database

On startup, the application creates its local `data/` and `database/` directories when needed. These directories are intentionally excluded from Git because they contain local network inventory, observations, captures, credentials/trust material and runtime database files.

- Back up your own `data/` and `database/` folders before upgrading.
- When updating application code, retain your existing local database and data folders.
- Older approved profiles without a valid `last_authorized` timestamp will require a one-time re-approval.
- Do not commit scan output, packet captures, database files, SSH known-host records, agent secrets, certificates or private keys.

This repository does **not** ship a live SQLite database.

## Run tests

From the repository root:

```powershell
python -m unittest discover -s tests -v
```

The suite includes isolated tests for startup/identity/diagnostic helpers and integration regression tests for the application identity scorer and network-approval freshness policy. Windows-specific discovery, packet capture, browser and remote-management behaviour still requires testing on a real Windows host.

## Security and authorised use

- Only scan networks for which you have permission.
- Active discovery and endpoint management are gated by a locally approved network profile.
- Open ports and service banners are observations, not proof of vulnerabilities or compromise.
- SSH host keys must be reviewed and explicitly trusted before authentication.
- Remote actions can affect availability. Review targets and confirm disruptive actions carefully.
- The optional endpoint-agent hub is disabled by default and requires TLS configuration. This repository snapshot does not yet provide a separately packaged endpoint-agent client installer; do not treat the hub alone as a complete deployable agent solution.

## Project structure

- `networkradar.py` — application runtime, dashboard/API and orchestration.
- `networkradar_modules/` — reusable identity, startup and diagnostics components.
- `migrations/` — additive database schema migrations.
- `tests/` — unit and application regression tests.
- `docs/` — architecture and audit notes.

See [Architecture](docs/ARCHITECTURE.md), [Release Notes](RELEASE_NOTES.md), and [Audit History](AUDIT_AND_TEST_RESULTS.md).
