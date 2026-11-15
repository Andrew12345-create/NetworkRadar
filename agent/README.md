# NetworkRadar Endpoint Inventory Agent 1.0.0

The endpoint agent closes an important identity gap: ordinary network observations can often estimate a device family, operating system or vendor, but they cannot reliably reveal the exact computer model, CPU, RAM or BIOS information. An explicitly enrolled endpoint can report that inventory directly.

## Scope and privacy

This client is deliberately **inventory-only**:

- Reads Windows CIM hardware and operating-system inventory.
- Reports manufacturer, exact system model/family, CPU, physical memory, BIOS version, disks and network adapters.
- Does not execute remote commands, poll the command queue, install a Windows service, change settings, enumerate user files, collect browser history or capture packets.
- Does not collect BIOS or disk serial numbers unless the operator explicitly supplies `--include-serial`.
- Reports immediately and then every five minutes by default.
- Requires a one-time enrolment token and a pinned HTTPS leaf-certificate SHA-256 fingerprint.
- Stores the per-agent HMAC key using Windows DPAPI for the current Windows user.

The agent does not silently install or start itself. Run it manually or create a Task Scheduler entry under the intended Windows account after reviewing the behaviour.

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 or newer.
- Network access to the NetworkRadar agent-hub host and TCP port.
- An authorised NetworkRadar network profile.
- The NetworkRadar agent hub enabled with a TLS certificate and private key.

## 1. Configure the NetworkRadar host

The hub is disabled by default and binds to loopback unless explicitly configured. On the computer running NetworkRadar, open PowerShell and set the following values for the session used to launch NetworkRadar:

```powershell
$env:NETWORKRADAR_AGENT_ENABLED = "1"
$env:NETWORKRADAR_AGENT_BIND = "192.168.1.10"  # Replace with this PC's LAN IPv4 address
$env:NETWORKRADAR_AGENT_PORT = "8767"
$env:NETWORKRADAR_AGENT_CERT = "C:\NetworkRadar\certs\agent-cert.pem"
$env:NETWORKRADAR_AGENT_KEY = "C:\NetworkRadar\certs\agent-key.pem"
.\NetworkRadar.ps1
```

Use the actual LAN address of the NetworkRadar host. Prefer binding to that one address rather than `0.0.0.0`. Protect the private key and restrict the Windows Firewall inbound rule for TCP 8767 to the specific endpoint devices that you administer. Do not expose the hub to the public internet.

The current network must be approved in NetworkRadar before the hub can start or accept enrolment.

## 2. Calculate the certificate pin

The endpoint agent checks the SHA-256 hash of the server's presented DER-encoded leaf certificate before it sends any enrolment or report data.

On the NetworkRadar host, calculate the pin from the same PEM certificate configured in `NETWORKRADAR_AGENT_CERT`:

```powershell
python -c "import ssl,hashlib,pathlib; p=pathlib.Path(r'C:\NetworkRadar\certs\agent-cert.pem'); der=ssl.PEM_cert_to_DER_cert(p.read_text(encoding='ascii')); print(hashlib.sha256(der).hexdigest())"
```

Copy the resulting 64-character hexadecimal fingerprint to the endpoint enrolment command. If the certificate is renewed or replaced, calculate and distribute the new pin before agents reconnect. A pin mismatch causes the agent to stop before sending the HTTP request.

## 3. Create a one-time enrolment token

In the NetworkRadar dashboard, open the **Managed Endpoints** section and select **Generate Enrolment Token**.

The token:
- can be used once;
- expires after 15 minutes;
- is stored on the server as a hash;
- must be entered on the target endpoint while it is connected to the authorised LAN.

Do not post the token in chat, commit it to a file or reuse it.

## 4. Enrol an endpoint

Copy the `agent` folder to the Windows endpoint, then open PowerShell in that folder. Run:

```powershell
python .\networkradar_agent.py --enrol --server https://192.168.1.10:8767 --server-cert-sha256 YOUR_64_CHARACTER_CERTIFICATE_PIN
```

Replace the server address and pin with the values from steps 1 and 2. The agent prompts for the one-time token without echoing it to the terminal. The token is not written to the configuration file.

After successful enrolment, the agent saves its server URL, certificate pin, agent ID and per-agent HMAC key in:

```text
%LOCALAPPDATA%\NetworkRadar\agent.dat
```

The file contents are protected with Windows DPAPI for the current Windows user. Copying the file to another Windows account or computer does not make the stored key usable there.

## 5. Send inventory

The enrolment command sends the first inventory report automatically. To send a one-off update later:

```powershell
python .\networkradar_agent.py --once
```

To run continuously at the default five-minute interval:

```powershell
python .\networkradar_agent.py
```

To use a different interval between 60 and 3600 seconds:

```powershell
python .\networkradar_agent.py --interval 600
```

To explicitly include BIOS and disk serial numbers in a report:

```powershell
python .\networkradar_agent.py --once --include-serial
```

Serial numbers are omitted by default. The `--include-serial` option must be supplied on each run where serials should be included.

## 6. View the endpoint dossier

When the report reaches NetworkRadar, the server associates it with an inventory device by the server-observed source IP or a matching endpoint network-adapter MAC. Hostnames alone are not used as join keys because they are client-supplied and may be duplicated. Open the device in the dashboard and select **Hardware** to view:

- endpoint-reported manufacturer and exact model;
- system family and BIOS version;
- CPU model, core count and logical processors;
- physical memory;
- disk models, sizes and interfaces;
- operating-system caption, version, build and architecture;
- network adapter names, MAC addresses, link status and IP addresses;
- agent status and last report time.

Endpoint inventory is shown separately from network-derived evidence. It is a device-reported inventory snapshot, not cryptographic proof that a machine's firmware or operating system is truthful. NetworkRadar does not silently overwrite a network-derived model guess with endpoint-reported data.

## Security boundaries

- The hub must be explicitly enabled and configured with TLS certificate and key files.
- The endpoint pins the certificate fingerprint; it does not accept a changed or unknown certificate.
- Every report is authenticated with a per-agent HMAC key, timestamp and random nonce. The server rejects stale timestamps, invalid signatures and replayed nonces.
- Enrolment uses a hashed, single-use, 15-minute token.
- The client advertises only the `inventory-report` capability.
- The client never polls `/agent/v1/commands` and does not implement remote command execution.
- The server enforces advertised capability boundaries before queuing or delivering commands.
- Revoking the agent in NetworkRadar prevents further authenticated reports.

This agent is intended only for computers you own or are explicitly authorised to inventory.
