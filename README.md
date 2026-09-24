# CertM Agent

Public pull-based deployment agents for CertM.

CertM has two agent implementations:

- `linux/` — unified API v2 agent for nginx and Apache on Ubuntu, Debian,
  RHEL, AlmaLinux, and Rocky Linux;
- `windows/` — native API v2 agent for Windows Server + IIS.

The other top-level directories are repository support files, not additional agents:

| Path | Purpose | Installed on managed servers |
|---|---|---:|
| `tests/` | Automated Linux safety tests and Windows contract validation | No |
| `.github/workflows/` | Runs the test suite on Linux and Windows | No |

The obsolete `rhel-nginx/` compatibility wrapper has been removed. RHEL,
AlmaLinux, Rocky Linux, Ubuntu, and Debian all use the unified `linux/` agent.
The `tests/` directory remains because it prevents unsafe agent releases; it is
never copied to managed servers.

This repository intentionally contains no enrollment keys, client tokens, private keys, production configuration, or CertM server-side source.

## Linux: nginx and Apache

The repository is public. HTTPS clone requires no GitHub account, SSH key,
personal access token, or stored Git credentials.

On Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

On RHEL, AlmaLinux, or Rocky Linux:

```bash
sudo dnf install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

The installer auto-detects nginx or Apache. If both are active, choose one:

```bash
sudo ./install.sh --web-server apache --display-name 'Apache Production 01'
```

Keep `/opt/certm-agent-src` as the source checkout; the installed runtime is
separate in `/opt/certm-agent`.

The first upgrade from an agent without the managed updater must be installed
from the public checkout. Version 1.0.0-rc.11 introduced this one-time
bootstrap requirement:

```bash
sudo git -C /opt/certm-agent-src pull --ff-only origin main
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

Version 1.0.0-rc.13 consolidates software updates and certificate work into one
six-hour cycle. `certm-agent.timer` activates `certm-agent.service`; the oneshot
service first checks and installs an approved agent release, then starts the
newly installed agent for certificate inventory and renewal. An update failure
is logged but does not block certificate work. The updater verifies the package
SHA-256, RSA signature, and manifest, performs a self-test, and restores the
previous runtime if installation fails.

Only `certm-agent.timer` is enabled. The legacy `certm-agent-update.timer` and
service are retired automatically after an RC12 client installs RC13.

Version 1.0.0-rc.14 adds clear handling for CertM's multiple-source-IP approval
policy. When a valid client reaches CertM through a new hospital WAN address,
the server records the address for administrator review and blocks certificate
and agent-update operations. Linux and Windows logs now identify the observed
source IP and state that administrator approval is required instead of showing
only a generic HTTP 403 error.

Version 1.0.0-rc.15 makes the Windows agent refresh IIS inventory immediately
after a successful certificate deployment. When one certificate is installed
on multiple hostname bindings, CertM now changes every affected domain to `OK`
in the same run instead of leaving all but the deployment's primary domain with
a stale pre-deployment status until the next six-hour cycle.

Version 1.0.0-rc.16 makes initial Windows enrollment failures actionable. The
first enrollment attempt no longer runs a premature update check, connection
failures identify the CertM API and the DNS, TCP 443, firewall/proxy, clock, and
TLS trust checks to perform, and the installer prints the final agent error
instead of replacing it with a generic installer exit code.

Version 1.0.0-rc.17 enables SNI before assigning a certificate to an IIS
hostname binding that did not already require SNI. This prevents HTTP.sys from
continuing to serve the default IP:port certificate on shared `*:443` bindings.
If installation or live TLS verification fails, the agent restores both the
previous certificate and the original IIS SSL flags.

Version 1.0.0-rc.18 identifies certificate substitution performed by Kaspersky
Endpoint Security during local TLS verification. It still rolls IIS back and
reports the deployment as failed, but now sends the observed certificate
subject, issuer, and fingerprint with a dedicated
`TLS_INTERCEPTION_DETECTED` code so CertM operators can keep, suspend, or
remove the affected assignment without treating it as an IIS repair.

Version 1.0.0-rc.19 stops nginx deployments from overwriting certificate and
private-key files owned by Certbot or another local tool. Version 1.0.0-rc.20
makes the CertM-owned versioned paths readable for operators: wildcard
`*.pmr.vn` uses `/etc/certm/live/pmr.vn/<deployment-revision>/`, while an
exact certificate uses its full domain. nginx configuration is updated only
after staging, then tested, reloaded, and verified with full rollback on failure.
Existing RC19 ID-based directories are left untouched when nginx migrates to the
new path.

The unified installer requires Python 3.8 or newer. It validates OpenSSL, the
selected web server, systemd, machine ID, configuration syntax, certificate/key
pairs, local write paths, reload capacity, and CertM API reachability before
enrollment. On AlmaLinux/RHEL 8, `python39` is supported without changing the
operating system's `python3` command.

The agent discovers current HTTPS vhosts on every run. The standalone `discover`
command is optional and read-only; preflight, inventory, and renewal discover
automatically. See `linux/README.md` before enabling the systemd timer.

Both agents support an optional `display_name` configuration value for a human-friendly server label. A new Linux installation asks for this value and always writes the field to `/etc/certm/agent.json`; upgrades add an empty field when an older configuration does not have it. The real operating-system hostname is reported independently on every inventory run. Changing a hostname therefore does not require re-enrollment as long as the machine ID and client token remain valid.

Every authenticated API call includes the running agent type and version. Inventory also
includes `agent_version`, allowing CertM to refresh an existing client's displayed version
after an upgrade without re-enrollment.

Agent log lines use the fixed Vietnam offset `UTC+07:00` and include `+07:00` in every timestamp. Protocol, certificate-validity, and state timestamps remain UTC.

## Windows/IIS

The Windows agent:

- creates a stable identity from the Windows `MachineGuid`;
- uses the API v2 preflight, enrollment, approval, desired/download, inventory, and deployment-report flow;
- protects enrollment and client tokens with Windows DPAPI (`LocalMachine` scope);
- inventories IIS HTTPS/SNI bindings and reports whether each IIS site is started or stopped;
- downloads a short-lived password-protected PFX package;
- imports the leaf and chain into `LocalMachine\My` without an exportable private key;
- updates only selected IIS bindings;
- verifies the SHA-256 fingerprint actually served by IIS using SNI;
- rolls bindings back when installation or verification fails;
- tracks `deployment_revision`, so a rebuilt package is applied even when the leaf fingerprint is unchanged.

The current release skips HTTPS bindings without a host name because CertM v2 selects certificates by domain. It also skips IIS Central Certificate Store bindings rather than silently changing them to direct certificate bindings.

Bindings from stopped or otherwise inactive IIS sites remain visible in inventory, but the
agent does not download a certificate, change the binding, or attempt live TLS verification
for them. Each skipped binding is recorded in the agent log. Once the site is started, the
next scheduled run evaluates and deploys its desired certificate normally.

### Requirements

- Windows Server 2016 or later
- IIS with the WebAdministration PowerShell module
- Windows PowerShell 5.1
- outbound HTTPS access to CertM
- CertM API v2 PFX download support
- an elevated PowerShell window for installation

### Install

For a new server, open PowerShell as Administrator and run one command:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
```

The bootstrap downloads the complete Windows agent, asks the operations engineer for the
bootstrap credential using a secure prompt, installs the agent, enrolls immediately, and
enables the Scheduled Task every six hours. The credential is not placed in the command
history or logs. After successful enrollment, the bootstrap credential field is removed
from `C:\CertM\config.json`; only the DPAPI-protected, client-specific identity remains.

An optional friendly name can be supplied without exposing the credential:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -DisplayName 'IIS Download Production'
```

Use `-Staged` when the machine requires the supervised discovery/dry-run workflow. The
bootstrap then enrolls once but leaves the task disabled.

### Manual installation and recovery

Use this procedure when the one-command bootstrap cannot download from GitHub, or when
the operations team needs to install from files copied through another approved channel.
Download the repository ZIP from
`https://github.com/radionu/certm-agent/archive/refs/heads/main.zip`, extract it, and copy
these four files from `windows/` into one directory such as `C:\Temp\CertM-Agent`:

- `CertM.Agent.ps1`
- `CertM.Update.ps1`
- `Install-CertMAgent.ps1`
- `Uninstall-CertMAgent.ps1`

The files may also be downloaded on another trusted administrator workstation and copied
to the server. Keep all four files in the same directory. Open PowerShell as Administrator,
then run:

```powershell
Set-Location 'C:\Temp\CertM-Agent'
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Filter '*.ps1' | Unblock-File

$secureCredential = Read-Host 'Enter the CertM operations bootstrap credential' -AsSecureString
$credentialPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCredential)
try {
    $plainCredential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($credentialPointer)
    .\Install-CertMAgent.ps1 `
        -ApiBase 'https://certm.pmr.vn/api/v2' `
        -DisplayName 'IIS Download Server' `
        -EnrollmentToken $plainCredential `
        -RunOnce `
        -EnableTask
}
finally {
    $plainCredential = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
}
```

This command performs initial enrollment and enables the six-hour task. For a supervised
staged installation, omit `-EnableTask`; the installer will run once for enrollment but
leave the task disabled until an administrator enables it.

The installer uses the PowerShell `ScheduledTasks` module to create a normal native Windows
Task Scheduler task. It does not replace or bypass Windows Task Scheduler; it only avoids
calling the separate `schtasks.exe` command-line program.

The default installer behavior without `-RunOnce` or `-EnableTask` is staged: it creates
the scheduled task in a disabled state and does not run the agent. This prevents enrollment
or certificate changes from racing ahead of administrator validation.

The enrollment key is only a non-empty, administrator-rotatable bootstrap gate against unsolicited enrollment. It has no minimum length requirement and is not a long-lived client credential. A successful enrollment replaces it locally with a unique client token and removes the enrollment-token field completely. Exactly one credential field exists at a time. Windows protects the active credential with DPAPI; Linux protects its configuration with mode `0600`. Rotating the enrollment key affects only future enrollments.

Every IIS HTTPS binding with a host name is evaluated dynamically on each run. There is no static domain allowlist in the agent configuration. CertM returns a deployment only when a certificate assigned to that client covers the binding domain.

To upgrade an existing installation while preserving its DPAPI-protected client identity, run the installer without an enrollment token:

```powershell
.\Install-CertMAgent.ps1 -DisplayName 'IIS Download Server'
```

An existing installation also preserves whether `CertM IIS Agent` was enabled
or disabled. That single six-hour task checks for approved agent updates before
running certificate work. The installer does not run a certificate cycle unless
`-RunOnce` is supplied explicitly.

Inspect current IIS bindings without contacting CertM or changing certificates:

```powershell
& 'C:\CertM\bin\CertM.Agent.ps1' -Mode Discover
```

Enroll a new client after discovery has been reviewed. Enrollment exits without changing IIS while the client waits for administrator approval:

```powershell
& 'C:\CertM\bin\CertM.Agent.ps1'
```

After client approval, evaluate desired changes without importing a PFX or changing IIS:

```powershell
& 'C:\CertM\bin\CertM.Agent.ps1' -Mode DryRun
```

After reviewing the dry run, perform one supervised deployment and only then enable automation:

```powershell
& 'C:\CertM\bin\CertM.Agent.ps1'
Enable-ScheduledTask -TaskName 'CertM IIS Agent'
```

The installer creates:

- task `CertM IIS Agent`, running as `SYSTEM` at the configured interval and disabled by default;
- no separate update task; the same task checks software updates first;
- program directory `C:\CertM\bin`;
- protected configuration `C:\CertM\config.json`;
- state file `C:\CertM\state.json` after the first deployment;
- log file `C:\CertM\logs\agent.log`;
- temporary PFX staging directory `C:\CertM\staging`.

After the initial run, approve the new client in the CertM dashboard. To retry immediately:

```powershell
Start-ScheduledTask -TaskName 'CertM IIS Agent'
Get-Content 'C:\CertM\logs\agent.log' -Tail 50
```

Operators can also press `Win+R`, run `taskschd.msc`, open **Task Scheduler Library**, and
select **CertM IIS Agent**. The task's General, Triggers, Actions, History, Last Run Time,
Last Run Result, and Next Run Time remain visible through the standard Windows interface.

Equivalent PowerShell checks are:

```powershell
Get-ScheduledTask -TaskName 'CertM IIS Agent' |
    Select-Object TaskName, State

Get-ScheduledTaskInfo -TaskName 'CertM IIS Agent' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
```

### Uninstall

Keep configuration, state, and logs:

```powershell
.\Uninstall-CertMAgent.ps1
```

Remove all CertM agent data as well:

```powershell
.\Uninstall-CertMAgent.ps1 -RemoveData
```

### API v2 compatibility

| Purpose | Endpoint |
|---|---|
| Preflight | `GET /api/v2/client/preflight` |
| Enrollment | `POST /api/v2/client/enroll` |
| Client state | `GET /api/v2/client/status` |
| IIS inventory | `POST /api/v2/client/inventory` |
| Desired package | `GET /api/v2/cert/desired?domain=...` |
| PFX download | `GET /api/v2/cert/download?domain=...&service=iis&port=...&format=pfx` |
| Verified report | `POST /api/v2/deployment/report` |
| Agent update check | `GET /api/v2/client/agent-update` |
| Agent update report | `POST /api/v2/client/agent-update/report` |

All authenticated calls send both the bearer token and `X-CertM-Machine-ID`.
