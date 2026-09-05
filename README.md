# CertM Agent

Public pull-based deployment agents for CertM.

Current release candidate implementations:

- `rhel-nginx/` — native API v2 agent for RHEL-family Linux + nginx.
- `windows/` — native API v2 agent for Windows Server + IIS.

This repository intentionally contains no enrollment keys, client tokens, private keys, production configuration, or CertM server-side source.

## RHEL/nginx

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
sudo ./install.sh
```

The nginx agent discovers current HTTPS vhosts from `nginx -T` on every run. Its configuration contains safety roots, API identity, logging, and timeout settings, but no domain or binding list. See `rhel-nginx/README.md` before enabling the systemd timer.

Both agents support an optional `display_name` configuration value for a human-friendly server label. The real operating-system hostname is reported independently on every inventory run. Changing a hostname therefore does not require re-enrollment as long as the machine ID and client token remain valid.

## Windows/IIS

The Windows agent:

- creates a stable identity from the Windows `MachineGuid`;
- uses the API v2 preflight, enrollment, approval, desired/download, inventory, and deployment-report flow;
- protects enrollment and client tokens with Windows DPAPI (`LocalMachine` scope);
- inventories IIS HTTPS/SNI bindings;
- downloads a short-lived password-protected PFX package;
- imports the leaf and chain into `LocalMachine\My` without an exportable private key;
- updates only selected IIS bindings;
- verifies the SHA-256 fingerprint actually served by IIS using SNI;
- rolls bindings back when installation or verification fails;
- tracks `deployment_revision`, so a rebuilt package is applied even when the leaf fingerprint is unchanged.

The current release skips HTTPS bindings without a host name because CertM v2 selects certificates by domain. It also skips IIS Central Certificate Store bindings rather than silently changing them to direct certificate bindings.

### Requirements

- Windows Server 2016 or later
- IIS with the WebAdministration PowerShell module
- Windows PowerShell 5.1
- outbound HTTPS access to CertM
- CertM API v2 PFX download support
- an elevated PowerShell window for installation

### Install

Download the three PowerShell files in `windows/` to one directory, then run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-CertMAgent.ps1 `
  -ApiBase 'https://certm.pmr.vn/api/v2' `
  -DisplayName 'IIS Download Server' `
  -EnrollmentToken 'PASTE_ENROLLMENT_KEY'
```

The default installation is staged: it creates the scheduled task in a disabled state and does not run the agent. This prevents enrollment or certificate changes from racing ahead of administrator validation. `-RunOnce` and `-EnableTask` are explicit opt-ins for unattended deployments.

The enrollment key is only a non-empty, administrator-rotatable bootstrap gate against unsolicited enrollment. It has no minimum length requirement and is not a long-lived client credential. A successful enrollment replaces it locally with a unique DPAPI-protected client token; rotating the enrollment key affects only future enrollments.

Every IIS HTTPS binding with a host name is evaluated dynamically on each run. There is no static domain allowlist in the agent configuration. CertM returns a deployment only when a certificate assigned to that client covers the binding domain.

To upgrade an existing installation while preserving its DPAPI-protected client identity, run the installer without an enrollment token:

```powershell
.\Install-CertMAgent.ps1 -DisplayName 'IIS Download Server'
```

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

All authenticated calls send both the bearer token and `X-CertM-Machine-ID`.
