# CertM Agent

Public pull-based deployment agents for CertM.

Current implementations:

- `rhel-nginx/` — native API v2 agent for RHEL-family Linux + nginx.
- `windows/` — native API v2 agent for Windows Server + IIS.

This repository intentionally contains no enrollment keys, client tokens, private keys, production configuration, or CertM server-side source.

## RHEL/nginx

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
sudo ./install.sh
```

See `rhel-nginx/README.md` before enabling the systemd timer.

## Windows/IIS

The Windows agent is an initial operational release. It:

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
  -EnrollmentToken 'PASTE_ENROLLMENT_KEY' `
  -ManagedDomains '*.pmr.vn'
```

An empty `ManagedDomains` list allows every IIS HTTPS binding with a host name to be evaluated. CertM returns a deployment only when the certificate assigned to the client covers that domain.

The installer creates:

- task `CertM IIS Agent`, running as `SYSTEM` every 30 minutes;
- program directory `C:\ProgramData\CertM\bin`;
- protected configuration `C:\ProgramData\CertM\config.json`;
- state file `C:\ProgramData\CertM\state.json` after the first deployment;
- log file `C:\ProgramData\CertM\logs\agent.log`.

After the initial run, approve the new client in the CertM dashboard. To retry immediately:

```powershell
Start-ScheduledTask -TaskName 'CertM IIS Agent'
Get-Content 'C:\ProgramData\CertM\logs\agent.log' -Tail 50
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
