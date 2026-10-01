# CertM Agent

[Tiếng Việt](README_vi.MD) · [Version history](CHANGELOG.md) · [Technical notes](docs/TECHNICAL_NOTES.md)

CertM Agent connects a server or firewall to CertM. It finds the HTTPS sites on
that system, reports their current certificates, and installs certificates that
an administrator has assigned in CertM.

The agent runs from the managed system. It does not require CertM to log in to
the server, and it does not issue certificates by itself.

## Supported agents

| System | Service | Agent |
|---|---|---|
| Ubuntu / Debian | nginx, Apache, Zimbra 9 single server | Linux agent |
| RHEL / AlmaLinux / Rocky Linux | nginx, Apache | Linux agent |
| Windows Server 2016 or later | IIS | Windows agent |
| pfSense CE / Plus | HAProxy package | pfSense HAProxy agent |

Before installing, ask the CertM administrator for the operations bootstrap
credential. The new client and its source IP may need approval in CertM before
certificate assignments become available.

## Linux agent: nginx, Apache and Zimbra

The same Linux agent is used for nginx, Apache and Zimbra. Run all installation
commands as `root` or through `sudo`.

Requirements:

- Python 3.8 or later;
- outbound HTTPS access to CertM;
- an active nginx or Apache service, or a supported Zimbra installation;
- `systemd`.

### Automatic installation

Ubuntu or Debian:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

RHEL, AlmaLinux or Rocky Linux:

```bash
sudo dnf install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

The installer normally detects nginx or Apache. If both are running, select the
service explicitly:

```bash
sudo ./install.sh --web-server nginx --display-name 'Web Server 01'
sudo ./install.sh --web-server apache --display-name 'Web Server 01'
```

For Zimbra, use the same Linux source:

```bash
cd /opt/certm-agent-src
sudo bash linux/install.sh --web-server zimbra --display-name 'Zimbra Mail 01'
```

Enter the bootstrap credential when asked. Installation enrolls the system but
does not immediately change a certificate.

### Manual installation

Use this method when Git is unavailable on the server:

1. Download the repository ZIP on a trusted administrator computer:
   `https://github.com/radionu/certm-agent/archive/refs/heads/main.zip`
2. Copy the ZIP to the server and extract it.
3. Run the same installer from the extracted `linux` directory.

Example:

```bash
cd /tmp/certm-agent-main/linux
sudo ./install.sh --web-server nginx --display-name 'Web Server 01'
```

For Zimbra:

```bash
cd /tmp/certm-agent-main
sudo bash linux/install.sh --web-server zimbra --display-name 'Zimbra Mail 01'
```

### Validate and enable nginx or Apache

After the CertM administrator approves the client and assigns certificates:

```bash
sudo /opt/certm-agent/certm-agent.py inventory
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew
sudo systemctl enable --now certm-agent.timer
```

### Validate and enable Zimbra

A Zimbra deployment restarts Zimbra services. Run the first deployment during a
maintenance period. For an urgent expired-certificate repair, the administrator
may explicitly allow a run outside the normal window:

```bash
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew --emergency
sudo /opt/certm-agent/certm-agent.py verify
sudo systemctl enable --now certm-agent.timer
```

Without `--emergency`, Zimbra certificate changes are made only during the
configured maintenance window. The `verify` command checks the installed
certificate and Zimbra services without changing them or restarting Zimbra.

### Linux checks and logs

```bash
sudo systemctl status certm-agent.timer --no-pager
sudo systemctl list-timers certm-agent.timer --all
sudo tail -n 100 /var/log/certm/certm-agent.log
sudo journalctl -u certm-agent.service -n 100 --no-pager
```

Run the complete scheduled cycle immediately. This may install an approved
agent update and deploy assigned certificates:

```bash
sudo systemctl start certm-agent.service
```

Important locations:

- Configuration: `/etc/certm/agent.json`
- Agent: `/opt/certm-agent`
- Log: `/var/log/certm/certm-agent.log`
- Backups: `/opt/certm-agent/bkup`
- Managed certificates: `/etc/certm/live`

When asking the CertM administrator for help, send the last 100 lines of the
agent log and the output of `systemctl status certm-agent.timer`.

## Windows IIS agent

Requirements:

- Windows Server 2016 or later;
- IIS and the WebAdministration PowerShell module;
- Windows PowerShell 5.1;
- outbound HTTPS access to CertM;
- an Administrator PowerShell window.

### Automatic installation

Open PowerShell as Administrator and run:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
```

The installer asks for the bootstrap credential using a hidden prompt, enrolls
the server, and creates the `CertM IIS Agent` task for a six-hour schedule.

To install with automation disabled until manual validation:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -Staged
```

### Manual installation

Use this method when the server cannot download from GitHub:

1. Download `main.zip` on a trusted administrator computer.
2. Copy these files from the `windows` directory to
   `C:\Temp\CertM-Agent`:
   `CertM.Agent.ps1`, `CertM.Update.ps1`, `Install-CertMAgent.ps1`, and
   `Uninstall-CertMAgent.ps1`.
3. Open PowerShell as Administrator and run:

```powershell
Set-Location 'C:\Temp\CertM-Agent'
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Filter '*.ps1' | Unblock-File

$secureCredential = Read-Host 'Enter the CertM operations bootstrap credential' -AsSecureString
$credentialPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCredential)
try {
    $plainCredential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($credentialPointer)
    .\Install-CertMAgent.ps1 `
        -DisplayName 'IIS Server 01' `
        -EnrollmentToken $plainCredential `
        -RunOnce `
        -EnableTask
}
finally {
    $plainCredential = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
}
```

### Windows checks and logs

After the client is approved and certificates are assigned:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Discover
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Inventory
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode DryRun
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Run
```

Check the scheduled task:

```powershell
Get-ScheduledTask -TaskName 'CertM IIS Agent'
Get-ScheduledTaskInfo -TaskName 'CertM IIS Agent' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
```

Enable or disable automation:

```powershell
Enable-ScheduledTask -TaskName 'CertM IIS Agent'
Disable-ScheduledTask -TaskName 'CertM IIS Agent'
```

Collect logs for the CertM administrator:

```powershell
Get-Content 'C:\CertM\logs\agent.log' -Tail 100
Get-Content 'C:\CertM\logs\agent-update.log' -Tail 100
```

Important locations:

- Configuration: `C:\CertM\config.json`
- Agent: `C:\CertM\bin`
- Logs: `C:\CertM\logs`
- Update staging: `C:\CertM\staging`

Do not send `config.json` to another person because it contains the protected
client identity for that Windows server.

## pfSense HAProxy agent

Requirements:

- pfSense CE or pfSense Plus;
- the pfSense HAProxy package;
- outbound HTTPS access to CertM;
- a root shell.

### Automatic installation

Run from the pfSense root shell:

```sh
fetch -qo /tmp/install-certm-pfsense.sh \
  'https://raw.githubusercontent.com/radionu/certm-agent/main/pfsense/install.sh'
/bin/sh -n /tmp/install-certm-pfsense.sh && \
  /bin/sh /tmp/install-certm-pfsense.sh
```

Enter the CertM address, display name and bootstrap credential when asked. The
installer enrolls the firewall and creates a six-hour pfSense cron entry.

### Manual installation

Use this method when the firewall cannot download files from GitHub. Copy these
files from the repository `pfsense` directory to the firewall:

- `CertM.HAProxy.Agent.php`
- `certm-haproxy`
- `config.example.json`

Then run:

```sh
mkdir -p /conf/certm
chmod 700 /conf/certm
cp /tmp/CertM.HAProxy.Agent.php /conf/certm/CertM.HAProxy.Agent.php
cp /tmp/certm-haproxy /conf/certm/certm-haproxy
cp /tmp/config.example.json /conf/certm/config.json
chmod 700 /conf/certm/CertM.HAProxy.Agent.php /conf/certm/certm-haproxy
chmod 600 /conf/certm/config.json
cp /conf/certm/certm-haproxy /usr/local/sbin/certm-haproxy
chmod 700 /usr/local/sbin/certm-haproxy
vi /conf/certm/config.json
/bin/sh /conf/certm/certm-haproxy preflight
/bin/sh /conf/certm/certm-haproxy enroll
/bin/sh /conf/certm/certm-haproxy enable
```

In `config.json`, replace the example display name and bootstrap credential
before running `enroll`.

### pfSense checks and logs

After the CertM administrator approves the client and assigns certificates:

```sh
certm-haproxy status
certm-haproxy inventory
certm-haproxy dry-run
certm-haproxy renew
certm-haproxy logs 100
```

Other operator commands:

```sh
certm-haproxy enable
certm-haproxy disable
certm-haproxy update
```

If the short command is unavailable after a pfSense upgrade, use the persistent
copy:

```sh
/bin/sh /conf/certm/certm-haproxy status
/bin/sh /conf/certm/certm-haproxy update
```

Important locations:

- Configuration and agent: `/conf/certm`
- Log: `/var/log/certm-haproxy.log`
- Scheduled job: native pfSense cron, minute 21 every six hours

For a pfSense HA pair, install initially on the configuration-primary node only.
Confirm the site's HA synchronization behavior before installing on the second
node.

## Getting help

Send the CertM administrator:

1. the client display name;
2. the command that failed;
3. the complete error shown by that command;
4. the last 100 agent log lines;
5. the approximate time when the problem occurred.

Do not send private keys, bootstrap credentials, client tokens, `config.json`, or
complete certificate packages through chat or email.
