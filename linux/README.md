# CertM Linux Agent 1.0.0-rc.12

One pull-based API v2 agent and installer for:

| Distribution family | nginx | Apache |
|---|---:|---:|
| Ubuntu / Debian | Supported | Supported (`apache2`) |
| RHEL / AlmaLinux / Rocky Linux | Supported | Supported (`httpd`) |

The installer detects the distribution, active web server, systemd unit, control
binary, configuration root, and a Python interpreter version 3.8 or newer. One
installed agent manages one web server. If nginx and Apache are both active, pass
`--web-server nginx` or `--web-server apache` explicitly.

## Install from the public repository

No GitHub account, token, or SSH key is needed.

Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

RHEL, AlmaLinux, or Rocky Linux:

```bash
sudo dnf install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

Specify the web server only when auto-detection would be ambiguous:

```bash
sudo ./install.sh --web-server apache --display-name 'Apache Production 01'
```

The installer performs local checks before writing CertM configuration or asking
for an enrollment key. It then runs the full preflight and enrolls only after the
environment is valid. It preserves an existing client token, display name, state,
backups, logs, and timer state during upgrades.

On AlmaLinux/RHEL 8 with only Python 3.6, install Python 3.9 first:

```bash
sudo dnf install -y python39
```

The installer selects Python 3.9 directly and does not replace the operating
system's `python3` command.

## Upgrade

```bash
sudo git -C /opt/certm-agent-src pull --ff-only origin main
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

RHEL/nginx installations now use this unified installer directly. The obsolete
`rhel-nginx/` compatibility wrapper is no longer part of the repository.

The installer also enables `certm-agent-update.timer`. It checks CertM every 15
minutes, but installs only a version allowed by the server's AUTO/MANUAL policy.
The separate update service shares `/run/certm-agent.lock` with certificate work,
verifies SHA-256, RSA signature, and every manifest file, and rolls back the
runtime when its self-test fails. Configuration, client identity, certificate
state, backups, and logs are not part of the replaced runtime set.

## Command flow

`discover` is optional and read-only. `preflight`, `inventory`, and `renew` always
perform discovery themselves.

A renewal submits one inventory before evaluating desired certificates. It
submits a second, freshly discovered inventory only after a certificate or web
server configuration was actually changed. No-change and dry-run renewals
therefore create one inventory event.

```bash
sudo /opt/certm-agent/certm-agent.py discover
sudo /opt/certm-agent/certm-agent.py preflight
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew
sudo systemctl enable --now certm-agent.timer
```

Before the supervised test, keep the timer stopped to avoid overlapping runs:

```bash
sudo systemctl stop certm-agent.timer
```

## Discovery and deployment safety

nginx discovery uses `nginx -T`. Apache discovery uses the running Apache build's
`HTTPD_ROOT`, `SERVER_CONFIG_FILE`, and included configuration files. Both adapters:

- accept only concrete DNS names and HTTPS virtual hosts;
- reject variable certificate paths and ambiguous domain/port mappings;
- restrict certificate and configuration paths to configured safety roots;
- group virtual hosts that share certificate files;
- split configuration safely when separate virtual hosts need different CertM profiles;
- refuse different assignments inside one indivisible virtual-host block;
- validate certificate/key matching, fullchain order, and hostname coverage;
- back up files, write atomically, test syntax, reload, and verify the served SNI fingerprint;
- roll back the complete file/config set if validation or served verification fails.

For modern Apache configurations, CertM writes a full chain to
`SSLCertificateFile`. Existing legacy `SSLCertificateChainFile` configurations are
also supported; the leaf and chain files are updated separately until a config
split is required, after which the managed fullchain form is used.

The installer configures a conservative systemd `LimitNOFILE` floor of `4096`
only when the selected web server currently has a lower limit; it never lowers a
higher existing value. Preflight attempts to raise the running master process to
that floor without restarting the web server and records the result in the agent
log. If the live adjustment cannot be applied, deployment still uses normal reload
verification and complete rollback on failure. After reload, the agent confirms a
new worker generation was actually created instead of trusting a successful exit.

## Files and logs

- Configuration: `/etc/certm/agent.json` (mode `0600`)
- Runtime: `/opt/certm-agent`
- Managed certificates: `/etc/certm/live`
- State: `/var/lib/certm/bindings`
- Backups: `/opt/certm-agent/bkup`
- Log: `/var/log/certm/certm-agent.log`

Log timestamps use fixed `UTC+07:00`. Protocol, certificate-validity, and state
timestamps remain UTC.

Exactly one credential is stored: the enrollment credential before enrollment,
or the client credential afterward. Successful enrollment removes the enrollment
credential. Inventory reports hostname, `display_name`, web-server type, and the
running agent version on every run.

## API v2

| Purpose | Endpoint |
|---|---|
| Preflight | `GET /api/v2/client/preflight` |
| Enrollment | `POST /api/v2/client/enroll` |
| Client state | `GET /api/v2/client/status` |
| Inventory | `POST /api/v2/client/inventory` |
| Desired package | `GET /api/v2/cert/desired?domain=...` |
| PEM download | `GET /api/v2/cert/download?domain=...&service=nginx|apache&port=...&format=pem` |
| Verified report | `POST /api/v2/deployment/report` |
