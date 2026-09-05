# CertM nginx Agent 1.0.0-rc.6

Public pull-based API v2 agent for RHEL-family Linux and nginx.

## Dynamic discovery

The agent runs `nginx -T` at the start of every `discover`, `inventory`, and `renew` operation. Domains and certificate paths are not stored in `agent.json`.

Running the standalone `discover` command is optional. It is a read-only diagnostic command
that prints what the agent currently sees. Installation runs a full `preflight`, and
`preflight`, `inventory`, and `renew` perform their own fresh discovery automatically.

`display_name` is an optional friendly server label. The agent always reports the current operating-system hostname separately on each inventory run, so renaming the host does not require re-enrollment while its machine ID and client token remain unchanged.

Before enrollment, `agent.json` contains `enrollment_token`. After CertM returns the unique client credential, the agent writes `client_token` and removes `enrollment_token` completely. The bootstrap enrollment key is never retained after successful enrollment.

It discovers concrete DNS names from HTTPS `server` blocks containing:

- a `listen ... ssl` directive;
- one or more concrete `server_name` values;
- exactly one `ssl_certificate` path;
- exactly one `ssl_certificate_key` path.

IPv4 and IPv6 listeners for the same domain and port are deduplicated. A newly added vhost appears in the next inventory. A removed vhost is omitted, allowing CertM to mark its previous binding as `REMOVED`.

For safety, the agent skips regex, wildcard, variable, and hostless `server_name` values; variable certificate paths; dual RSA/ECDSA certificate blocks; and paths outside `discovery.allowed_certificate_roots`.

## Shared certificate paths and profile separation

Multiple domains may initially use the same nginx certificate/key paths. When every domain sharing the paths resolves to the same CertM package, the agent can safely update that shared pair as one group.

When separate nginx `server {}` blocks sharing the current paths resolve to different CertM profiles, the agent automatically:

1. downloads and validates every required package before changing nginx;
2. writes each package below `paths.managed_certificate_root/certificate-<profile-id>/`;
3. changes only the `ssl_certificate` and `ssl_certificate_key` directives in the affected server blocks;
4. runs `nginx -t`, reloads nginx, and verifies each served SNI fingerprint;
5. restores both config files and certificate files if any step fails.

An unassigned server block remains on its current paths. If domains with different assignments are listed together in one `server_name` directive, the agent refuses the change because one nginx server block can use only one certificate pair. Split those names into separate server blocks first.

Only config files below `discovery.allowed_config_roots` may be edited. The source block must still exactly match the last `nginx -T` result, preventing changes based on stale discovery data.

## Install or upgrade

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
chmod +x install.sh
sudo ./install.sh
```

The installer first checks for root access, Python 3.8+, OpenSSL, nginx, systemd, a machine
ID, an active nginx unit, and a valid `nginx -t`. It stops before creating CertM files or
asking for an enrollment key if any prerequisite fails. On AlmaLinux/RHEL 8 with only the
system Python 3.6, install a supported interpreter first:

```bash
sudo dnf install -y python39
```

The installer selects a Python 3.8+ executable and pins the installed agent shebang to it;
`python3` does not need to be repointed system-wide. It then preserves or creates the
configuration, installs the files, performs a full preflight, and enrolls a new client only
after every local check and the read-only CertM API preflight succeed. The systemd timer
remains disabled.

During an upgrade the installer preserves the existing token, migrates a version 2 config
to version 3, and removes obsolete static `management.bindings` data. Review
`discovery.allowed_certificate_roots` after an upgrade.

## Commands

Optional local discovery without contacting CertM or changing certificates:

```bash
sudo /opt/certm-agent/certm-agent.py discover
```

Repeat the full host validation and interactively enroll or check identity:

```bash
sudo /opt/certm-agent/certm-agent.py preflight
```

The full preflight checks Python, OpenSSL, nginx, `nginx -t`, the active systemd unit,
machine ID, configuration permissions, every discovered certificate/key pair, writable
certificate/config paths, the managed certificate directory, and CertM API reachability.

Submit inventory only:

```bash
sudo /opt/certm-agent/certm-agent.py inventory
```

Evaluate desired deployments without changing certificate files:

```bash
sudo /opt/certm-agent/certm-agent.py renew --dry-run
```

Perform a normal renewal run:

```bash
sudo /opt/certm-agent/certm-agent.py renew
```

## Deployment safety

Before modifying nginx, the agent validates API metadata, base64 encoding, certificate/private-key matching, fullchain order, and domain coverage. It backs up the current files and any config files involved in a profile split, writes atomically, preserves existing ownership and permissions, restores SELinux contexts when `restorecon` is available, runs `nginx -t`, reloads nginx, and verifies the served SHA-256 fingerprint through SNI.

If validation, reload, or served-certificate verification fails, the previous complete certificate/key pair is restored and nginx is revalidated and reloaded.

Do not enable the timer until `discover` and `renew --dry-run` have been reviewed on that server.

```bash
sudo systemctl enable --now certm-agent.timer
```

For production, install a reviewed release tag rather than following `main`.
