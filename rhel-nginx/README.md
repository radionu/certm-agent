# CertM nginx Agent 1.0.0-rc.1

Public pull-based API v2 agent for RHEL-family Linux and nginx.

## Dynamic discovery

The agent runs `nginx -T` at the start of every `discover`, `inventory`, and `renew` operation. Domains and certificate paths are not stored in `agent.json`.

It discovers concrete DNS names from HTTPS `server` blocks containing:

- a `listen ... ssl` directive;
- one or more concrete `server_name` values;
- exactly one `ssl_certificate` path;
- exactly one `ssl_certificate_key` path.

IPv4 and IPv6 listeners for the same domain and port are deduplicated. A newly added vhost appears in the next inventory. A removed vhost is omitted, allowing CertM to mark its previous binding as `REMOVED`.

For safety, the agent skips regex, wildcard, variable, and hostless `server_name` values; variable certificate paths; dual RSA/ECDSA certificate blocks; and paths outside `discovery.allowed_certificate_roots`.

## Shared certificate paths

Multiple domains may use the same nginx certificate/key paths. CertM replaces that pair only when every discovered domain sharing it:

1. has an active certificate assignment; and
2. resolves to the same certificate version and package revision.

The downloaded certificate must cover every concrete domain in the group. Otherwise the files are not changed.

## Install or upgrade

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
chmod +x install.sh
sudo ./install.sh
```

The installer preserves the existing token, migrates a version 2 config to version 3, and removes obsolete static `management.bindings` data. Review `discovery.allowed_certificate_roots` after an upgrade.

## Commands

Local discovery without changing certificates:

```bash
sudo /opt/certm-agent/certm-agent.py discover
```

Validate the host and enroll or check identity:

```bash
sudo /opt/certm-agent/certm-agent.py preflight
```

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

Before modifying nginx, the agent validates API metadata, base64 encoding, certificate/private-key matching, fullchain order, and coverage for all domains sharing the target paths. It backs up the current files, writes atomically, restores SELinux contexts when `restorecon` is available, runs `nginx -t`, reloads nginx, and verifies the served SHA-256 fingerprint through SNI.

If validation, reload, or served-certificate verification fails, the previous complete certificate/key pair is restored and nginx is revalidated and reloaded.

Do not enable the timer until `discover` and `renew --dry-run` have been reviewed on that server.

```bash
sudo systemctl enable --now certm-agent.timer
```

For production, install a reviewed release tag rather than following `main`.
