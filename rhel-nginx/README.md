# CertM Agent 0.4.0 — native API v2

This is the public RHEL-family Linux + nginx agent for CertM.

## Security boundary

This repository contains only deployable agent code and examples. Do not commit enrollment keys, client tokens, certificate private keys, production `agent.json`, or CertM server-side source.

## Current status

The repository migration has started. Preflight/enrollment code, installer, safe example config, and systemd units are present. The full native-v2 renew/deploy/rollback pipeline is being moved from the private CertM server repository next. Do not enable the timer until the renew pipeline is published and manually tested.

## Clone

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
```

## Install

```bash
chmod +x install.sh certm-agent.py
sudo ./install.sh
```

If `/etc/certm/agent.json` already exists, the installer preserves it.

Agent 0.4.0 requires:

- `config_version: 2`
- `api_base` ending in `/api/v2`
- at least one `management.bindings[]` entry

## Preflight

```bash
sudo /opt/certm-agent/certm-agent.py preflight
```

The agent uses `/api/v2/client/preflight` and `/api/v2/client/enroll`.

## Upgrade workflow

For source-based test deployments:

```bash
cd /opt/certm-agent-src
git pull --ff-only
cd rhel-nginx
sudo ./install.sh
sudo /opt/certm-agent/certm-agent.py preflight
```

For production, versioned tags/releases should be used instead of blindly following `main`.
