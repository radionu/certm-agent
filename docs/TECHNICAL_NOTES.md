# CertM Agent technical notes

This document contains implementation information for maintainers. Operators
should use [README.md](../README.md) or [README_vi.MD](../README_vi.MD).

## Repository scope

- `linux/` contains the unified nginx, Apache and Zimbra agent.
- `windows/` contains the IIS agent.
- `pfsense/` contains the pfSense HAProxy agent.
- `tests/` and `.github/workflows/` validate changes and are not installed on
  managed systems.
- CertM server code and API documentation belong in the CertM server repository.

This repository must not contain enrollment credentials, client tokens, private
keys, production configuration or downloaded certificate packages.

## Common operating model

Agents make outbound connections to CertM. A new installation uses a temporary
operations bootstrap credential. After enrollment, the agent stores a unique
client identity locally. Certificate work remains blocked until required client
and source-IP approvals are complete.

Linux and Windows perform software update checking inside the same six-hour task
used for certificate work. pfSense runs a bounded six-hour cron job. None of the
agents requires a permanent connection from CertM to the managed system.

## Deployment safety

All agents discover the active HTTPS configuration before evaluating assigned
certificates. A deployment validates the downloaded certificate, private key,
chain, hostname coverage and expected fingerprint before changing the service.
The service configuration is tested and the certificate served to clients is
verified after the change. Failed changes are rolled back when a safe rollback
is possible.

Linux writes CertM-managed certificates to versioned paths and does not overwrite
files owned by Certbot or another certificate tool. Windows updates only selected
IIS hostname bindings. pfSense updates Certificate Manager and asks the installed
HAProxy package to regenerate and reload its configuration; it does not edit
generated HAProxy files directly.

## Local identity and configuration

- Linux stores configuration in `/etc/certm/agent.json` with mode `0600`.
- Windows protects credentials with DPAPI LocalMachine scope in
  `C:\CertM\config.json`.
- pfSense stores configuration in `/conf/certm/config.json` with mode `0600`.

Installers preserve an existing client identity unless intentional re-enrollment
is explicitly requested.

## Scheduling

- Linux: `certm-agent.timer` starts a oneshot systemd service every six hours.
- Windows: the `CertM IIS Agent` Scheduled Task runs as SYSTEM every six hours.
- pfSense: native pfSense cron runs `/bin/sh /conf/certm/certm-haproxy run` at
  minute 21 every six hours.
- Zimbra uses the Linux agent with a maintenance-aware timer. Certificate
  deployment is limited to `00:00-04:00 UTC+07` unless an operator explicitly
  uses `--emergency`.

## Updates and releases

Approved Linux and Windows updates are downloaded from the authenticated CertM
server. Packages are checked against their manifest, SHA-256 digest and release
signature before installation. An update failure must not block certificate
inventory and renewal.

The pfSense operator command currently performs a supervised refresh from the
public repository while preserving local enrollment configuration.

Documentation-only changes do not require a new agent version. Code releases
must update all relevant version constants and manifests, pass the Linux,
Windows and pfSense validation suites, and publish the required release
artifacts.
