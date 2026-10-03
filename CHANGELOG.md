# CertM Agent changelog

This file records user-visible changes. Installation and operating instructions
are kept in [README.md](README.md) and [README_vi.MD](README_vi.MD).

## 1.0.0-rc.36 (pfSense)

- Made certificate SHA-256 fingerprint verification portable across pfSense 2.7.2 and 2.8.x by hashing decoded certificate data directly.

## 1.0.0-rc.35 (pfSense)

- Fixed certificate and CA insertion on pfSense 2.7.2 without changing the HAProxy configuration format used by pfSense 2.8.x.

## 1.0.0-rc.34 (pfSense)

- Added signed pfSense updates delivered through the authenticated CertM server.
- Added automatic update checks to the existing six-hour pfSense run, with rollback and status reporting.
- Split Linux, Windows and pfSense package versions so unchanged platforms are not republished.
- Added the pfSense HAProxy agent.
- Added the persistent `certm-haproxy` operator command and six-hour pfSense cron
  schedule.
- Added support for pfSense systems where `/conf` is mounted with `noexec`.
- Added onboarding for exact HAProxy domains that do not yet have a matching
  certificate entry.
- Reported the pfSense version during every inventory, with `/etc/version` as a
  fallback, so existing CertM clients refresh without re-enrollment.
- Reorganized documentation into operator guides, this changelog and separate
  technical notes.

## 1.0.0-rc.31

- Published a no-logic-change canary to verify the embedded Windows update
  method introduced in RC30.

## 1.0.0-rc.30

- Changed Windows updates to replace only the running agent file. This reduces
  endpoint-protection alerts caused by replacing several scripts from a
  PowerShell process.
- Allowed the Windows agent to finish and report an update when endpoint
  protection terminated the legacy updater after the new runtime had already
  been installed and verified.
- Kept certificate work running when an update check fails.

## 1.0.0-rc.29

- Removed the Windows agent dependency on the native IIS ServerManager type for
  binding updates and rollback.

## 1.0.0-rc.28

- Corrected IIS assembly loading and recovery of interrupted Windows updates.

## 1.0.0-rc.27

- Corrected IIS binding handling when SSL flags contain values beyond the older
  0-3 range.

## 1.0.0-rc.26

- Corrected Zimbra trust-root enumeration.
- Refreshed the mailbox certificate view from the Java keystore.
- Verified LDAP using the configured LDAP address.

## 1.0.0-rc.25

- Completed Zimbra CA chains using cryptographically verified roots from the
  operating-system trust store.

## 1.0.0-rc.24

- Added single-server Zimbra certificate deployment, verification, rollback and
  emergency renewal.

## 1.0.0-rc.22

- Added a backward-compatible Linux launcher so older updaters can move to the
  selected Python 3.8+ runtime safely.

## 1.0.0-rc.21

- Preserved the installer-selected Python runtime during Linux agent updates.

## 1.0.0-rc.20

- Changed CertM-managed Linux certificate directories to readable domain-based
  names.

## 1.0.0-rc.19

- Stopped nginx deployments from overwriting certificate and key files owned by
  Certbot or another local tool.

## 1.0.0-rc.18

- Added clear reporting when local certificate verification sees TLS
  substitution by customer-managed endpoint protection.

## 1.0.0-rc.17

- Enabled SNI when required before assigning a certificate to an IIS hostname
  binding.
- Restored the previous certificate and IIS SSL flags after a failed deployment.

## 1.0.0-rc.16

- Improved Windows enrollment errors with checks for DNS, TCP 443, firewall or
  proxy access, clock and TLS trust.

## 1.0.0-rc.15

- Refreshed IIS inventory immediately after a successful certificate deployment.

## 1.0.0-rc.14

- Added clear log messages when a new client source IP requires administrator
  approval.

## 1.0.0-rc.13

- Combined software update checks and certificate work into one six-hour task.
- Retired the separate legacy update task.

## 1.0.0-rc.12

- Published a no-logic-change build to validate managed self-updates from RC11
  on Linux and Windows.

## 1.0.0-rc.11

- Published versioned Linux and Windows agent packages.
