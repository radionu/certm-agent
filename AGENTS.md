# CertM Agent project instructions

## Ownership and communication

- The user owns the operational requirements and performs sysadmin deployment and testing.
- Codex owns implementation, repository hygiene, tests, pull requests, release preparation, and Git history.
- Explain outcomes and provide short copy/paste commands for operators. Do not require the user to understand code, build packages, or manually upload release artifacts.

## Repository scope

- This repository contains exactly two supported agent implementations: `linux/` and `windows/`.
- RHEL, AlmaLinux, Rocky Linux, Ubuntu, and Debian all use the unified Linux agent. Do not restore a separate `rhel-nginx` agent.
- `tests/` and `.github/workflows/` are required repository support and are never installed on clients.
- CertM server code belongs in `radionu/certm`, not here.
- Never install the agent on the CertM/Plesk server.

## Workspace check

Before editing:

1. Confirm the checkout path with `pwd`.
2. Run `git status --short --branch`, `git remote -v`, and `git log -1 --oneline`.
3. Prefer the shared checkout `/workspace/certm-agent` when it is available.
4. A scratch checkout is temporary. Do not assume that another conversation's scratch directory is the shared workspace.
5. If no checkout is visible, check the configured workspace first, then clone the repository once. State clearly which checkout is being used.

## Git workflow

- Git is the source of truth. Do not edit production clients or GitHub `main` directly.
- Start from an up-to-date `origin/main` and create a focused branch.
- Make local file changes, run the relevant Linux and Windows validation, commit, push, open a pull request, wait for CI, then squash-merge.
- Prefer normal Git over SSH from the connected workspace.
- HTTPS is acceptable for cloning the public repository. It is a transport, not a replacement for the branch/commit/PR workflow.
- GitHub App/Contents API writes are fallback only when the shell cannot push. If used, say so explicitly, write only to a feature branch, avoid one commit per file, open a PR, and never update `main` file-by-file.
- Report the final branch, PR, merge commit, tag, release, and CI result.
- Preserve unrelated user changes and do not rewrite published history to clean up cosmetic commit issues.

## Agent behavior that must not regress

- Linux and Windows run one unified six-hour certificate task. Software update checking happens inside that task.
- Windows uses the native PowerShell `ScheduledTasks` module; do not reintroduce a hard dependency on `schtasks.exe`.
- Windows bootstrap must force TLS 1.2 before downloading and must stop cleanly when download fails.
- Installation must preserve an existing client identity unless intentional re-enrollment is explicitly requested.
- Clients download approved update packages from the authenticated CertM server, not directly from GitHub.
- New source IP addresses remain blocked until approved in CertM.

## Release workflow

- Do not create a new agent version for documentation-only changes.
- For code changes, update both package manifests/version constants as required, validate both platforms, merge first, then tag and publish one official GitHub release.
- A release must contain Linux and Windows packages, `SHA256SUMS`, valid manifests, and CI-built artifacts.
- CertM imports official GitHub releases as DRAFT. An administrator tests selected clients before approving a version for AUTO clients.
