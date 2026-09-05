#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run install.sh as root" >&2
  exit 1
fi

echo "CertM Agent pre-install checks"

PYTHON_BIN=""
PYTHON_VERSION=""
declare -A SEEN_PYTHON=()
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
  candidate_path="$(command -v "${candidate}" 2>/dev/null || true)"
  [[ -n "${candidate_path}" ]] || continue
  [[ -z "${SEEN_PYTHON[${candidate_path}]:-}" ]] || continue
  SEEN_PYTHON["${candidate_path}"]=1
  if "${candidate_path}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    PYTHON_BIN="${candidate_path}"
    PYTHON_VERSION="$("${candidate_path}" -c 'import platform; print(platform.python_version())')"
    break
  fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
  detected="$(python3 --version 2>&1 || true)"
  echo "FAILED: Python 3.8 or newer is required; detected: ${detected:-none}" >&2
  echo "On AlmaLinux/RHEL 8, install it first with: dnf install -y python39" >&2
  exit 1
fi
echo "OK: Python ${PYTHON_VERSION} (${PYTHON_BIN})"

for command in openssl nginx systemctl install; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "FAILED: Required command not found: ${command}" >&2
    exit 1
  fi
  echo "OK: Found ${command}"
done

if [[ ! -s /etc/machine-id ]]; then
  echo "FAILED: /etc/machine-id is missing or empty" >&2
  exit 1
fi
echo "OK: Machine ID is present"

NGINX_UNIT="nginx"
if [[ -f /etc/certm/agent.json ]]; then
  NGINX_UNIT="$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
config = json.loads(Path('/etc/certm/agent.json').read_text())
print(str(config.get('service', {}).get('systemd_unit', 'nginx')).strip())
PY
)"
fi
if [[ -z "${NGINX_UNIT}" ]]; then
  echo "FAILED: service.systemd_unit must not be empty" >&2
  exit 1
fi
if [[ "$(systemctl show "${NGINX_UNIT}" --property=LoadState --value 2>/dev/null)" != "loaded" ]]; then
  echo "FAILED: systemd unit is not loaded: ${NGINX_UNIT}" >&2
  exit 1
fi
if ! systemctl is-active --quiet "${NGINX_UNIT}"; then
  echo "FAILED: systemd unit is not active: ${NGINX_UNIT}" >&2
  exit 1
fi
echo "OK: systemd unit ${NGINX_UNIT} is active"

nginx -v
openssl version
if ! nginx -t; then
  echo "FAILED: nginx configuration test failed" >&2
  exit 1
fi
echo "OK: nginx configuration syntax is valid"
echo "All pre-install checks passed; continuing with CertM setup."

install -d -m 0750 /opt/certm-agent
install -d -m 0700 /opt/certm-agent/bkup
install -d -m 0750 /etc/certm
install -d -m 0750 /etc/certm/live
install -d -m 0750 /var/log/certm
install -d -m 0700 /var/lib/certm/bindings

if [[ ! -f /etc/certm/agent.json ]]; then
  install -m 0600 "${BASE_DIR}/agent.json.example" /etc/certm/agent.json
  TOKEN=""
  while [[ -z "${TOKEN}" ]]; do
    read -r -s -p "Enter CertM enrollment key or existing client token: " TOKEN
    echo
    [[ -n "${TOKEN}" ]] || echo "Token cannot be empty."
  done
  read -r -p "Enter optional CertM display name (Enter to use hostname): " DISPLAY_NAME
  CERTM_TOKEN="${TOKEN}" CERTM_DISPLAY_NAME="${DISPLAY_NAME}" "${PYTHON_BIN}" - <<'PY'
import json
import os
from pathlib import Path
p = Path('/etc/certm/agent.json')
cfg = json.loads(p.read_text())
token = os.environ['CERTM_TOKEN']
cfg['display_name'] = os.environ.get('CERTM_DISPLAY_NAME', '').strip()
if token.startswith('ct_'):
    cfg['client_token'] = token
    cfg.pop('enrollment_token', None)
else:
    cfg['enrollment_token'] = token
    cfg.pop('client_token', None)
p.write_text(json.dumps(cfg, indent=2) + '\n')
p.chmod(0o600)
PY
else
  echo "/etc/certm/agent.json already exists; keeping existing configuration."
fi

"${PYTHON_BIN}" - <<'PY'
import json
import shutil
from pathlib import Path

path = Path('/etc/certm/agent.json')
config = json.loads(path.read_text())
version = int(config.get('config_version', 0))
if version not in (2, 3):
    raise SystemExit(f'Unsupported CertM config_version={version}')
if version == 2:
    backup = Path('/etc/certm/agent.json.pre-v3.bak')
    if not backup.exists():
        shutil.copy2(path, backup)
        backup.chmod(0o600)
config['config_version'] = 3
config.pop('management', None)
config.setdefault('display_name', '')
legacy_token = str(config.get('client_token', '')).strip()
if 'enrollment_token' not in config and legacy_token and not legacy_token.startswith('ct_'):
    config['enrollment_token'] = legacy_token
    config.pop('client_token', None)
elif legacy_token:
    config.pop('enrollment_token', None)
discovery = config.get('discovery')
if not isinstance(discovery, dict):
    discovery = {}
discovery.setdefault('max_bindings', 1000)
discovery.setdefault('allowed_config_roots', ['/etc/nginx'])
if not discovery.get('allowed_certificate_roots'):
    discovery['allowed_certificate_roots'] = [
        '/etc/certm',
        '/etc/nginx',
        '/etc/pki/tls',
        '/etc/letsencrypt',
        '/opt/certm-agent/live',
    ]
config['discovery'] = discovery
paths = config.get('paths')
if not isinstance(paths, dict):
    paths = {}
paths.setdefault('managed_certificate_root', '/etc/certm/live')
config['paths'] = paths
path.write_text(json.dumps(config, indent=2) + '\n')
path.chmod(0o600)
PY

install -m 0750 "${BASE_DIR}/certm-agent.py" /opt/certm-agent/certm-agent.py
sed -i "1s|^#!.*$|#!${PYTHON_BIN}|" /opt/certm-agent/certm-agent.py
rm -f /opt/certm-agent/certm-agent-core.py

install -m 0644 "${BASE_DIR}/systemd/certm-agent.service" /etc/systemd/system/certm-agent.service
install -m 0644 "${BASE_DIR}/systemd/certm-agent.timer" /etc/systemd/system/certm-agent.timer
systemctl daemon-reload

echo
echo "CertM Agent 1.0.0-rc.7 installed. Running full preflight before enrollment."
/opt/certm-agent/certm-agent.py preflight --enroll
echo
echo "Installation and preflight completed."
echo "The standalone discover command is optional and read-only:"
echo "  /opt/certm-agent/certm-agent.py discover"
echo "The timer remains disabled until dry-run and one supervised renewal succeed."
