#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run install.sh as root" >&2
  exit 1
fi

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
  CERTM_TOKEN="${TOKEN}" python3 - <<'PY'
import json
import os
from pathlib import Path
p = Path('/etc/certm/agent.json')
cfg = json.loads(p.read_text())
cfg['client_token'] = os.environ['CERTM_TOKEN']
p.write_text(json.dumps(cfg, indent=2) + '\n')
p.chmod(0o600)
PY
else
  echo "/etc/certm/agent.json already exists; keeping existing configuration."
fi

python3 - <<'PY'
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
rm -f /opt/certm-agent/certm-agent-core.py

install -m 0644 "${BASE_DIR}/systemd/certm-agent.service" /etc/systemd/system/certm-agent.service
install -m 0644 "${BASE_DIR}/systemd/certm-agent.timer" /etc/systemd/system/certm-agent.timer
systemctl daemon-reload

echo
echo "CertM Agent 1.0.0-rc.2 installed."
echo "Discover: /opt/certm-agent/certm-agent.py discover"
echo "Preflight: /opt/certm-agent/certm-agent.py preflight"
