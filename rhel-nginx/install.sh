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
install -d -m 0750 /var/log/certm
install -d -m 0700 /var/lib/certm/bindings

install -m 0640 "${BASE_DIR}/certm-agent.py" /opt/certm-agent/certm-agent-core.py
install -m 0750 "${BASE_DIR}/certm-agent-0.4.1.py" /opt/certm-agent/certm-agent.py

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
  echo "Agent 0.4.1 requires config_version=2 and api_base ending in /api/v2."
fi

install -m 0644 "${BASE_DIR}/systemd/certm-agent.service" /etc/systemd/system/certm-agent.service
install -m 0644 "${BASE_DIR}/systemd/certm-agent.timer" /etc/systemd/system/certm-agent.timer
systemctl daemon-reload

echo
echo "CertM Agent 0.4.1 installed."
echo "Run: /opt/certm-agent/certm-agent.py preflight"
