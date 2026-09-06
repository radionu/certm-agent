#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
REQUESTED_WEB_SERVER=""
DISPLAY_NAME_ARGUMENT=""

usage() {
  echo "Usage: sudo ./install.sh [--web-server nginx|apache] [--display-name NAME]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --web-server)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      REQUESTED_WEB_SERVER="${2,,}"
      shift 2
      ;;
    --display-name)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      DISPLAY_NAME_ARGUMENT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run install.sh as root" >&2
  exit 1
fi

if [[ -n "${REQUESTED_WEB_SERVER}" && "${REQUESTED_WEB_SERVER}" != "nginx" && "${REQUESTED_WEB_SERVER}" != "apache" ]]; then
  echo "FAILED: --web-server must be nginx or apache" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "FAILED: /etc/os-release is missing" >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
OS_ID="${ID,,}"
OS_LIKE="${ID_LIKE:-}"
case " ${OS_ID} ${OS_LIKE,,} " in
  *debian*|*ubuntu*) PLATFORM_FAMILY="debian" ;;
  *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) PLATFORM_FAMILY="rhel" ;;
  *)
    echo "FAILED: Unsupported Linux distribution: ${PRETTY_NAME:-${OS_ID}}" >&2
    exit 1
    ;;
esac

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
  if [[ "${PLATFORM_FAMILY}" == "rhel" ]]; then
    echo "Install a supported interpreter, for example: dnf install -y python39" >&2
  else
    echo "Install a supported interpreter, for example: apt-get install -y python3" >&2
  fi
  exit 1
fi

for command in openssl systemctl install; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "FAILED: Required command not found: ${command}" >&2
    exit 1
  fi
done

EXISTING_WEB_SERVER=""
if [[ -f /etc/certm/agent.json ]]; then
  EXISTING_WEB_SERVER="$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
try:
    value = json.loads(Path('/etc/certm/agent.json').read_text()).get('service', {}).get('type', '')
    print(str(value).strip().lower())
except Exception:
    print('')
PY
)"
fi

if [[ -n "${REQUESTED_WEB_SERVER}" && -n "${EXISTING_WEB_SERVER}" && "${REQUESTED_WEB_SERVER}" != "${EXISTING_WEB_SERVER}" ]]; then
  echo "FAILED: Existing agent manages ${EXISTING_WEB_SERVER}; refusing to change it to ${REQUESTED_WEB_SERVER}" >&2
  exit 1
fi

WEB_SERVER="${REQUESTED_WEB_SERVER:-${EXISTING_WEB_SERVER}}"
NGINX_ACTIVE=0
APACHE2_ACTIVE=0
HTTPD_ACTIVE=0
systemctl is-active --quiet nginx 2>/dev/null && NGINX_ACTIVE=1 || true
systemctl is-active --quiet apache2 2>/dev/null && APACHE2_ACTIVE=1 || true
systemctl is-active --quiet httpd 2>/dev/null && HTTPD_ACTIVE=1 || true

if [[ -z "${WEB_SERVER}" ]]; then
  if [[ "${NGINX_ACTIVE}" -eq 1 && ( "${APACHE2_ACTIVE}" -eq 1 || "${HTTPD_ACTIVE}" -eq 1 ) ]]; then
    echo "FAILED: Both nginx and apache are active; rerun with --web-server nginx or --web-server apache" >&2
    exit 1
  elif [[ "${NGINX_ACTIVE}" -eq 1 ]]; then
    WEB_SERVER="nginx"
  elif [[ "${APACHE2_ACTIVE}" -eq 1 || "${HTTPD_ACTIVE}" -eq 1 ]]; then
    WEB_SERVER="apache"
  else
    echo "FAILED: No supported active web server was detected" >&2
    exit 1
  fi
fi

if [[ "${WEB_SERVER}" == "nginx" ]]; then
  SYSTEMD_UNIT="nginx"
  CONTROL_BINARY="$(command -v nginx 2>/dev/null || true)"
  CONFIG_ROOT="/etc/nginx"
  CONFIG_TEST=("${CONTROL_BINARY}" -t)
else
  if [[ "${APACHE2_ACTIVE}" -eq 1 ]]; then
    SYSTEMD_UNIT="apache2"
  elif [[ "${HTTPD_ACTIVE}" -eq 1 ]]; then
    SYSTEMD_UNIT="httpd"
  elif [[ "${PLATFORM_FAMILY}" == "debian" ]]; then
    SYSTEMD_UNIT="apache2"
  else
    SYSTEMD_UNIT="httpd"
  fi
  if [[ "${PLATFORM_FAMILY}" == "debian" ]]; then
    CONTROL_BINARY="$(command -v apache2ctl 2>/dev/null || command -v apachectl 2>/dev/null || true)"
    CONFIG_ROOT="/etc/apache2"
  else
    CONTROL_BINARY="$(command -v apachectl 2>/dev/null || command -v httpd 2>/dev/null || true)"
    CONFIG_ROOT="/etc/httpd"
  fi
  CONFIG_TEST=("${CONTROL_BINARY}" configtest)
fi

if [[ -z "${CONTROL_BINARY}" ]]; then
  echo "FAILED: Control binary for ${WEB_SERVER} was not found" >&2
  exit 1
fi
if [[ "$(systemctl show "${SYSTEMD_UNIT}" --property=LoadState --value 2>/dev/null)" != "loaded" ]]; then
  echo "FAILED: systemd unit is not loaded: ${SYSTEMD_UNIT}" >&2
  exit 1
fi
if ! systemctl is-active --quiet "${SYSTEMD_UNIT}"; then
  echo "FAILED: systemd unit is not active: ${SYSTEMD_UNIT}" >&2
  exit 1
fi
if [[ ! -s /etc/machine-id ]]; then
  echo "FAILED: /etc/machine-id is missing or empty" >&2
  exit 1
fi
if ! "${CONFIG_TEST[@]}"; then
  echo "FAILED: ${WEB_SERVER} configuration test failed" >&2
  exit 1
fi

echo "Operating system : ${PRETTY_NAME:-${OS_ID}}"
echo "OS family        : ${PLATFORM_FAMILY}"
echo "Web server       : ${WEB_SERVER}"
echo "Systemd unit     : ${SYSTEMD_UNIT}"
echo "Control binary   : ${CONTROL_BINARY}"
echo "Configuration    : ${CONFIG_ROOT}"
echo "Python           : ${PYTHON_BIN} (${PYTHON_VERSION})"

install -d -m 0750 /opt/certm-agent
install -d -m 0750 /opt/certm-agent/certm_agent
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
  if [[ -n "${DISPLAY_NAME_ARGUMENT}" ]]; then
    DISPLAY_NAME="${DISPLAY_NAME_ARGUMENT}"
  else
    read -r -p "Enter optional CertM display name (Enter to use hostname): " DISPLAY_NAME
  fi
else
  TOKEN=""
  DISPLAY_NAME="${DISPLAY_NAME_ARGUMENT}"
  echo "/etc/certm/agent.json already exists; preserving client identity and state."
fi

CERTM_TOKEN="${TOKEN}" \
CERTM_DISPLAY_NAME="${DISPLAY_NAME}" \
CERTM_WEB_SERVER="${WEB_SERVER}" \
CERTM_SYSTEMD_UNIT="${SYSTEMD_UNIT}" \
CERTM_CONTROL_BINARY="${CONTROL_BINARY}" \
CERTM_CONFIG_ROOT="${CONFIG_ROOT}" \
CERTM_PLATFORM_FAMILY="${PLATFORM_FAMILY}" \
"${PYTHON_BIN}" - <<'PY'
import json
import os
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
if os.environ.get('CERTM_DISPLAY_NAME', '').strip():
    config['display_name'] = os.environ['CERTM_DISPLAY_NAME'].strip()

token = os.environ.get('CERTM_TOKEN', '').strip()
if token:
    if token.startswith('ct_'):
        config['client_token'] = token
        config.pop('enrollment_token', None)
    else:
        config['enrollment_token'] = token
        config.pop('client_token', None)
legacy_token = str(config.get('client_token', '')).strip()
if 'enrollment_token' not in config and legacy_token and not legacy_token.startswith('ct_'):
    config['enrollment_token'] = legacy_token
    config.pop('client_token', None)
elif legacy_token:
    config.pop('enrollment_token', None)

service = config.get('service') if isinstance(config.get('service'), dict) else {}
previous_service_type = str(service.get('type', '')).strip().lower()
service['type'] = os.environ['CERTM_WEB_SERVER']
service['systemd_unit'] = os.environ['CERTM_SYSTEMD_UNIT']
service['control_binary'] = os.environ['CERTM_CONTROL_BINARY']
config['service'] = service
config['platform_family'] = os.environ['CERTM_PLATFORM_FAMILY']

config_root = os.environ['CERTM_CONFIG_ROOT']
discovery = config.get('discovery') if isinstance(config.get('discovery'), dict) else {}
discovery.setdefault('max_bindings', 1000)
config_roots = discovery.get('allowed_config_roots')
if not isinstance(config_roots, list) or previous_service_type != os.environ['CERTM_WEB_SERVER']:
    config_roots = [config_root]
elif config_root not in config_roots:
    config_roots.append(config_root)
discovery['allowed_config_roots'] = config_roots
certificate_roots = discovery.get('allowed_certificate_roots')
if not isinstance(certificate_roots, list):
    certificate_roots = []
for root in (
    '/etc/certm', config_root, '/etc/pki/tls', '/etc/ssl',
    '/etc/letsencrypt', '/opt/certm-agent/live',
):
    if root not in certificate_roots:
        certificate_roots.append(root)
discovery['allowed_certificate_roots'] = certificate_roots
config['discovery'] = discovery

paths = config.get('paths') if isinstance(config.get('paths'), dict) else {}
paths.setdefault('managed_certificate_root', '/etc/certm/live')
config['paths'] = paths
path.write_text(json.dumps(config, indent=2) + '\n')
path.chmod(0o600)
PY

install -m 0750 "${BASE_DIR}/certm-agent.py" /opt/certm-agent/certm-agent.py
sed -i "1s|^#!.*$|#!${PYTHON_BIN}|" /opt/certm-agent/certm-agent.py
install -m 0644 "${BASE_DIR}/certm_agent/__init__.py" /opt/certm-agent/certm_agent/__init__.py
install -m 0644 "${BASE_DIR}/certm_agent/apache.py" /opt/certm-agent/certm_agent/apache.py
rm -f /opt/certm-agent/certm-agent-core.py

install -m 0644 "${BASE_DIR}/systemd/certm-agent.service" /etc/systemd/system/certm-agent.service
install -m 0644 "${BASE_DIR}/systemd/certm-agent.timer" /etc/systemd/system/certm-agent.timer
install -d -m 0755 /etc/systemd/system/certm-agent.service.d
sed "s|@WEB_SERVER_UNIT@|${SYSTEMD_UNIT}|g" \
  "${BASE_DIR}/systemd/web-server.conf" \
  > /etc/systemd/system/certm-agent.service.d/web-server.conf
chmod 0644 /etc/systemd/system/certm-agent.service.d/web-server.conf
systemctl daemon-reload

echo
echo "CertM Agent 1.0.0-rc.8 installed. Running full preflight before enrollment."
/opt/certm-agent/certm-agent.py preflight --enroll
echo
echo "Installation and preflight completed."
echo "For a new install, run a dry-run and one supervised renewal before enabling the timer."
echo "An existing installation keeps its previous timer enablement state."
