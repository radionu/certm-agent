#!/usr/bin/env bash
# Invoked by install.sh --web-server zimbra; never starts/restarts Zimbra.
set -euo pipefail
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,8), "Python 3.8+ required"'
for tool in openssl systemctl su; do command -v "$tool" >/dev/null; done
id zimbra >/dev/null
[[ -x /opt/zimbra/bin/zmcertmgr && -s /etc/machine-id ]]
install -d -m 0750 /opt/certm-agent /opt/certm-agent/certm_agent /etc/certm /var/log/certm
install -d -m 0700 /opt/certm-agent/bkup /var/lib/certm/bindings
export CERTM_ZIMBRA_DISPLAY_NAME="${1:-}"
python3 - <<'PY'
import getpass, json, os, tempfile
from pathlib import Path
path = Path('/etc/certm/agent.json')
if path.exists():
    config = json.loads(path.read_text())
    if config.get('service', {}).get('type') != 'zimbra':
        raise SystemExit('Existing agent manages another service; refusing to overwrite')
    print('Preserving existing Zimbra client identity')
else:
    token = getpass.getpass('Enter CertM operations bootstrap credential: ').strip()
    if not token:
        raise SystemExit('Credential cannot be empty')
    config = {'config_version': 3, 'api_base': 'https://certm.pmr.vn/api/v2',
              'service': {'type': 'zimbra', 'systemd_unit': 'zimbra'},
              'display_name': os.environ.get('CERTM_ZIMBRA_DISPLAY_NAME') or 'Zimbra mail server',
              'machine_id_file': '/etc/machine-id',
              'discovery': {'allowed_certificate_roots': ['/etc/certm', '/opt/zimbra'],
                            'allowed_config_roots': ['/opt/zimbra/conf']},
              'paths': {'backup_root': '/opt/certm-agent/bkup',
                        'log_file': '/var/log/certm/certm-agent.log'},
              'verify': {'connect_host': '127.0.0.1', 'retry_timeout_seconds': 60}}
    config['client_token' if token.startswith('ct_') else 'enrollment_token'] = token
fd, name = tempfile.mkstemp(dir=str(path.parent), prefix='.zimbra-')
try:
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f, indent=2)
        f.write('\n')
    os.chmod(name, 0o600)
    os.replace(name, path)
finally:
    if os.path.exists(name): os.unlink(name)
PY
install -m 0750 "$BASE_DIR/certm-agent.py" /opt/certm-agent/certm-agent.py
install -m 0750 "$BASE_DIR/certm-agent-update.py" /opt/certm-agent/certm-agent-update.py
install -m 0644 "$BASE_DIR/certm_agent/"*.py /opt/certm-agent/certm_agent/
install -m 0644 "$BASE_DIR/systemd/certm-agent.service" /etc/systemd/system/
install -m 0644 "$BASE_DIR/systemd/certm-agent.timer" /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/certm-agent.timer.d
cat > /etc/systemd/system/certm-agent.timer.d/zimbra.conf <<'TIMER'
[Timer]
OnBootSec=
OnUnitActiveSec=
OnCalendar=
OnCalendar=*-*-* 00,06,12,18:05:00 Asia/Ho_Chi_Minh
RandomizedDelaySec=5min
TIMER
# A full Zimbra restart may exceed systemd's default start timeout.
install -d -m 0755 /etc/systemd/system/certm-agent.service.d
cat > /etc/systemd/system/certm-agent.service.d/zimbra.conf <<'SERVICE'
[Service]
TimeoutStartSec=40min
SERVICE
systemctl daemon-reload
/opt/certm-agent/certm-agent.py preflight --enroll
cat <<'NEXT'
Zimbra agent installed. No certificate changes or Zimbra restart performed.
1. Approve this client and its IP in CertM, then assign the new certificate.
2. Emergency deployment now (restarts Zimbra):
   /opt/certm-agent/certm-agent.py renew --emergency
3. After successful verification, enable scheduled renewal:
   systemctl enable --now certm-agent.timer
NEXT
