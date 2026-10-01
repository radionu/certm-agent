#!/bin/sh

set -eu

AGENT_DIR='/conf/certm'
AGENT_PATH="${AGENT_DIR}/CertM.HAProxy.Agent.php"
COMMAND_PATH="${AGENT_DIR}/certm-haproxy"
COMMAND_LINK='/usr/local/sbin/certm-haproxy'
PHP_BIN='/usr/local/bin/php'

if [ "$(id -u)" -ne 0 ]; then
    echo 'FAILED: Run this uninstaller as root on pfSense.' >&2
    exit 1
fi

if [ -f "${AGENT_PATH}" ]; then
    "${PHP_BIN}" -f "${AGENT_PATH}" remove-cron || true
fi

rm -f "${COMMAND_LINK}" "${COMMAND_PATH}" "${AGENT_PATH}"

echo 'CertM pfSense HAProxy Agent removed.'
echo "Enrollment configuration was preserved at ${AGENT_DIR}/config.json."
echo 'Remove that file manually only when this firewall will not be reinstalled.'
