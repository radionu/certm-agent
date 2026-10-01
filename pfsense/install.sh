#!/bin/sh

set -eu

AGENT_DIR='/conf/certm'
AGENT_PATH="${AGENT_DIR}/CertM.HAProxy.Agent.php"
COMMAND_PATH="${AGENT_DIR}/certm-haproxy"
COMMAND_LINK='/usr/local/sbin/certm-haproxy'
CONFIG_PATH="${AGENT_DIR}/config.json"
SOURCE_URL='https://raw.githubusercontent.com/radionu/certm-agent/main/pfsense/CertM.HAProxy.Agent.php'
COMMAND_URL='https://raw.githubusercontent.com/radionu/certm-agent/main/pfsense/certm-haproxy'
PHP_BIN='/usr/local/bin/php'
FETCH_BIN='/usr/bin/fetch'

if [ "$(id -u)" -ne 0 ]; then
    echo 'FAILED: Run this installer as root on pfSense.' >&2
    exit 1
fi

if [ ! -x "${PHP_BIN}" ] || [ ! -x "${FETCH_BIN}" ]; then
    echo 'FAILED: The pfSense PHP or fetch binary is unavailable.' >&2
    exit 1
fi

mkdir -p "${AGENT_DIR}"
chmod 700 "${AGENT_DIR}"

temporary_agent="${AGENT_PATH}.download.$$"
temporary_command="${COMMAND_PATH}.download.$$"
trap 'rm -f "${temporary_agent}" "${temporary_command}"' EXIT HUP INT TERM
"${FETCH_BIN}" -qo "${temporary_agent}" "${SOURCE_URL}"
"${FETCH_BIN}" -qo "${temporary_command}" "${COMMAND_URL}"
"${PHP_BIN}" -l "${temporary_agent}" >/dev/null
/bin/sh -n "${temporary_command}"
chmod 700 "${temporary_agent}" "${temporary_command}"
mv -f "${temporary_agent}" "${AGENT_PATH}"
mv -f "${temporary_command}" "${COMMAND_PATH}"
rm -f "${COMMAND_LINK}"
cp -f "${COMMAND_PATH}" "${COMMAND_LINK}"
chmod 700 "${COMMAND_LINK}"
trap - EXIT HUP INT TERM

if [ ! -f "${CONFIG_PATH}" ]; then
    printf 'CertM API base [https://certm.pmr.vn/api/v2]: '
    IFS= read -r api_base
    api_base=${api_base:-https://certm.pmr.vn/api/v2}

    printf 'pfSense display name [%s]: ' "$(hostname)"
    IFS= read -r display_name
    display_name=${display_name:-$(hostname)}

    printf 'CertM operations bootstrap credential: '
    stty -echo
    IFS= read -r enrollment_token
    stty echo
    printf '\n'

    if [ -z "${enrollment_token}" ]; then
        echo 'FAILED: The bootstrap credential cannot be empty.' >&2
        exit 1
    fi

    CERTM_API_BASE="${api_base}" \
    CERTM_DISPLAY_NAME="${display_name}" \
    CERTM_ENROLLMENT_TOKEN="${enrollment_token}" \
    CERTM_CONFIG_PATH="${CONFIG_PATH}" \
    "${PHP_BIN}" -r '
        $config = [
            "api_base" => getenv("CERTM_API_BASE"),
            "display_name" => getenv("CERTM_DISPLAY_NAME"),
            "enrollment_token" => getenv("CERTM_ENROLLMENT_TOKEN"),
        ];
        $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || file_put_contents(getenv("CERTM_CONFIG_PATH"), $json."\n") === false) {
            fwrite(STDERR, "Unable to write CertM configuration.\n");
            exit(1);
        }
    '
    chmod 600 "${CONFIG_PATH}"
fi

/bin/sh "${COMMAND_PATH}" preflight

if ! grep -q '"client_token"' "${CONFIG_PATH}"; then
    /bin/sh "${COMMAND_PATH}" enroll
fi

/bin/sh "${COMMAND_PATH}" enable

echo
echo 'CertM pfSense HAProxy Agent installed.'
echo 'Approve the new client in CertM, assign its certificates, then run:'
echo 'certm-haproxy status'
echo 'certm-haproxy dry-run'
echo 'certm-haproxy renew'
