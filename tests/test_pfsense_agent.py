from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]
AGENT = (ROOT / "pfsense/CertM.HAProxy.Agent.php").read_text()
INSTALLER = (ROOT / "pfsense/install.sh").read_text()
COMMAND = (ROOT / "pfsense/certm-haproxy").read_text()


class PfSenseAgentContractTest(unittest.TestCase):
    def test_example_configuration_is_valid_json(self):
        config = json.loads((ROOT / "pfsense/config.example.json").read_text())
        self.assertTrue(config["api_base"].startswith("https://"))
        self.assertIn("enrollment_token", config)

    def test_agent_uses_pfsense_certificate_manager_and_haproxy_api(self):
        for contract in (
            "certm_lookup_certificate($refid)",
            "certm_append_config_item('cert', $cert)",
            "certm_append_config_item('ca', $ca)",
            "write_config(",
            "haproxy_check_run(1)",
        ):
            self.assertIn(contract, AGENT)
        self.assertNotIn("file_put_contents('/var/etc/haproxy", AGENT)
        self.assertNotIn('file_put_contents("/var/etc/haproxy', AGENT)

    def test_fingerprint_normalizes_certificate_and_hashes_decoded_der(self):
        self.assertIn("openssl_x509_export($resource, $certificatePem, false)", AGENT)
        self.assertIn("base64_decode($encoded, true)", AGENT)
        self.assertIn("return hash('sha256', $der);", AGENT)
        self.assertIn("return certm_fingerprint_via_openssl($certificate);", AGENT)
        self.assertIn("tempnam(sys_get_temp_dir(), 'certm-x509-')", AGENT)
        self.assertIn("chmod($temporary, 0600)", AGENT)
        self.assertIn("@unlink($temporary)", AGENT)
        self.assertNotIn("openssl_x509_fingerprint", AGENT)

    def test_haproxy_pem_uses_openssl_cli_der_fingerprint(self):
        self.assertIn("function certm_fingerprint_file", AGENT)
        self.assertIn("' x509 -in '.escapeshellarg($path)", AGENT)
        self.assertIn("' -outform DER 2>/dev/null'", AGENT)
        verification = AGENT.split(
            "function certm_verify_haproxy_pem", 1
        )[1].split("function certm_report", 1)[0]
        self.assertIn("certm_fingerprint_file($path)", verification)
        self.assertNotIn("certm_fingerprint($contents)", verification)

    def test_http_only_frontends_are_not_inventoried_as_https(self):
        ports = AGENT.split(
            "function certm_frontend_ports", 1
        )[1].split("function certm_frontend_certificate_refs", 1)[0]
        self.assertIn("return array_values(array_unique($ports));", ports)
        self.assertNotIn("$ports ?: [443]", ports)
        discovery = AGENT.split(
            "function certm_discover_bindings", 1
        )[1].split("function certm_push_inventory", 1)[0]
        self.assertIn("if ($ports === [])", discovery)

    def test_agent_uses_version_independent_certificate_lookup(self):
        self.assertIn("function certm_lookup_certificate", AGENT)
        lookup = AGENT.split(
            "function certm_lookup_certificate", 1
        )[1].split("function certm_find_ca_by_fingerprint", 1)[0]
        self.assertIn("config_get_path('cert', [])", lookup)
        self.assertNotIn("lookup_cert(", lookup)

    def test_agent_does_not_depend_on_new_trailing_slash_append_semantics(self):
        self.assertIn("function certm_append_config_item", AGENT)
        self.assertIn("$items[] = $item;", AGENT)
        self.assertIn("config_set_path($path, $items);", AGENT)
        self.assertNotIn("config_set_path('cert/', $cert)", AGENT)
        self.assertNotIn("config_set_path('ca/', $ca)", AGENT)

    def test_agent_validates_package_and_rolls_back_configuration(self):
        for contract in (
            "openssl_x509_check_private_key",
            "Downloaded full chain does not start with the leaf certificate",
            "Downloaded certificate does not cover",
            "certm_verify_haproxy_pem",
            "config_set_path('cert', $oldCerts)",
            "config_set_path('ca', $oldCas)",
            "config_set_path('installedpackages/haproxy/ha_backends/item', $oldFrontends)",
            "'FAILED'",
        ):
            self.assertIn(contract, AGENT)

    def test_agent_reports_pfsense_identity_and_six_hour_schedule(self):
        self.assertIn("pfsense-haproxy", AGENT)
        self.assertIn("'21', '*/6'", AGENT)
        self.assertIn("/bin/sh /conf/certm/certm-haproxy run", AGENT)

    def test_inventory_refreshes_pfsense_operating_system_metadata(self):
        for contract in (
            "function certm_pfsense_version()",
            "'/etc/version'",
            "'os_name' => 'pfSense'",
            "'os_version' => certm_pfsense_version()",
        ):
            self.assertIn(contract, AGENT)

        inventory = AGENT.split(
            "function certm_push_inventory", 1
        )[1].split("function certm_desired", 1)[0]
        self.assertIn("'os_name' => 'pfSense'", inventory)
        self.assertIn("'os_version' => certm_pfsense_version()", inventory)

    def test_status_is_safe_and_operational(self):
        for contract in (
            "function certm_status()",
            "CertM API status:",
            "Active HTTPS bindings:",
            "Six-hour cron:",
            "Last log:",
        ):
            self.assertIn(contract, AGENT)
        self.assertNotIn("client_token: ", AGENT)

    def test_unmatched_acl_domains_are_onboarded_without_replacing_primary_certificate(self):
        for contract in (
            "'pending:'.$domain",
            "'fingerprint_sha256' => null",
            "function certm_create_certificate(",
            "function certm_attach_certificate(",
            "'ha_certificates']['item']",
            "DRY RUN would create and attach",
            "'create' => true",
        ):
            self.assertIn(contract, AGENT)

    def test_operator_command_supports_service_like_operations(self):
        for command in (
            "status|preflight|enroll|inventory|dry-run|renew|run",
            "enable)",
            "disable)",
            "logs)",
            "update)",
        ):
            self.assertIn(command, COMMAND)
        self.assertIn(
            'exec "${PHP_BIN}" -f "${AGENT_PATH}" update',
            COMMAND,
        )
        self.assertNotIn("raw.githubusercontent.com", COMMAND)

    def test_update_uses_signed_certm_packages_and_can_roll_back(self):
        for contract in (
            "'client/agent-update'",
            "'client/agent-update/key'",
            "'client/agent-update/report'",
            "openssl_verify(",
            "signing_key_fingerprint",
            "'platform'] ?? null) !== 'pfsense'",
            "$modified ? 'ROLLBACK' : 'FAILED'",
            "certm_scheduled_run()",
            "certificate work will continue",
        ):
            self.assertIn(contract, AGENT)

    def test_installer_keeps_identity_when_refreshing_agent_code(self):
        self.assertIn('if [ ! -f "${CONFIG_PATH}" ]', INSTALLER)
        self.assertIn('/bin/sh "${COMMAND_PATH}" enable', INSTALLER)
        self.assertIn("chmod 600", INSTALLER)
        self.assertIn('rm -f "${COMMAND_LINK}"', INSTALLER)
        self.assertIn('cp -f "${COMMAND_PATH}" "${COMMAND_LINK}"', INSTALLER)
        self.assertNotIn('ln -sf "${COMMAND_PATH}" "${COMMAND_LINK}"', INSTALLER)


if __name__ == "__main__":
    unittest.main()
