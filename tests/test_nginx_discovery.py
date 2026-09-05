import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AGENT_PATH = REPOSITORY_ROOT / "rhel-nginx" / "certm-agent.py"
SPEC = importlib.util.spec_from_file_location("certm_nginx_agent", AGENT_PATH)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class NginxDiscoveryTest(unittest.TestCase):
    def discover(self, configuration, roots=("/etc",), prefix="/"):
        return agent.bindings_from_dump(
            configuration,
            Path(prefix),
            list(roots),
            1000,
        )

    def test_discovers_level_three_and_level_four_domains(self):
        configuration = r"""
        http { include /etc/nginx/conf.d/*.conf; }
        # configuration file /etc/nginx/conf.d/sites.conf:
        server {
            listen 443 ssl;
            listen [::]:443 ssl;
            server_name xxx.pmr.vn xxx.xxx.pmr.vn;
            ssl_certificate /etc/nginx/ssl/pmr/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/pmr/privkey.pem;
        }
        nginx: configuration file /etc/nginx/nginx.conf test is successful
        """
        bindings, warnings = self.discover(configuration)

        self.assertEqual(
            [(item["domain"], item["port"]) for item in bindings],
            [("xxx.pmr.vn", 443), ("xxx.xxx.pmr.vn", 443)],
        )
        self.assertEqual(warnings, [])
        self.assertTrue(all(item["binding_id"].startswith("nginx:") for item in bindings))

    def test_discovers_new_vhost_and_omits_removed_vhost_each_run(self):
        original = r"""
        server {
            listen 443 ssl;
            server_name old.pmr.vn;
            ssl_certificate /etc/nginx/ssl/old/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/old/privkey.pem;
        }
        """
        changed = r"""
        server {
            listen 443 ssl;
            server_name new.pmr.vn;
            ssl_certificate /etc/nginx/ssl/new/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/new/privkey.pem;
        }
        """

        first, _ = self.discover(original)
        second, _ = self.discover(changed)

        self.assertEqual([item["domain"] for item in first], ["old.pmr.vn"])
        self.assertEqual([item["domain"] for item in second], ["new.pmr.vn"])

    def test_groups_domains_that_share_the_same_certificate_files(self):
        configuration = r"""
        server {
            listen 8443 ssl;
            server_name a.pmr.vn b.pmr.vn;
            ssl_certificate /etc/certm/live/pmr/fullchain.pem;
            ssl_certificate_key /etc/certm/live/pmr/privkey.pem;
        }
        """
        bindings, _ = self.discover(configuration)
        groups = agent.binding_groups(bindings)

        self.assertEqual(len(groups), 1)
        self.assertEqual({item["domain"] for item in groups[0]}, {"a.pmr.vn", "b.pmr.vn"})
        self.assertEqual({item["port"] for item in groups[0]}, {8443})

    def test_records_editable_source_for_each_server_block(self):
        configuration = r"""# configuration file /etc/nginx/conf.d/site.conf:
server {
    listen 443 ssl;
    server_name editable.pmr.vn;
    ssl_certificate /etc/nginx/ssl/shared/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/shared/privkey.pem;
}
"""
        bindings, _ = self.discover(configuration)

        self.assertEqual(bindings[0]["config_file"], "/etc/nginx/conf.d/site.conf")
        self.assertIn("server_name editable.pmr.vn", bindings[0]["config_server_text"])
        server_text = bindings[0]["config_server_text"]
        start = bindings[0]["certificate_directive_start"]
        end = bindings[0]["certificate_directive_end"]
        self.assertEqual(
            server_text[start:end],
            "ssl_certificate /etc/nginx/ssl/shared/fullchain.pem;",
        )

    def test_public_discovery_output_hides_config_edit_metadata(self):
        configuration = r"""# configuration file /etc/nginx/conf.d/site.conf:
server {
    listen 443 ssl;
    server_name public.pmr.vn;
    ssl_certificate /etc/nginx/ssl/public/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/public/privkey.pem;
}
"""
        bindings, _ = self.discover(configuration)
        public = agent.public_binding(bindings[0])

        self.assertEqual(public["domain"], "public.pmr.vn")
        self.assertEqual(public["certificate_path"], "/etc/nginx/ssl/public/fullchain.pem")
        self.assertNotIn("config_server_text", public)
        self.assertNotIn("config_file", public)
        self.assertFalse(any("directive" in key for key in public))

    def test_rejects_duplicate_domain_and_port_with_different_files(self):
        configuration = r"""
        server {
            listen 443 ssl;
            server_name duplicate.pmr.vn;
            ssl_certificate /etc/nginx/ssl/one/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/one/privkey.pem;
        }
        server {
            listen 443 ssl;
            server_name duplicate.pmr.vn;
            ssl_certificate /etc/nginx/ssl/two/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/two/privkey.pem;
        }
        """

        with self.assertRaisesRegex(RuntimeError, "Ambiguous nginx binding"):
            self.discover(configuration)

    def test_skips_regex_wildcard_variable_and_hostless_names(self):
        configuration = r"""
        server {
            listen 443 ssl;
            server_name _ *.pmr.vn ~^regex\\.pmr\\.vn$ $dynamic_name;
            ssl_certificate /etc/nginx/ssl/default/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/default/privkey.pem;
        }
        """
        bindings, warnings = self.discover(configuration)

        self.assertEqual(bindings, [])
        self.assertGreaterEqual(len(warnings), 5)

    def test_skips_multi_certificate_and_variable_path_blocks(self):
        configuration = r"""
        server {
            listen 443 ssl;
            server_name dual.pmr.vn;
            ssl_certificate /etc/nginx/ssl/dual/rsa.pem;
            ssl_certificate /etc/nginx/ssl/dual/ecdsa.pem;
            ssl_certificate_key /etc/nginx/ssl/dual/rsa.key;
            ssl_certificate_key /etc/nginx/ssl/dual/ecdsa.key;
        }
        server {
            listen 444 ssl;
            server_name variable.pmr.vn;
            ssl_certificate /etc/nginx/ssl/$ssl_server_name/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/$ssl_server_name/privkey.pem;
        }
        """
        bindings, warnings = self.discover(configuration)

        self.assertEqual(bindings, [])
        self.assertTrue(any("exactly one" in warning for warning in warnings))
        self.assertTrue(any("variable" in warning for warning in warnings))

    def test_skips_paths_outside_allowed_roots(self):
        configuration = r"""
        server {
            listen 443 ssl;
            server_name unsafe.pmr.vn;
            ssl_certificate /srv/unsafe/fullchain.pem;
            ssl_certificate_key /srv/unsafe/privkey.pem;
        }
        """
        bindings, warnings = self.discover(configuration, roots=("/etc/nginx",))

        self.assertEqual(bindings, [])
        self.assertTrue(any("outside allowed roots" in warning for warning in warnings))

    def test_resolves_relative_paths_against_nginx_prefix(self):
        configuration = r"""
        server {
            listen 10.0.0.5:9443 ssl;
            server_name relative.pmr.vn;
            ssl_certificate ssl/site/fullchain.pem;
            ssl_certificate_key ssl/site/privkey.pem;
        }
        """
        bindings, _ = self.discover(
            configuration,
            roots=("/opt/nginx",),
            prefix="/opt/nginx",
        )

        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0]["listen_host"], "10.0.0.5")
        self.assertEqual(bindings[0]["port"], 9443)
        self.assertEqual(
            bindings[0]["certificate_path"],
            "/opt/nginx/ssl/site/fullchain.pem",
        )

    def test_preserves_symlink_but_writes_to_its_allowed_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive"
            live = root / "live"
            archive.mkdir()
            live.mkdir()
            certificate_target = archive / "fullchain1.pem"
            key_target = archive / "privkey1.pem"
            certificate_target.write_text("placeholder")
            key_target.write_text("placeholder")
            (live / "fullchain.pem").symlink_to(certificate_target)
            (live / "privkey.pem").symlink_to(key_target)
            configuration = f"""
            server {{
                listen 443 ssl;
                server_name symlink.pmr.vn;
                ssl_certificate {live / 'fullchain.pem'};
                ssl_certificate_key {live / 'privkey.pem'};
            }}
            """

            bindings, _ = self.discover(configuration, roots=(temporary,))

            self.assertEqual(len(bindings), 1)
            self.assertEqual(
                bindings[0]["certificate_write_path"],
                str(certificate_target),
            )
            self.assertTrue((live / "fullchain.pem").is_symlink())

    def test_rejects_certificate_path_paired_with_multiple_keys(self):
        configuration = r"""
        server {
            listen 443 ssl;
            server_name first.pmr.vn;
            ssl_certificate /etc/nginx/ssl/shared/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/shared/first.key;
        }
        server {
            listen 443 ssl;
            server_name second.pmr.vn;
            ssl_certificate /etc/nginx/ssl/shared/fullchain.pem;
            ssl_certificate_key /etc/nginx/ssl/shared/second.key;
        }
        """

        with self.assertRaisesRegex(RuntimeError, "paired with multiple key paths"):
            self.discover(configuration)

    def test_example_config_has_no_static_domain_bindings(self):
        config_path = REPOSITORY_ROOT / "rhel-nginx" / "agent.json.example"
        config = json.loads(config_path.read_text())

        self.assertEqual(config["config_version"], 3)
        self.assertIn("display_name", config)
        self.assertIn("enrollment_token", config)
        self.assertEqual(config["client_token"], "")
        self.assertNotIn("management", config)
        self.assertNotIn("domains", config)
        self.assertTrue(config["discovery"]["allowed_certificate_roots"])
        self.assertTrue(config["discovery"]["allowed_config_roots"])
        self.assertEqual(config["paths"]["managed_certificate_root"], "/etc/certm/live")

    def test_inventory_reports_current_hostname_and_display_name(self):
        previous = agent.CONFIG
        agent.CONFIG = {"display_name": "Nginx Edge 01"}
        try:
            with mock.patch.object(agent.socket, "gethostname", return_value="edge-01"), \
                    mock.patch.object(
                        agent,
                        "api_request",
                        return_value={"summary": {}},
                    ) as request:
                agent.push_inventory([], "token", "machine-id")
        finally:
            agent.CONFIG = previous

        payload = request.call_args.args[4]
        self.assertEqual(payload["hostname"], "edge-01")
        self.assertEqual(payload["display_name"], "Nginx Edge 01")
        self.assertEqual(payload["items"], [])

    def test_saving_client_token_removes_bootstrap_enrollment_token(self):
        previous_config = agent.CONFIG
        previous_file = agent.CONFIG_FILE
        with tempfile.TemporaryDirectory() as temporary:
            agent.CONFIG = {
                "enrollment_token": "abcd1234",
                "client_token": "",
            }
            agent.CONFIG_FILE = Path(temporary) / "agent.json"
            try:
                agent.save_client_token("ct_unique_client_token")
                saved = json.loads(agent.CONFIG_FILE.read_text())
            finally:
                agent.CONFIG = previous_config
                agent.CONFIG_FILE = previous_file

        self.assertEqual(saved["client_token"], "ct_unique_client_token")
        self.assertNotIn("enrollment_token", saved)


class NginxRenewPlanningTest(unittest.TestCase):
    def setUp(self):
        self.bindings = [
            {
                "site_name": "a.pmr.vn",
                "domain": "a.pmr.vn",
                "port": 443,
                "protocol": "https",
                "listen_host": "127.0.0.1",
                "certificate_path": "/etc/nginx/ssl/shared/fullchain.pem",
                "key_path": "/etc/nginx/ssl/shared/privkey.pem",
                "certificate_write_path": "/etc/nginx/ssl/shared/fullchain.pem",
                "key_write_path": "/etc/nginx/ssl/shared/privkey.pem",
                "binding_id": "a",
            },
            {
                "site_name": "b.pmr.vn",
                "domain": "b.pmr.vn",
                "port": 443,
                "protocol": "https",
                "listen_host": "127.0.0.1",
                "certificate_path": "/etc/nginx/ssl/shared/fullchain.pem",
                "key_path": "/etc/nginx/ssl/shared/privkey.pem",
                "certificate_write_path": "/etc/nginx/ssl/shared/fullchain.pem",
                "key_write_path": "/etc/nginx/ssl/shared/privkey.pem",
                "binding_id": "b",
            },
        ]
        self.desired = {
            "certificate_id": 10,
            "certificate_version_id": 20,
            "version_id": "260901",
            "package_revision": 1,
            "deployment_revision": "260901-r1",
            "fingerprint_sha256": "a" * 64,
        }

    def renew_with(self, desired_values, dry_run=False):
        with mock.patch.object(agent, "validate_local_environment"), \
                mock.patch.object(agent, "read_active_identity", return_value=("token", "machine")), \
                mock.patch.object(agent, "discover_bindings", return_value=self.bindings), \
                mock.patch.object(agent, "push_inventory"), \
                mock.patch.object(agent, "desired_for", side_effect=desired_values), \
                mock.patch.object(agent, "deploy_group", return_value=False) as deploy, \
                mock.patch.object(agent, "deploy_split_group", return_value=False) as split:
            agent.renew(dry_run=dry_run)
            return deploy, split

    def test_no_assignment_never_deploys(self):
        deploy, split = self.renew_with([None, None])
        deploy.assert_not_called()
        split.assert_not_called()

    def test_shared_paths_with_partial_assignment_are_split(self):
        deploy, split = self.renew_with([self.desired, None], dry_run=True)
        deploy.assert_not_called()
        split.assert_called_once()
        self.assertTrue(split.call_args.args[-1])

    def test_shared_paths_with_different_certificates_are_split(self):
        different = dict(self.desired)
        different["certificate_id"] = 11
        deploy, split = self.renew_with([self.desired, different], dry_run=True)
        deploy.assert_not_called()
        split.assert_called_once()

    def test_dry_run_is_forwarded_without_local_mutation(self):
        deploy, split = self.renew_with([self.desired, self.desired], dry_run=True)
        deploy.assert_called_once()
        self.assertTrue(deploy.call_args.args[-1])
        split.assert_not_called()

    def test_current_certificate_dry_run_does_not_write_binding_state(self):
        with mock.patch.object(
            agent,
            "fingerprint_file",
            return_value=self.desired["fingerprint_sha256"],
        ), mock.patch.object(
            agent,
            "load_state",
            return_value={},
        ), mock.patch.object(
            agent,
            "verify_served",
            return_value=self.desired["fingerprint_sha256"],
        ), mock.patch.object(
            agent,
            "save_state",
        ) as save_state, mock.patch.object(
            agent,
            "api_request",
        ) as request:
            changed = agent.deploy_group(
                self.bindings,
                self.desired,
                "token",
                "machine",
                dry_run=True,
            )

        self.assertFalse(changed)
        save_state.assert_not_called()
        request.assert_not_called()


class NginxConfigSplitTest(unittest.TestCase):
    def desired(self, certificate_id, fingerprint):
        return {
            "certificate_id": certificate_id,
            "certificate_version_id": certificate_id * 10,
            "version_id": "260901",
            "package_revision": 1,
            "deployment_revision": f"260901-r1-c{certificate_id}",
            "fingerprint_sha256": fingerprint,
        }

    def fixture(self, root, same_server=False, certbot_comments=False):
        root = Path(root)
        config_path = root / "nginx" / "conf.d" / "sites.conf"
        config_path.parent.mkdir(parents=True)
        shared = root / "nginx" / "ssl" / "shared"
        shared.mkdir(parents=True)
        (shared / "fullchain.pem").write_text("old certificate")
        (shared / "privkey.pem").write_text("old key")
        comment = " # managed by Certbot" if certbot_comments else ""
        if same_server:
            content = f"""server {{
    listen 443 ssl;
    server_name a.pmr.vn b.pmr.vn;
    ssl_certificate {shared / 'fullchain.pem'};{comment}
    ssl_certificate_key {shared / 'privkey.pem'};{comment}
}}
"""
        else:
            content = f"""server {{
    listen 443 ssl;
    server_name a.pmr.vn;
    ssl_certificate {shared / 'fullchain.pem'};{comment}
    ssl_certificate_key {shared / 'privkey.pem'};{comment}
}}
server {{
    listen 443 ssl;
    server_name b.pmr.vn;
    ssl_certificate {shared / 'fullchain.pem'};{comment}
    ssl_certificate_key {shared / 'privkey.pem'};{comment}
}}
"""
        config_path.write_text(content)
        dump = f"# configuration file {config_path}:\n{content}"
        bindings, warnings = agent.bindings_from_dump(
            dump,
            Path("/"),
            [str(root)],
            1000,
        )
        self.assertEqual(warnings, [])
        return config_path, content, bindings

    def configure(self, root):
        old = agent.CONFIG
        agent.CONFIG = {
            "paths": {
                "backup_root": str(Path(root) / "backups"),
                "managed_certificate_root": str(Path(root) / "managed"),
                "state_root": str(Path(root) / "state"),
            },
            "discovery": {
                "allowed_certificate_roots": [str(root)],
                "allowed_config_roots": [str(Path(root) / "nginx")],
            },
        }
        return old

    def test_separate_server_blocks_can_resolve_to_different_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, bindings = self.fixture(temporary)
            old = self.configure(temporary)
            try:
                targets, untouched = agent.split_plan(
                    bindings,
                    [self.desired(10, "a" * 64), self.desired(11, "b" * 64)],
                )
            finally:
                agent.CONFIG = old

            self.assertEqual(len(targets), 2)
            self.assertEqual(untouched, [])
            self.assertEqual(
                {Path(item["paths"]["certificate_path"]).parent.name for item in targets},
                {"certificate-10", "certificate-11"},
            )

    def test_one_server_block_cannot_receive_different_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, bindings = self.fixture(temporary, same_server=True)
            old = self.configure(temporary)
            try:
                with self.assertRaisesRegex(RuntimeError, "One nginx server block"):
                    agent.split_plan(
                        bindings,
                        [self.desired(10, "a" * 64), self.desired(11, "b" * 64)],
                    )
            finally:
                agent.CONFIG = old

    def test_render_rewrites_only_the_two_certificate_directives(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path, original, bindings = self.fixture(temporary)
            old = self.configure(temporary)
            try:
                targets, _ = agent.split_plan(
                    bindings,
                    [self.desired(10, "a" * 64), self.desired(11, "b" * 64)],
                )
                rendered = agent.render_split_config_updates(targets)[str(config_path)]
            finally:
                agent.CONFIG = old

            self.assertIn("server_name a.pmr.vn;", rendered)
            self.assertIn("server_name b.pmr.vn;", rendered)
            self.assertNotEqual(rendered, original)
            self.assertIn("certificate-10/fullchain.pem", rendered)
            self.assertIn("certificate-11/fullchain.pem", rendered)
            self.assertNotIn("ssl/shared/fullchain.pem", rendered)

    def test_render_replaces_stale_certbot_ownership_comments(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path, _, bindings = self.fixture(
                temporary,
                certbot_comments=True,
            )
            old = self.configure(temporary)
            try:
                targets, _ = agent.split_plan(
                    bindings,
                    [self.desired(10, "a" * 64), self.desired(11, "b" * 64)],
                )
                rendered = agent.render_split_config_updates(targets)[str(config_path)]
            finally:
                agent.CONFIG = old

            self.assertNotIn("managed by Certbot", rendered)
            self.assertEqual(rendered.count("managed by CertM"), 4)

    def test_dry_run_validates_config_edits_without_downloading_or_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path, original, bindings = self.fixture(temporary)
            old = self.configure(temporary)
            desired_values = [
                self.desired(10, "a" * 64),
                self.desired(11, "b" * 64),
            ]
            try:
                with mock.patch.object(agent, "api_request") as request:
                    changed = agent.deploy_split_group(
                        bindings,
                        desired_values,
                        "token",
                        "machine",
                        dry_run=True,
                    )
            finally:
                agent.CONFIG = old

            self.assertFalse(changed)
            request.assert_not_called()
            self.assertEqual(config_path.read_text(), original)
            self.assertFalse((Path(temporary) / "managed").exists())

    def test_reload_failure_restores_config_and_removes_new_managed_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path, original, bindings = self.fixture(temporary)
            old = self.configure(temporary)
            desired_values = [
                self.desired(10, "a" * 64),
                self.desired(11, "b" * 64),
            ]

            def package(_response, desired, _domains):
                return {
                    "deployment_id": int(desired["certificate_id"]),
                    "fullchain": f"certificate-{desired['certificate_id']}".encode(),
                    "key": f"key-{desired['certificate_id']}".encode(),
                    "expected": desired["fingerprint_sha256"],
                }

            def install(bindings_to_install, downloaded):
                target = bindings_to_install[0]
                Path(target["certificate_write_path"]).parent.mkdir(parents=True, exist_ok=True)
                Path(target["certificate_write_path"]).write_bytes(downloaded["fullchain"])
                Path(target["key_write_path"]).write_bytes(downloaded["key"])

            try:
                with mock.patch.object(agent, "api_request", return_value={}), \
                        mock.patch.object(agent, "decode_package", side_effect=package), \
                        mock.patch.object(agent, "install_package", side_effect=install), \
                        mock.patch.object(
                            agent,
                            "nginx_test_reload",
                            side_effect=[RuntimeError("nginx test failed"), None],
                        ), \
                        mock.patch.object(agent, "restore_selinux_context"), \
                        mock.patch.object(agent, "report_deployment"):
                    with self.assertRaisesRegex(RuntimeError, "rollback completed successfully"):
                        agent.deploy_split_group(
                            bindings,
                            desired_values,
                            "token",
                            "machine",
                        )
            finally:
                agent.CONFIG = old

            self.assertEqual(config_path.read_text(), original)
            self.assertFalse((Path(temporary) / "managed" / "certificate-10" / "fullchain.pem").exists())
            self.assertFalse((Path(temporary) / "managed" / "certificate-11" / "fullchain.pem").exists())

    def test_successful_split_installs_both_profiles_and_updates_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_path, _, bindings = self.fixture(temporary)
            old = self.configure(temporary)
            desired_values = [
                self.desired(10, "a" * 64),
                self.desired(11, "b" * 64),
            ]

            def package(_response, desired, _domains):
                return {
                    "deployment_id": int(desired["certificate_id"]),
                    "fullchain": f"certificate-{desired['certificate_id']}".encode(),
                    "key": f"key-{desired['certificate_id']}".encode(),
                    "expected": desired["fingerprint_sha256"],
                }

            def install(bindings_to_install, downloaded):
                target = bindings_to_install[0]
                Path(target["certificate_write_path"]).parent.mkdir(parents=True, exist_ok=True)
                Path(target["certificate_write_path"]).write_bytes(downloaded["fullchain"])
                Path(target["key_write_path"]).write_bytes(downloaded["key"])

            def fingerprint(path):
                return "a" * 64 if "certificate-10" in str(path) else "b" * 64

            try:
                with mock.patch.object(agent, "api_request", return_value={}), \
                        mock.patch.object(agent, "decode_package", side_effect=package), \
                        mock.patch.object(agent, "install_package", side_effect=install), \
                        mock.patch.object(agent, "fingerprint_file", side_effect=fingerprint), \
                        mock.patch.object(agent, "verify_served", side_effect=lambda _, expected: expected), \
                        mock.patch.object(agent, "nginx_test_reload") as reload_nginx, \
                        mock.patch.object(agent, "restore_selinux_context"), \
                        mock.patch.object(agent, "report_deployment", return_value={"status": "ok"}) as report:
                    changed = agent.deploy_split_group(
                        bindings,
                        desired_values,
                        "token",
                        "machine",
                    )
            finally:
                agent.CONFIG = old

            self.assertTrue(changed)
            rendered = config_path.read_text()
            self.assertIn("certificate-10/fullchain.pem", rendered)
            self.assertIn("certificate-11/fullchain.pem", rendered)
            self.assertTrue((Path(temporary) / "managed" / "certificate-10" / "privkey.pem").exists())
            self.assertTrue((Path(temporary) / "managed" / "certificate-11" / "privkey.pem").exists())
            reload_nginx.assert_called_once()
            self.assertEqual(report.call_count, 2)


class NginxDeploymentRollbackTest(unittest.TestCase):
    def test_reload_failure_restores_previous_certificate_and_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "fullchain.pem"
            key = root / "privkey.pem"
            backup_root = root / "backups"
            certificate.write_bytes(b"old certificate")
            key.write_bytes(b"old key")
            binding = {
                "site_name": "rollback.pmr.vn",
                "domain": "rollback.pmr.vn",
                "port": 443,
                "protocol": "https",
                "listen_host": "127.0.0.1",
                "certificate_path": str(certificate),
                "key_path": str(key),
                "certificate_write_path": str(certificate),
                "key_write_path": str(key),
                "binding_id": "rollback",
            }
            desired = {
                "certificate_id": 10,
                "certificate_version_id": 20,
                "version_id": "260901",
                "package_revision": 1,
                "deployment_revision": "260901-r1",
                "fingerprint_sha256": "a" * 64,
            }
            response = {"download": "placeholder"}
            package = {
                "deployment_id": 50,
                "fullchain": b"new certificate",
                "key": b"new key",
                "expected": "a" * 64,
            }
            old_config = agent.CONFIG
            agent.CONFIG = {"paths": {"backup_root": str(backup_root)}}
            try:
                def install_new_files(bindings, downloaded):
                    certificate.write_bytes(downloaded["fullchain"])
                    key.write_bytes(downloaded["key"])

                with mock.patch.object(agent, "fingerprint_file", return_value="b" * 64), \
                        mock.patch.object(agent, "api_request", return_value=response), \
                        mock.patch.object(agent, "decode_package", return_value=package), \
                        mock.patch.object(agent, "install_package", side_effect=install_new_files), \
                        mock.patch.object(
                            agent,
                            "nginx_test_reload",
                            side_effect=[RuntimeError("nginx reload failed"), None],
                        ), \
                        mock.patch.object(agent, "restore_selinux_context"), \
                        mock.patch.object(agent, "report_deployment") as report:
                    with self.assertRaisesRegex(RuntimeError, "Rollback completed successfully"):
                        agent.deploy_group([binding], desired, "token", "machine")

                self.assertEqual(certificate.read_bytes(), b"old certificate")
                self.assertEqual(key.read_bytes(), b"old key")
                self.assertEqual(report.call_args.args[3], "FAILED")
            finally:
                agent.CONFIG = old_config


if __name__ == "__main__":
    unittest.main()
