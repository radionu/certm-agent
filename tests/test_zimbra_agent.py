import argparse
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock
from test_linux_agent import agent


class ZimbraSafetyTest(unittest.TestCase):
    def test_window_uses_vietnam_time_and_excludes_0400(self):
        for hour, expected in [(16, False), (17, True), (20, True), (21, False)]:
            self.assertEqual(agent.zimbra_window(datetime(2026, 9, 26, hour, tzinfo=timezone.utc)), expected)

    def test_zimbra_service_type_is_accepted(self):
        with mock.patch.object(agent, 'CONFIG', {'service': {'type': 'zimbra'}}):
            self.assertEqual(agent.service_type(), 'zimbra')

    def cycle(self, *, emergency=False, dry_run=False, window=False, failure=None):
        binding = {'domain': 'mail1.pmr.vn', 'certificate_path': '/unused'}
        patches = {
            'zimbra_binding': mock.Mock(return_value=binding),
            'read_active_identity': mock.Mock(return_value=('token', 'machine')),
            'push_inventory': mock.Mock(),
            'desired_for': mock.Mock(return_value={'fingerprint_sha256': 'a' * 64}),
            'fingerprint_file': mock.Mock(return_value='b' * 64),
            'zimbra_window': mock.Mock(return_value=window),
            'api_request': mock.Mock(return_value={'deployment_id': 42}),
            'decode_package': mock.Mock(return_value={}),
            'zimbra_stage': mock.Mock(return_value=Path('/unused-stage')),
            'zimbra_validate_stage': mock.Mock(side_effect=failure),
            'zimbra_deploy': mock.Mock(return_value='a' * 64),
            'report_deployment': mock.Mock(),
        }
        with mock.patch.multiple(agent, **patches), mock.patch.object(agent.shutil, 'rmtree'):
            args = argparse.Namespace(command='renew', emergency=emergency, dry_run=dry_run)
            if failure:
                with self.assertRaises(RuntimeError):
                    agent.zimbra_main(args)
            else:
                agent.zimbra_main(args)
        return patches

    def test_outside_window_never_downloads_or_restarts(self):
        p = self.cycle()
        p['api_request'].assert_not_called()
        p['zimbra_deploy'].assert_not_called()

    def test_dry_run_never_downloads_even_with_emergency(self):
        p = self.cycle(emergency=True, dry_run=True)
        p['api_request'].assert_not_called()
        p['zimbra_deploy'].assert_not_called()

    def test_emergency_can_deploy_outside_window(self):
        p = self.cycle(emergency=True)
        p['zimbra_deploy'].assert_called_once()
        self.assertEqual(p['report_deployment'].call_args.args[3], 'SUCCESS')

    def test_bad_chain_never_changes_zimbra(self):
        p = self.cycle(emergency=True, failure=RuntimeError('Invalid CA chain'))
        p['zimbra_deploy'].assert_not_called()
        self.assertEqual(p['report_deployment'].call_args.args[3], 'FAILED')

    def test_expired_previous_certificate_is_not_automatically_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'commercial.key').write_text('fake test key')
            with mock.patch.object(agent, 'zimbra_backup', return_value=stage), \
                 mock.patch.object(agent, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                 mock.patch.object(agent, 'fingerprint_file', return_value='b' * 64), \
                 mock.patch.object(agent.pwd, 'getpwnam', return_value=argparse.Namespace(pw_uid=0, pw_gid=0)), \
                 mock.patch.object(agent, 'atomic_write'), \
                 mock.patch.object(agent.os, 'chown'), \
                 mock.patch.object(Path, 'chmod'), \
                 mock.patch.object(agent, 'zimbra_run', side_effect=RuntimeError('deploy failed')) as runner:
                with self.assertRaisesRegex(RuntimeError, 'automatic rollback skipped'):
                    agent.zimbra_deploy(stage, {}, 'a' * 64)
                self.assertEqual(runner.call_count, 1)

    def test_success_sequence_restores_tls_before_ldap_save(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / 'commercial.key').write_text('fake test key')
            events = []
            def execute(*args, **kwargs):
                events.append(args)
            with mock.patch.object(agent, 'zimbra_backup', return_value=stage), \
                 mock.patch.object(agent, 'run', return_value=subprocess.CompletedProcess([], 1)), \
                 mock.patch.object(agent, 'fingerprint_file', return_value='b' * 64), \
                 mock.patch.object(agent.pwd, 'getpwnam', return_value=argparse.Namespace(pw_uid=0, pw_gid=0)), \
                 mock.patch.object(agent, 'atomic_write'), \
                 mock.patch.object(agent.os, 'chown'), \
                 mock.patch.object(Path, 'chmod'), \
                 mock.patch.object(agent, 'zimbra_run', side_effect=execute), \
                 mock.patch.object(agent, 'zimbra_verify', side_effect=lambda *a: events.append(('verify',)) or 'a' * 64):
                self.assertEqual(agent.zimbra_deploy(stage, {}, 'a' * 64), 'a' * 64)
            self.assertIn('-localonly', events[0])
            self.assertEqual(events[1][1], 'restart')
            self.assertEqual(events[2], ('verify',))
            self.assertEqual(events[3][1], 'savecrt')


if __name__ == '__main__':
    unittest.main()
