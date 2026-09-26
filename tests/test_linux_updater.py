import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "certm_agent_update", ROOT / "linux" / "certm-agent-update.py"
)
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


class LinuxUpdaterSafetyTest(unittest.TestCase):
    def test_legacy_launcher_selects_an_available_python_38_or_newer(self):
        with tempfile.TemporaryDirectory() as temporary:
            binaries = Path(temporary)
            old_python = binaries / "python3"
            old_python.write_text("#!/bin/sh\nexit 1\n")
            old_python.chmod(0o755)
            (binaries / "python3.8").symlink_to(sys.executable)

            result = subprocess.run(
                [
                    "/bin/sh",
                    str(ROOT / "linux" / "certm-agent.py"),
                    "--help",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={"PATH": str(binaries)},
                timeout=30,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CertM API v2 Linux web-server agent", result.stdout)

    def test_installer_pinned_entrypoints_remain_valid_python(self):
        for relative in (
            "linux/certm-agent.py",
            "linux/certm-agent-update.py",
        ):
            source = (ROOT / relative).read_text()
            self.assertTrue(source.startswith("#!/bin/sh\n"))
            pinned = (
                f"#!{sys.executable}\n"
                + source.split("\n", 1)[1]
            )
            compile(pinned, relative, "exec")

    def test_copy_atomic_pins_executable_scripts_to_running_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "package" / "certm-agent.py"
            target = root / "installed" / "certm-agent.py"
            source.parent.mkdir()
            source.write_text("#!/usr/bin/env python3\nprint('agent')\n")

            with mock.patch.object(
                UPDATER.sys,
                "executable",
                "/opt/certm-python/bin/python3.9",
            ):
                UPDATER.copy_atomic(source, target)

            self.assertEqual(
                target.read_text(),
                "#!/opt/certm-python/bin/python3.9\nprint('agent')\n",
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o750)

    def test_copy_atomic_leaves_library_content_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "package" / "apache.py"
            target = root / "installed" / "apache.py"
            source.parent.mkdir()
            source.write_text("VALUE = 1\n")

            UPDATER.copy_atomic(source, target)

            self.assertEqual(target.read_text(), "VALUE = 1\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_self_test_reports_interpreter_failure_details(self):
        result = mock.MagicMock(
            returncode=1,
            stdout="",
            stderr="ERROR CertM Agent requires Python 3.8 or newer",
        )

        with mock.patch.object(
            UPDATER.subprocess,
            "run",
            return_value=result,
        ), mock.patch.object(
            UPDATER,
            "installed_version",
            return_value="1.0.0-rc.23",
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "exit_code=1.*requires Python 3.8 or newer",
            ):
                UPDATER.self_test("1.0.0-rc.23")

    def test_ip_approval_error_is_operator_friendly(self):
        error = UPDATER.ApiError(403, {
            "status": "ip_pending_approval",
            "source_ip": "198.51.100.20",
            "message": "This source IP is waiting for administrator approval.",
        })

        self.assertIn("198.51.100.20", str(error))
        self.assertIn("administrator approval", str(error))

    def test_safe_extract_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                contents = b"bad"
                info = tarfile.TarInfo("../outside")
                info.size = len(contents)
                package.addfile(info, io.BytesIO(contents))

            with self.assertRaisesRegex(RuntimeError, "Unsafe archive path"):
                UPDATER.safe_extract(archive, root / "extract")

    def test_manifest_requires_exact_runtime_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = []
            for relative in UPDATER.TARGETS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                contents = relative.encode()
                path.write_bytes(contents)
                files.append({
                    "path": relative,
                    "sha256": hashlib.sha256(contents).hexdigest(),
                })
            (root / "manifest.json").write_text(json.dumps({
                "schema": 1,
                "platform": "linux",
                "version": "1.0.0-rc.11",
                "files": files,
            }))

            manifest = UPDATER.verify_manifest(root, "1.0.0-rc.11")
            self.assertEqual("linux", manifest["platform"])

            (root / next(iter(UPDATER.TARGETS))).write_text("tampered")
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                UPDATER.verify_manifest(root, "1.0.0-rc.11")

    def test_manifest_rejects_undeclared_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = []
            for relative in UPDATER.TARGETS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative)
                files.append({
                    "path": relative,
                    "sha256": hashlib.sha256(relative.encode()).hexdigest(),
                })
            (root / "manifest.json").write_text(json.dumps({
                "schema": 1,
                "platform": "linux",
                "version": "1.0.0-rc.11",
                "files": files,
            }))
            (root / "unexpected.sh").write_text("echo unexpected")

            with self.assertRaisesRegex(RuntimeError, "undeclared"):
                UPDATER.verify_manifest(root, "1.0.0-rc.11")

    def test_manifest_accepts_runtime_without_legacy_schedule_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = []
            for relative in UPDATER.CORE_TARGETS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                contents = relative.encode()
                path.write_bytes(contents)
                files.append({
                    "path": relative,
                    "sha256": hashlib.sha256(contents).hexdigest(),
                })
            (root / "manifest.json").write_text(json.dumps({
                "schema": 1,
                "platform": "linux",
                "version": "1.0.0-rc.15",
                "files": files,
            }))

            manifest = UPDATER.verify_manifest(root, "1.0.0-rc.15")

            self.assertEqual(files, manifest["files"])

    def test_retires_legacy_update_timer_and_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = {
                "service": root / "certm-agent-update.service",
                "timer": root / "certm-agent-update.timer",
            }
            for path in legacy.values():
                path.write_text("legacy")

            with mock.patch.object(UPDATER, "LEGACY_TARGETS", legacy), \
                    mock.patch.object(UPDATER.subprocess, "run") as run, \
                    mock.patch.object(UPDATER, "log") as log:
                UPDATER.retire_legacy_schedule()

            self.assertFalse(any(path.exists() for path in legacy.values()))
            self.assertEqual(2, run.call_count)
            self.assertIn(
                "six-hour certificate cycle",
                log.call_args.args[0],
            )


if __name__ == "__main__":
    unittest.main()
