import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "certm_agent_update", ROOT / "linux" / "certm-agent-update.py"
)
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


class LinuxUpdaterSafetyTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
