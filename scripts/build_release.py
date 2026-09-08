#!/usr/bin/env python3

import argparse
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path


PLATFORM_FILES = {
    "linux": [
        "linux/certm-agent.py",
        "linux/certm-agent-update.py",
        "linux/certm_agent/__init__.py",
        "linux/certm_agent/apache.py",
        "linux/systemd/certm-agent.service",
        "linux/systemd/certm-agent.timer",
        # RC12's updater requires these paths while installing transitional
        # RC13. RC13 removes the units locally and accepts their omission in
        # subsequent package manifests.
        "linux/systemd/certm-agent-update.service",
        "linux/systemd/certm-agent-update.timer",
    ],
    "windows": [
        "windows/CertM.Agent.ps1",
        "windows/CertM.Update.ps1",
        "windows/Uninstall-CertMAgent.ps1",
    ],
}


def manifest(root, platform, version):
    files = []
    for relative in PLATFORM_FILES[platform]:
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"Missing release file: {relative}")
        files.append({
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    return {
        "schema": 1,
        "platform": platform,
        "version": version,
        "files": files,
    }


def check_version(root, version):
    checks = {
        "linux/certm-agent.py": r'^AGENT_VERSION\s*=\s*["\']([^"\']+)',
        "linux/certm-agent-update.py": r'^UPDATER_VERSION\s*=\s*["\']([^"\']+)',
        "windows/CertM.Agent.ps1": r"AgentVersion\s*=\s*'([^']+)'",
        "windows/CertM.Update.ps1": r"UpdaterVersion\s*=\s*'([^']+)'",
    }
    for relative, pattern in checks.items():
        match = re.search(pattern, (root / relative).read_text(), re.M | re.I)
        if not match or match.group(1) != version:
            raise SystemExit(f"{relative} does not declare version {version}")


def build_linux(root, output, data):
    manifest_bytes = (json.dumps(data, indent=2) + "\n").encode()
    with tarfile.open(output, "w:gz") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(manifest_bytes))
        for relative in PLATFORM_FILES["linux"]:
            archive.add(root / relative, arcname=relative, recursive=False)


def build_windows(root, output, data):
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(data, indent=2) + "\n")
        for relative in PLATFORM_FILES["windows"]:
            archive.write(root / relative, relative)


def main():
    parser = argparse.ArgumentParser(description="Build CertM signed-update payloads")
    parser.add_argument("version")
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    check_version(root, args.version)

    linux_path = output / f"certm-agent-linux-{args.version}.tar.gz"
    windows_path = output / f"certm-agent-windows-{args.version}.zip"
    build_linux(root, linux_path, manifest(root, "linux", args.version))
    build_windows(root, windows_path, manifest(root, "windows", args.version))

    for path in (linux_path, windows_path):
        print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}")


if __name__ == "__main__":
    main()
