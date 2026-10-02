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
        "linux/systemd/certm-agent-update.service",
        "linux/systemd/certm-agent-update.timer",
    ],
    "windows": [
        "windows/CertM.Agent.ps1",
        "windows/CertM.Update.ps1",
        "windows/Uninstall-CertMAgent.ps1",
    ],
    "pfsense": [
        "pfsense/CertM.HAProxy.Agent.php",
        "pfsense/certm-haproxy",
    ],
}

VERSION_SOURCES = {
    "linux": (
        "linux/certm-agent.py",
        r'^AGENT_VERSION\s*=\s*["\']([^"\']+)',
    ),
    "windows": (
        "windows/CertM.Agent.ps1",
        r"AgentVersion\s*=\s*'([^']+)'",
    ),
    "pfsense": (
        "pfsense/CertM.HAProxy.Agent.php",
        r"CERTM_PFSENSE_AGENT_VERSION\s*=\s*'([^']+)'",
    ),
}


def declared_version(root, platform):
    relative, pattern = VERSION_SOURCES[platform]
    match = re.search(pattern, (root / relative).read_text(), re.M | re.I)
    if not match:
        raise SystemExit(f"Unable to read {platform} agent version")
    return match.group(1)


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


def check_platform_version(root, platform, version):
    if declared_version(root, platform) != version:
        raise SystemExit(
            f"{platform} runtime does not declare version {version}"
        )
    if platform == "linux":
        updater = (root / "linux/certm-agent-update.py").read_text()
        match = re.search(
            r'^UPDATER_VERSION\s*=\s*["\']([^"\']+)',
            updater,
            re.M,
        )
        if not match or match.group(1) != version:
            raise SystemExit(
                "linux/certm-agent-update.py has a different version"
            )
    if platform == "windows":
        updater = (root / "windows/CertM.Update.ps1").read_text()
        match = re.search(
            r"UpdaterVersion\s*=\s*'([^']+)'",
            updater,
            re.I,
        )
        if not match or match.group(1) != version:
            raise SystemExit(
                "windows/CertM.Update.ps1 has a different version"
            )


def build_tar(root, output, platform, data):
    manifest_bytes = (json.dumps(data, indent=2) + "\n").encode()
    with tarfile.open(output, "w:gz") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(manifest_bytes))
        for relative in PLATFORM_FILES[platform]:
            archive.add(
                root / relative,
                arcname=relative,
                recursive=False,
            )


def build_windows(root, output, data):
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(data, indent=2) + "\n",
        )
        for relative in PLATFORM_FILES["windows"]:
            archive.write(root / relative, relative)


def main():
    parser = argparse.ArgumentParser(
        description="Build independent CertM agent update packages"
    )
    parser.add_argument(
        "version",
        nargs="?",
        help="Optional version assertion for selected platforms",
    )
    parser.add_argument(
        "--platform",
        action="append",
        choices=tuple(PLATFORM_FILES),
        dest="platforms",
        help="Build only this platform; may be repeated",
    )
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    platforms = args.platforms or list(PLATFORM_FILES)
    built = []

    for platform in platforms:
        version = declared_version(root, platform)
        if args.version is not None and version != args.version:
            raise SystemExit(
                f"{platform} declares {version}, not {args.version}"
            )
        check_platform_version(root, platform, version)
        extension = ".zip" if platform == "windows" else ".tar.gz"
        path = output / (
            f"certm-agent-{platform}-{version}{extension}"
        )
        data = manifest(root, platform, version)
        if platform == "windows":
            build_windows(root, path, data)
        else:
            build_tar(root, path, platform, data)
        built.append(path)

    for path in built:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"{digest}  {path}")


if __name__ == "__main__":
    main()
