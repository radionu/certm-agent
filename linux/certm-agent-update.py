#!/usr/bin/env python3

import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


UPDATER_VERSION = "1.0.0-rc.13"
CONFIG_PATH = Path("/etc/certm/agent.json")
PUBLIC_KEY_PATH = Path("/etc/certm/update-public.pem")
LOCK_PATH = Path("/run/certm-agent.lock")
STATE_ROOT = Path("/var/lib/certm/agent-updates")
LOG_PATH = Path("/var/log/certm/certm-agent-update.log")

CORE_TARGETS = {
    "linux/certm-agent.py": Path("/opt/certm-agent/certm-agent.py"),
    "linux/certm-agent-update.py": Path("/opt/certm-agent/certm-agent-update.py"),
    "linux/certm_agent/__init__.py": Path("/opt/certm-agent/certm_agent/__init__.py"),
    "linux/certm_agent/apache.py": Path("/opt/certm-agent/certm_agent/apache.py"),
    "linux/systemd/certm-agent.service": Path("/etc/systemd/system/certm-agent.service"),
    "linux/systemd/certm-agent.timer": Path("/etc/systemd/system/certm-agent.timer"),
}
LEGACY_TARGETS = {
    "linux/systemd/certm-agent-update.service": Path("/etc/systemd/system/certm-agent-update.service"),
    "linux/systemd/certm-agent-update.timer": Path("/etc/systemd/system/certm-agent-update.timer"),
}
TARGETS = {**CORE_TARGETS, **LEGACY_TARGETS}


def log(message):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = str(message)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    print(line)


def load_config():
    config = json.loads(CONFIG_PATH.read_text())
    token = str(config.get("client_token", "")).strip()
    if not token:
        return config, None, None
    machine_path = Path(config.get("machine_id_file", "/etc/machine-id"))
    machine_id = machine_path.read_text().strip()
    if not machine_id:
        raise RuntimeError("Machine ID is empty")
    return config, token, machine_id


def installed_version():
    path = Path("/opt/certm-agent/certm-agent.py")
    if not path.is_file():
        return UPDATER_VERSION
    match = re.search(r'^AGENT_VERSION\s*=\s*["\']([^"\']+)', path.read_text(), re.M)
    return match.group(1) if match else UPDATER_VERSION


def headers(token, machine_id):
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-CertM-Agent-Type": "updater-linux",
        "X-CertM-Agent-Version": installed_version(),
        "X-CertM-Machine-ID": machine_id,
        "User-Agent": f"CertM-Agent-Updater/{UPDATER_VERSION}",
    }


def api_json(config, token, machine_id, method, path, payload=None):
    url = str(config["api_base"]).rstrip("/") + path
    request_headers = headers(token, machine_id)
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    timeout = int(config.get("network", {}).get("api_timeout_seconds", 30))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
    return json.loads(body.decode("utf-8")) if body else {}


def report(config, token, machine_id, release_id, status, message="", version=None):
    payload = {"release_id": release_id, "status": status, "message": str(message)[:2000]}
    if version:
        payload["installed_version"] = version
    try:
        api_json(config, token, machine_id, "POST", "/client/agent-update/report", payload)
    except Exception as exc:
        log(f"Unable to report update status {status}: {exc}")


def pin_or_validate_key(config, token, machine_id, expected_fingerprint):
    metadata = api_json(config, token, machine_id, "GET", "/client/agent-update/key")
    if metadata.get("algorithm") != "RSA-SHA256":
        raise RuntimeError("Unsupported signing-key algorithm")
    pem = str(metadata.get("pem", ""))
    fingerprint = hashlib.sha256(pem.encode("utf-8")).hexdigest()
    if fingerprint != metadata.get("fingerprint_sha256") or fingerprint != expected_fingerprint:
        raise RuntimeError("Agent-update signing-key fingerprint mismatch")

    if PUBLIC_KEY_PATH.exists():
        pinned = PUBLIC_KEY_PATH.read_text()
        if hashlib.sha256(pinned.encode("utf-8")).hexdigest() != fingerprint:
            raise RuntimeError("Server signing key differs from the locally pinned key")
    else:
        PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = PUBLIC_KEY_PATH.with_suffix(".tmp")
        temporary.write_text(pem)
        os.chmod(temporary, 0o644)
        os.replace(temporary, PUBLIC_KEY_PATH)
        log(f"Pinned agent-update public key {fingerprint}")


def download(config, token, machine_id, path, destination):
    if not str(path).startswith("/client/agent-update/download/"):
        raise RuntimeError("Server returned an invalid update download path")
    url = str(config["api_base"]).rstrip("/") + str(path)
    request = urllib.request.Request(url, headers=headers(token, machine_id), method="GET")
    timeout = int(config.get("network", {}).get("api_timeout_seconds", 30))
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def safe_extract(archive, destination):
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if destination_resolved != target and destination_resolved not in target.parents:
                raise RuntimeError(f"Unsafe archive path: {member.name}")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise RuntimeError(f"Unsupported archive entry: {member.name}")
        package.extractall(destination)


def verify_manifest(root, expected_version):
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("platform") != "linux":
        raise RuntimeError("Invalid Linux update manifest")
    if manifest.get("version") != expected_version:
        raise RuntimeError("Manifest version does not match assigned release")
    declared = set()
    for item in manifest.get("files", []):
        relative = str(item.get("path", ""))
        if relative not in TARGETS or relative in declared:
            raise RuntimeError(f"Unexpected manifest file: {relative}")
        path = root / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
            raise RuntimeError(f"Manifest hash mismatch: {relative}")
        declared.add(relative)
    if declared not in (set(CORE_TARGETS), set(TARGETS)):
        raise RuntimeError("Manifest does not contain the complete Linux runtime")
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    if actual != declared:
        raise RuntimeError("Archive contains undeclared files")
    return manifest


def copy_atomic(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        executable_names = {"certm-agent.py", "certm-agent-update.py"}
        os.chmod(temporary, 0o750 if target.name in executable_names else 0o644)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def install(root, backup, declared):
    backup.mkdir(parents=True, exist_ok=False)
    existing = {}
    for relative in declared:
        target = TARGETS[relative]
        if target.exists():
            saved = backup / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, saved)
            existing[relative] = True
        else:
            existing[relative] = False
        copy_atomic(root / relative, target)
    (backup / "existing.json").write_text(json.dumps(existing))
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)


def rollback(backup):
    existing = json.loads((backup / "existing.json").read_text())
    for relative in existing:
        target = TARGETS[relative]
        if existing.get(relative):
            copy_atomic(backup / relative, target)
        else:
            target.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)


def self_test(version):
    result = subprocess.run(
        [str(TARGETS["linux/certm-agent.py"]), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or installed_version() != version:
        raise RuntimeError("Updated Linux agent failed its executable/version self-test")


def retire_legacy_schedule():
    legacy_paths = tuple(LEGACY_TARGETS.values())
    if not any(path.exists() for path in legacy_paths):
        return
    subprocess.run(
        ["systemctl", "disable", "--now", "certm-agent-update.timer"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    for path in legacy_paths:
        path.unlink(missing_ok=True)
    subprocess.run(
        ["systemctl", "daemon-reload"],
        check=False,
        timeout=30,
    )
    log("Retired legacy 15-minute agent-update timer; updates now run with the six-hour certificate cycle")


def run_update():
    if os.geteuid() != 0:
        raise RuntimeError("CertM updater must run as root")
    config, token, machine_id = load_config()
    if not token:
        log("Client enrollment has not completed; update check skipped")
        return

    response = api_json(config, token, machine_id, "GET", "/client/agent-update")
    update = response.get("update")
    if not update:
        return
    if update.get("platform") != "linux":
        raise RuntimeError("Server assigned a non-Linux update to this client")

    release_id = int(update["release_id"])
    version = str(update["version"])
    report(config, token, machine_id, release_id, "STARTED", f"Installing Linux agent {version}")
    modified = False

    with tempfile.TemporaryDirectory(prefix="certm-update-", dir=str(STATE_ROOT)) as temporary_name:
        temporary = Path(temporary_name)
        archive = temporary / "package.tar.gz"
        extracted = temporary / "extracted"
        signature = temporary / "signature.bin"
        backup = temporary / "backup"
        extracted.mkdir()

        try:
            pin_or_validate_key(config, token, machine_id, update["signing_key_fingerprint"])
            download(config, token, machine_id, update["download_path"], archive)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != update["sha256"]:
                raise RuntimeError("Downloaded package SHA-256 mismatch")
            signature.write_bytes(base64.b64decode(update["signature"], validate=True))
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(PUBLIC_KEY_PATH), "-signature", str(signature), str(archive)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            safe_extract(archive, extracted)
            manifest = verify_manifest(extracted, version)
            modified = True
            install(
                extracted,
                backup,
                [str(item["path"]) for item in manifest["files"]],
            )
            self_test(version)
            report(config, token, machine_id, release_id, "SUCCESS", f"Linux agent {version} installed", version)
            log(f"CertM Linux agent updated successfully to {version}")
        except Exception as exc:
            report(config, token, machine_id, release_id, "FAILED", str(exc))
            if modified:
                try:
                    rollback(backup)
                    report(config, token, machine_id, release_id, "ROLLBACK", f"Rolled back after: {exc}")
                except Exception as rollback_exc:
                    log(f"Rollback failed: {rollback_exc}")
            raise


def main():
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_ROOT, 0o700)
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Another CertM agent process is running; update check skipped")
            return
        retire_legacy_schedule()
        run_update()


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        log(f"CertM updater HTTP error {exc.code}")
        sys.exit(1)
    except Exception as exc:
        log(f"CertM updater failed: {exc}")
        sys.exit(1)
