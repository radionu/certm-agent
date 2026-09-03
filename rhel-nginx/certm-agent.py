#!/usr/bin/env python3

import argparse
import base64
import fcntl
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

AGENT_VERSION = "0.4.0"
DEFAULT_CONFIG_FILE = Path("/etc/certm/agent.json")
LOGGER = logging.getLogger("certm-agent")
CONFIG = {}
CONFIG_FILE = DEFAULT_CONFIG_FILE


def log(message):
    LOGGER.info(message)
    print(message)


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            if isinstance(data, str):
                data = data.encode()
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def load_config(path):
    global CONFIG, CONFIG_FILE
    CONFIG_FILE = Path(path)
    if not CONFIG_FILE.exists():
        raise RuntimeError(f"Configuration file not found: {CONFIG_FILE}")
    CONFIG = json.loads(CONFIG_FILE.read_text())
    if int(CONFIG.get("config_version", 0)) != 2:
        raise RuntimeError("Agent 0.4.0 requires config_version=2")
    api_base = str(CONFIG.get("api_base", "")).rstrip("/")
    if not api_base.endswith("/api/v2"):
        raise RuntimeError("api_base must end with /api/v2")
    bindings = CONFIG.get("management", {}).get("bindings", [])
    if not isinstance(bindings, list) or not bindings:
        raise RuntimeError("management.bindings must contain at least one binding")
    seen = set()
    for item in bindings:
        domain = str(item.get("domain", "")).strip().lower().rstrip(".")
        port = int(item.get("port", 443))
        cert_dir = str(item.get("certificate_dir", "")).strip()
        if not domain or not cert_dir or not (1 <= port <= 65535):
            raise RuntimeError(f"Invalid managed binding: {item}")
        key = (domain, port)
        if key in seen:
            raise RuntimeError(f"Duplicate managed binding: {domain}:{port}")
        seen.add(key)
    return CONFIG


def setup_logging():
    log_file = Path(CONFIG.get("paths", {}).get("log_file", "/var/log/certm/certm-agent.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.setLevel(logging.INFO)
    LOGGER.handlers.clear()
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)


def run(cmd, input_data=None, check=True, timeout=30):
    result = subprocess.run(
        cmd,
        input=input_data,
        text=isinstance(input_data, str) or input_data is None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {result.stderr.strip()}")
    return result


def normalize_fp(value):
    if not value:
        return ""
    value = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def load_identity():
    token = str(CONFIG.get("client_token", "")).strip()
    machine_path = Path(CONFIG.get("machine_id_file", "/etc/machine-id"))
    if not token:
        raise RuntimeError(f"client_token is missing in {CONFIG_FILE}")
    if not machine_path.exists():
        raise RuntimeError(f"Machine ID file not found: {machine_path}")
    machine_id = machine_path.read_text().strip()
    if not machine_id:
        raise RuntimeError("Machine ID is empty")
    return token, machine_id


def save_client_token(token):
    token = str(token or "").strip()
    if not token:
        raise RuntimeError("CertM returned an empty client token")
    CONFIG["client_token"] = token
    atomic_write(CONFIG_FILE, json.dumps(CONFIG, indent=2) + "\n", 0o600)
    log(f"Client token saved to {CONFIG_FILE}")


def api_request(method, path, token, machine_id, payload=None, query=None):
    base = str(CONFIG["api_base"]).rstrip("/")
    url = base + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-CertM-Machine-ID": machine_id,
        "User-Agent": f"CertM-Agent/{AGENT_VERSION}",
    }
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    timeout = int(CONFIG.get("network", {}).get("api_timeout_seconds", 30))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            detail = json.loads(body)
        except Exception:
            detail = body
        raise RuntimeError(f"CertM API HTTP {exc.code}: {detail}")


def read_os_release():
    values = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            k, v = line.split("=", 1)
            values[k.lower()] = v.strip().strip('"')
    return values


def local_preflight():
    if os.geteuid() != 0:
        raise RuntimeError("CertM agent must run as root")
    if sys.version_info < (3, 8):
        raise RuntimeError("Python 3.8 or newer is required")
    for command in ("openssl", "nginx", "systemctl"):
        if shutil.which(command) is None:
            raise RuntimeError(f"Required command not found: {command}")
    nginx = run(["nginx", "-v"], check=False)
    if nginx.returncode != 0:
        raise RuntimeError("nginx -v failed")
    token, machine_id = load_identity()
    osrel = read_os_release()
    log(f"CertM Agent version={AGENT_VERSION}")
    log(f"Platform={osrel.get('pretty_name', osrel.get('name', 'Linux'))}")
    log(f"Web service={nginx.stderr.strip() or nginx.stdout.strip()}")
    log(f"Managed bindings={len(CONFIG['management']['bindings'])}")
    log("Local preflight successful")
    return token, machine_id, osrel


def enrollment_payload(osrel):
    return {
        "machine_id": Path(CONFIG.get("machine_id_file", "/etc/machine-id")).read_text().strip(),
        "hostname": socket.gethostname(),
        "agent_type": "nginx",
        "agent_version": AGENT_VERSION,
        "os_name": osrel.get("id") or osrel.get("name") or "linux",
        "os_version": osrel.get("version_id") or "",
    }


def preflight():
    token, machine_id, osrel = local_preflight()
    identity = api_request("GET", "/client/preflight", token, machine_id)
    status = str(identity.get("status", "")).lower()
    if status == "enrollment_available":
        answer = input("This server is not enrolled with CertM. Enroll now? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            log("Enrollment skipped")
            return
        response = api_request("POST", "/client/enroll", token, machine_id, enrollment_payload(osrel))
        if str(response.get("status", "")).lower() != "pending_approval":
            raise RuntimeError(f"Unexpected enrollment response: {response}")
        save_client_token(response.get("client_token"))
        log(f"Enrollment successful. Client ID={response.get('client_id')} status=PENDING_APPROVAL")
        return
    if status == "pending_approval":
        log(f"Client ID={identity.get('client_id')} is PENDING_APPROVAL")
        return
    if status == "active":
        log(f"Client identity valid. Client ID={identity.get('client_id')} status=ACTIVE")
        return
    raise RuntimeError(f"CertM denied client identity: {status or identity}")


def main_cli():
    parser = argparse.ArgumentParser(description="CertM nginx certificate deployment agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_FILE))
    parser.add_argument("command", choices=["preflight", "renew"])
    args = parser.parse_args()
    load_config(args.config)
    setup_logging()
    log(f"Starting certm-agent command={args.command}")
    if args.command == "preflight":
        preflight()
        return 0
    # Full renew pipeline remains in the server repository source of 0.4.0 during migration.
    # It will be moved here next, before this public repository is treated as release-ready.
    raise RuntimeError("Public repo migration is incomplete: renew pipeline not yet published")


if __name__ == "__main__":
    try:
        sys.exit(main_cli())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
