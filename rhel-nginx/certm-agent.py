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
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


AGENT_VERSION = "1.0.0-rc.2"
DEFAULT_CONFIG_FILE = Path("/etc/certm/agent.json")
LOGGER = logging.getLogger("certm-agent")
CONFIG = {}
CONFIG_FILE = DEFAULT_CONFIG_FILE


class ApiError(RuntimeError):
    def __init__(self, code, detail):
        self.code = int(code)
        self.detail = detail
        super().__init__(f"CertM API HTTP {self.code}: {detail}")


@dataclass
class NginxNode:
    name: str
    args: List[str]
    children: Optional[List["NginxNode"]] = None
    source_file: Optional[str] = None
    start: int = 0
    end: int = 0


@dataclass
class NginxToken:
    value: str
    start: int
    end: int


def log(message, level=logging.INFO):
    LOGGER.log(level, message)
    print(message)


def warn(message):
    log(f"WARNING {message}", logging.WARNING)


def atomic_write(path, data, default_mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = default_mode
    owner = None
    try:
        existing = path.stat()
        mode = stat.S_IMODE(existing.st_mode)
        owner = (existing.st_uid, existing.st_gid)
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            if isinstance(data, str):
                data = data.encode()
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if owner is not None:
            os.chown(temporary, owner[0], owner[1])
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load_config(path):
    global CONFIG, CONFIG_FILE
    CONFIG_FILE = Path(path)
    if not CONFIG_FILE.exists():
        raise RuntimeError(f"Configuration file not found: {CONFIG_FILE}")
    CONFIG = json.loads(CONFIG_FILE.read_text())
    if int(CONFIG.get("config_version", 0)) != 3:
        raise RuntimeError("CertM nginx agent 1.0 requires config_version=3")
    api_base = str(CONFIG.get("api_base", "")).rstrip("/")
    if not api_base.startswith("https://") or not api_base.endswith("/api/v2"):
        raise RuntimeError("api_base must use HTTPS and end with /api/v2")
    if not str(CONFIG.get("client_token", "")).strip():
        raise RuntimeError(f"client_token is missing in {CONFIG_FILE}")
    roots = CONFIG.get("discovery", {}).get("allowed_certificate_roots", [])
    if not isinstance(roots, list) or not roots:
        raise RuntimeError("discovery.allowed_certificate_roots must not be empty")
    for root in roots:
        if not Path(str(root)).is_absolute():
            raise RuntimeError(f"Allowed certificate root must be absolute: {root}")
    config_roots = CONFIG.get("discovery", {}).get(
        "allowed_config_roots",
        ["/etc/nginx"],
    )
    if not isinstance(config_roots, list) or not config_roots:
        raise RuntimeError("discovery.allowed_config_roots must not be empty")
    for root in config_roots:
        if not Path(str(root)).is_absolute():
            raise RuntimeError(f"Allowed nginx config root must be absolute: {root}")
    managed_root = Path(
        CONFIG.get("paths", {}).get(
            "managed_certificate_root",
            "/etc/certm/live",
        )
    )
    if not managed_root.is_absolute():
        raise RuntimeError("paths.managed_certificate_root must be absolute")
    if not path_is_allowed(managed_root, roots):
        raise RuntimeError(
            "paths.managed_certificate_root must be inside an allowed certificate root"
        )
    return CONFIG


def setup_logging():
    log_file = Path(CONFIG.get("paths", {}).get("log_file", "/var/log/certm/certm-agent.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.setLevel(logging.INFO)
    LOGGER.handlers.clear()
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(message)s",
        "%Y-%m-%dT%H:%M:%S",
    )
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
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {detail}")
    return result


def normalize_fingerprint(value):
    if not value:
        return ""
    normalized = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    return normalized if re.fullmatch(r"[0-9a-f]{64}", normalized) else ""


def load_identity():
    token = str(CONFIG.get("client_token", "")).strip()
    machine_path = Path(CONFIG.get("machine_id_file", "/etc/machine-id"))
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
    url = str(CONFIG["api_base"]).rstrip("/") + path
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
        raise ApiError(exc.code, detail) from exc


def read_os_release():
    values = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key.lower()] = value.strip().strip('"')
    return values


def validate_local_environment():
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
    return (nginx.stderr or nginx.stdout).strip()


def nginx_dump():
    result = run(["nginx", "-T"], timeout=60)
    if "# configuration file " in result.stdout:
        return result.stdout
    if "# configuration file " in result.stderr:
        return "".join(
            line for line in result.stderr.splitlines(keepends=True)
            if not line.lstrip().startswith("nginx:")
        )
    return result.stdout + "\n" + result.stderr


def nginx_prefix():
    result = run(["nginx", "-V"], check=False)
    text = result.stderr + " " + result.stdout
    match = re.search(r"(?:^|\s)--prefix=([^\s]+)", text)
    return Path(match.group(1)) if match else Path("/")


def tokenize_nginx(text):
    tokens = []
    current = []
    current_start = None
    quote = None
    escaped = False
    comment = False

    def flush(end):
        nonlocal current_start
        if current:
            tokens.append(NginxToken("".join(current), current_start, end))
            current.clear()
            current_start = None

    for position, char in enumerate(text):
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                current.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char == "#":
            flush(position)
            comment = True
        elif char in ("'", '"'):
            if current_start is None:
                current_start = position
            quote = char
        elif char.isspace():
            flush(position)
        elif char in ("{", "}", ";"):
            flush(position)
            tokens.append(NginxToken(char, position, position + 1))
        else:
            if current_start is None:
                current_start = position
            current.append(char)
    if quote:
        raise RuntimeError("Unterminated quote in nginx configuration")
    flush(len(text))
    return tokens


def parse_nginx_nodes(tokens, start=0, nested=False, source_file=None):
    nodes = []
    index = start
    while index < len(tokens):
        if tokens[index].value == "}":
            if not nested:
                raise RuntimeError("Unexpected closing brace in nginx configuration")
            return nodes, index + 1, tokens[index].end
        words = []
        while index < len(tokens) and tokens[index].value not in ("{", "}", ";"):
            words.append(tokens[index])
            index += 1
        if not words:
            raise RuntimeError("Invalid nginx configuration token sequence")
        if index >= len(tokens):
            raise RuntimeError(
                f"Unterminated nginx directive: {' '.join(token.value for token in words)}"
            )
        delimiter = tokens[index]
        if delimiter.value == "}":
            raise RuntimeError(
                f"Missing semicolon before closing brace: "
                f"{' '.join(token.value for token in words)}"
            )
        if delimiter.value == ";":
            nodes.append(
                NginxNode(
                    words[0].value,
                    [token.value for token in words[1:]],
                    source_file=source_file,
                    start=words[0].start,
                    end=delimiter.end,
                )
            )
            index += 1
            continue
        children, index, block_end = parse_nginx_nodes(
            tokens,
            index + 1,
            nested=True,
            source_file=source_file,
        )
        nodes.append(
            NginxNode(
                words[0].value,
                [token.value for token in words[1:]],
                children,
                source_file=source_file,
                start=words[0].start,
                end=block_end,
            )
        )
    if nested:
        raise RuntimeError("Unclosed block in nginx configuration")
    return nodes, index, len(tokens)


def nginx_dump_sections(text):
    sections = []
    source_file = None
    lines = []
    marker = re.compile(r"^# configuration file (.+):\s*$")
    for line in text.splitlines(keepends=True):
        match = marker.match(line.rstrip("\r\n"))
        if match:
            if source_file is not None:
                sections.append((source_file, "".join(lines)))
            source_file = match.group(1)
            lines = []
        elif source_file is not None:
            lines.append(line)
    if source_file is not None:
        sections.append((source_file, "".join(lines)))
    return sections


def parse_nginx_dump(text):
    sections = nginx_dump_sections(text)
    if not sections:
        sections = [(None, text)]
    nodes = []
    for source_file, content in sections:
        filtered = content if source_file else "\n".join(
            line for line in content.splitlines()
            if not line.lstrip().startswith("nginx:")
        )
        parsed, _, _ = parse_nginx_nodes(
            tokenize_nginx(filtered),
            source_file=source_file,
        )
        nodes.extend(parsed)
    return nodes


def walk_server_nodes(nodes):
    for node in nodes:
        if node.children is None:
            continue
        if node.name.lower() == "server":
            yield node
            continue
        yield from walk_server_nodes(node.children)


def node_directives(node, name):
    return [
        child.args for child in (node.children or [])
        if child.children is None and child.name.lower() == name.lower()
    ]


def direct_nodes(node, name):
    return [
        child for child in (node.children or [])
        if child.children is None and child.name.lower() == name.lower()
    ]


def normalize_domain(value):
    value = str(value).strip().rstrip(".").lower()
    if not value or value == "_" or value.startswith(("~", ".")):
        return None
    if "*" in value or "$" in value or "/" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    label = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if not all(label.fullmatch(part) for part in value.split(".")):
        return None
    return value


def parse_listen(args, ssl_enabled=False):
    lowered = [str(item).lower() for item in args]
    if not args or ("ssl" not in lowered and not ssl_enabled):
        return None
    target = str(args[0])
    if target.startswith("unix:"):
        return None
    host = "127.0.0.1"
    port_text = target
    if target.startswith("["):
        match = re.fullmatch(r"\[([^]]+)\]:(\d+)", target)
        if not match:
            return None
        host, port_text = match.group(1), match.group(2)
    elif ":" in target:
        host, port_text = target.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    if host in ("*", "0.0.0.0"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    return host, port


def resolved_nginx_path(value, prefix):
    value = str(value).strip()
    if not value or "$" in value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = Path(prefix) / path
    return Path(os.path.normpath(str(path)))


def path_is_allowed(path, roots):
    resolved = Path(path).resolve(strict=False)
    for root in roots:
        allowed = Path(root).resolve(strict=False)
        try:
            if os.path.commonpath((str(resolved), str(allowed))) == str(allowed):
                return True
        except ValueError:
            continue
    return False


def make_binding_id(domain, port, certificate_path, key_path):
    digest = hashlib.sha256(
        f"nginx\0{domain}\0{port}\0{certificate_path}\0{key_path}".encode()
    ).hexdigest()[:20]
    return f"nginx:{domain}:{port}:{digest}"


def bindings_from_dump(text, prefix, allowed_roots, max_bindings=1000):
    candidates = {}
    warnings = []
    roots = [Path(item) for item in allowed_roots]
    source_contents = {source: content for source, content in nginx_dump_sections(text)}

    for position, server in enumerate(walk_server_nodes(parse_nginx_dump(text)), start=1):
        ssl_enabled = any(
            args and str(args[0]).lower() == "on"
            for args in node_directives(server, "ssl")
        )
        listens = []
        for args in node_directives(server, "listen"):
            parsed = parse_listen(args, ssl_enabled)
            if parsed and parsed not in listens:
                listens.append(parsed)
        if not listens:
            continue

        domains = []
        for args in node_directives(server, "server_name"):
            for raw_domain in args:
                domain = normalize_domain(raw_domain)
                if domain and domain not in domains:
                    domains.append(domain)
                elif not domain:
                    warnings.append(
                        f"server block {position}: skip non-concrete server_name {raw_domain!r}"
                    )
        if not domains:
            warnings.append(f"server block {position}: no concrete DNS server_name")
            continue

        certificate_nodes = [node for node in direct_nodes(server, "ssl_certificate") if node.args]
        key_nodes = [node for node in direct_nodes(server, "ssl_certificate_key") if node.args]
        certificate_values = {str(node.args[0]) for node in certificate_nodes}
        key_values = {str(node.args[0]) for node in key_nodes}
        if (
            len(certificate_values) != 1
            or len(key_values) != 1
            or len(certificate_nodes) != 1
            or len(key_nodes) != 1
        ):
            warnings.append(
                f"server block {position}: require exactly one ssl_certificate and one ssl_certificate_key"
            )
            continue
        certificate_path = resolved_nginx_path(next(iter(certificate_values)), prefix)
        key_path = resolved_nginx_path(next(iter(key_values)), prefix)
        if certificate_path is None or key_path is None:
            warnings.append(f"server block {position}: variable or invalid certificate path")
            continue
        certificate_write_path = certificate_path.resolve(strict=False)
        key_write_path = key_path.resolve(strict=False)
        if certificate_write_path == key_write_path:
            warnings.append(f"server block {position}: certificate and key paths are identical")
            continue
        if not path_is_allowed(certificate_path, roots) or not path_is_allowed(
            certificate_write_path, roots
        ):
            warnings.append(
                f"server block {position}: certificate path is outside allowed roots: {certificate_path}"
            )
            continue
        if not path_is_allowed(key_path, roots) or not path_is_allowed(key_write_path, roots):
            warnings.append(
                f"server block {position}: key path is outside allowed roots: {key_path}"
            )
            continue

        certificate_node = certificate_nodes[0]
        key_node = key_nodes[0]
        source_content = source_contents.get(server.source_file)
        server_text = (
            source_content[server.start:server.end]
            if source_content is not None else None
        )
        server_identity = hashlib.sha256(
            f"{server.source_file or ''}\0{server.start}\0{server.end}\0{server_text or ''}".encode()
        ).hexdigest()[:20]
        site_name = domains[0]
        for host, port in listens:
            for domain in domains:
                binding = {
                    "site_name": site_name,
                    "domain": domain,
                    "port": port,
                    "protocol": "https",
                    "listen_host": host,
                    "certificate_path": str(certificate_path),
                    "key_path": str(key_path),
                    "certificate_write_path": str(certificate_write_path),
                    "key_write_path": str(key_write_path),
                    "binding_id": make_binding_id(domain, port, certificate_path, key_path),
                    "config_file": server.source_file,
                    "config_server_id": server_identity,
                    "config_server_text": server_text,
                    "certificate_directive_start": certificate_node.start - server.start,
                    "certificate_directive_end": certificate_node.end - server.start,
                    "key_directive_start": key_node.start - server.start,
                    "key_directive_end": key_node.end - server.start,
                }
                identity = (domain, port)
                existing = candidates.get(identity)
                if existing:
                    existing_paths = (
                        existing["certificate_write_path"],
                        existing["key_write_path"],
                    )
                    new_paths = (
                        binding["certificate_write_path"],
                        binding["key_write_path"],
                    )
                    if existing_paths != new_paths:
                        raise RuntimeError(
                            f"Ambiguous nginx binding {domain}:{port} uses different certificate paths"
                        )
                    continue
                candidates[identity] = binding

    bindings = sorted(candidates.values(), key=lambda item: (item["domain"], item["port"]))
    if len(bindings) > int(max_bindings):
        raise RuntimeError(
            f"Discovered {len(bindings)} bindings, exceeding configured maximum {max_bindings}"
        )

    certificate_to_key = {}
    key_to_certificate = {}
    for binding in bindings:
        certificate = binding["certificate_write_path"]
        key = binding["key_write_path"]
        if certificate in certificate_to_key and certificate_to_key[certificate] != key:
            raise RuntimeError(f"Certificate path {certificate} is paired with multiple key paths")
        if key in key_to_certificate and key_to_certificate[key] != certificate:
            raise RuntimeError(f"Key path {key} is paired with multiple certificate paths")
        certificate_to_key[certificate] = key
        key_to_certificate[key] = certificate
    return bindings, warnings


def discover_bindings():
    discovery = CONFIG.get("discovery", {})
    bindings, warnings = bindings_from_dump(
        nginx_dump(),
        nginx_prefix(),
        discovery["allowed_certificate_roots"],
        int(discovery.get("max_bindings", 1000)),
    )
    for message in warnings:
        warn(message)
    log(f"Discovered {len(bindings)} concrete nginx HTTPS binding(s)")
    return bindings


def fingerprint_file(path):
    path = Path(path)
    if not path.exists():
        return ""
    result = run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"])
    return normalize_fingerprint(result.stdout.split("=", 1)[-1])


def openssl_date_iso(value):
    return datetime.strptime(
        value.strip(), "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc).isoformat()


def inspect_certificate(path):
    path = Path(path)
    if not path.exists():
        return {}
    result = run(
        ["openssl", "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-serial", "-dates"]
    )
    info = {"fingerprint_sha256": fingerprint_file(path)}
    for line in result.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("serial="):
            info["serial_number"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = openssl_date_iso(line.split("=", 1)[1])
        elif line.startswith("notAfter="):
            info["not_after"] = openssl_date_iso(line.split("=", 1)[1])
    return info


def served_fingerprint(binding):
    configured_host = str(CONFIG.get("verify", {}).get("connect_host", "")).strip()
    host = configured_host or binding.get("listen_host") or "127.0.0.1"
    timeout = int(CONFIG.get("verify", {}).get("connect_timeout_seconds", 15))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(binding["port"])), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=binding["domain"]) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def verify_served(binding, expected):
    timeout = int(CONFIG.get("verify", {}).get("retry_timeout_seconds", 30))
    interval = float(CONFIG.get("verify", {}).get("retry_interval_seconds", 1))
    deadline = time.monotonic() + timeout
    last = ""
    while True:
        try:
            last = normalize_fingerprint(served_fingerprint(binding))
            if last == expected:
                return last
        except Exception as exc:
            last = f"ERROR: {exc}"
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)
    raise RuntimeError(
        f"{binding['domain']}:{binding['port']} does not serve expected certificate; last={last}"
    )


def validate_cert_key(certificate, key):
    certificate_public = run(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"]
    ).stdout
    key_public = run(
        ["openssl", "pkey", "-in", str(key), "-pubout"]
    ).stdout
    if hashlib.sha256(certificate_public.encode()).digest() != hashlib.sha256(
        key_public.encode()
    ).digest():
        raise RuntimeError("Certificate and private key do not match")


def validate_hostname(certificate, domain):
    result = run(
        ["openssl", "x509", "-in", str(certificate), "-noout", "-checkhost", domain],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Downloaded certificate does not cover {domain}")


def validate_download_metadata(desired, metadata, expected):
    checks = {
        "id": int(desired["certificate_id"]),
        "certificate_version_id": int(desired["certificate_version_id"]),
        "version_id": str(desired["version_id"]),
        "package_revision": int(desired["package_revision"]),
        "deployment_revision": str(desired["deployment_revision"]),
    }
    for key, wanted in checks.items():
        if key not in metadata:
            raise RuntimeError(f"Download metadata missing {key}")
        actual = metadata[key]
        if key in ("id", "certificate_version_id", "package_revision"):
            actual = int(actual)
        else:
            actual = str(actual)
        if actual != wanted:
            raise RuntimeError(
                f"Download metadata mismatch for {key}: desired={wanted} downloaded={actual}"
            )
    if normalize_fingerprint(metadata.get("fingerprint_sha256")) != expected:
        raise RuntimeError("Downloaded fingerprint metadata does not match desired certificate")


def decode_package(response, desired, domains):
    if response.get("status") != "ok":
        raise RuntimeError(f"Unexpected download response: {response}")
    deployment_id = int(response.get("deployment_id", 0))
    metadata = response.get("certificate", {})
    files = response.get("files", {})
    expected = normalize_fingerprint(desired.get("fingerprint_sha256"))
    if deployment_id < 1 or len(expected) != 64:
        raise RuntimeError("Invalid deployment metadata")
    validate_download_metadata(desired, metadata, expected)
    try:
        certificate = base64.b64decode(files["certificate.pem"], validate=True)
        key = base64.b64decode(files["privkey.pem"], validate=True)
        fullchain = (
            base64.b64decode(files["fullchain.pem"], validate=True)
            if files.get("fullchain.pem") else certificate
        )
    except Exception as exc:
        raise RuntimeError(f"Invalid certificate package encoding: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="certm-package-") as temporary:
        certificate_path = Path(temporary) / "certificate.pem"
        fullchain_path = Path(temporary) / "fullchain.pem"
        key_path = Path(temporary) / "privkey.pem"
        certificate_path.write_bytes(certificate)
        fullchain_path.write_bytes(fullchain)
        key_path.write_bytes(key)
        validate_cert_key(certificate_path, key_path)
        for domain in domains:
            validate_hostname(certificate_path, domain)
        leaf = fingerprint_file(certificate_path)
        first_fullchain = fingerprint_file(fullchain_path)
        if leaf != expected:
            raise RuntimeError("Downloaded certificate fingerprint does not match metadata")
        if first_fullchain != leaf:
            raise RuntimeError("fullchain.pem does not start with the downloaded leaf certificate")
    return {
        "deployment_id": deployment_id,
        "fullchain": fullchain,
        "key": key,
        "expected": expected,
    }


def restore_selinux_context(paths):
    if shutil.which("restorecon"):
        run(["restorecon", "-F"] + [str(path) for path in paths], check=False)


def group_id(bindings):
    first = bindings[0]
    return hashlib.sha256(
        f"{first['certificate_write_path']}\0{first['key_write_path']}".encode()
    ).hexdigest()[:20]


def create_backup(bindings):
    first = bindings[0]
    certificate = Path(first["certificate_write_path"])
    key = Path(first["key_write_path"])
    root = Path(CONFIG.get("paths", {}).get("backup_root", "/opt/certm-agent/bkup"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = root / group_id(bindings) / stamp
    suffix = 0
    while target.exists():
        suffix += 1
        target = root / group_id(bindings) / f"{stamp}-{suffix}"
    target.mkdir(parents=True, exist_ok=False)
    manifest = {
        "certificate_path": str(certificate),
        "key_path": str(key),
        "certificate_backup": None,
        "key_backup": None,
    }
    if certificate.exists():
        destination = target / "certificate.pem"
        shutil.copy2(certificate, destination)
        manifest["certificate_backup"] = str(destination)
    if key.exists():
        destination = target / "privkey.pem"
        shutil.copy2(key, destination)
        manifest["key_backup"] = str(destination)
    atomic_write(target / "manifest.json", json.dumps(manifest, indent=2) + "\n", 0o600)
    return target, manifest


def restore_backup(manifest):
    for path_key, backup_key, mode in (
        ("certificate_path", "certificate_backup", 0o644),
        ("key_path", "key_backup", 0o600),
    ):
        path = Path(manifest[path_key])
        backup = manifest.get(backup_key)
        if backup:
            atomic_write(path, Path(backup).read_bytes(), mode)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    restore_selinux_context((manifest["certificate_path"], manifest["key_path"]))


def install_package(bindings, package):
    first = bindings[0]
    certificate = Path(first["certificate_write_path"])
    key = Path(first["key_write_path"])
    atomic_write(certificate, package["fullchain"], 0o644)
    atomic_write(key, package["key"], 0o600)
    restore_selinux_context((certificate, key))
    validate_cert_key(certificate, key)


def state_path(binding):
    root = Path(CONFIG.get("paths", {}).get("state_root", "/var/lib/certm/bindings"))
    digest = hashlib.sha256(binding["binding_id"].encode()).hexdigest()
    return root / f"{digest}.json"


def load_state(binding):
    path = state_path(binding)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_state(binding, desired, fingerprint):
    payload = {
        "binding_id": binding["binding_id"],
        "domain": binding["domain"],
        "port": int(binding["port"]),
        "certificate_id": desired["certificate_id"],
        "certificate_version_id": desired["certificate_version_id"],
        "version_id": desired["version_id"],
        "package_revision": int(desired["package_revision"]),
        "deployment_revision": desired["deployment_revision"],
        "fingerprint_sha256": fingerprint,
        "certificate_path": binding["certificate_path"],
        "key_path": binding["key_path"],
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write(state_path(binding), json.dumps(payload, indent=2) + "\n", 0o600)


def desired_for(binding, token, machine_id):
    try:
        response = api_request(
            "GET",
            "/cert/desired",
            token,
            machine_id,
            query={"domain": binding["domain"]},
        )
    except ApiError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if exc.code == 404 and detail.get("status") == "not_found":
            return None
        raise
    if response.get("status") != "ok":
        raise RuntimeError(
            f"Unexpected desired certificate response for {binding['domain']}: {response}"
        )
    return response


def desired_identity(desired):
    return (
        int(desired["certificate_id"]),
        int(desired["certificate_version_id"]),
        str(desired["version_id"]),
        int(desired["package_revision"]),
        str(desired["deployment_revision"]),
        normalize_fingerprint(desired["fingerprint_sha256"]),
    )


def report_deployment(
    token,
    machine_id,
    deployment_id,
    status,
    installed=None,
    served=None,
    message="",
):
    payload = {
        "deployment_id": deployment_id,
        "status": status,
        "message": message,
    }
    if installed:
        payload["installed_fingerprint"] = installed
    if served:
        payload["served_fingerprint"] = served
    return api_request("POST", "/deployment/report", token, machine_id, payload)


def inventory_item(binding):
    info = inspect_certificate(binding["certificate_write_path"])
    served = ""
    try:
        served = normalize_fingerprint(served_fingerprint(binding))
    except Exception:
        pass
    return {
        "site_name": binding["site_name"],
        "domain": binding["domain"],
        "port": int(binding["port"]),
        "protocol": "https",
        "subject": info.get("subject"),
        "issuer": info.get("issuer"),
        "serial_number": info.get("serial_number"),
        "fingerprint_sha256": info.get("fingerprint_sha256") or None,
        "served_fingerprint_sha256": served or None,
        "not_before": info.get("not_before"),
        "not_after": info.get("not_after"),
        "cert_path": binding["certificate_path"],
        "key_path": binding["key_path"],
        "binding_id": binding["binding_id"],
    }


def push_inventory(bindings, token, machine_id):
    items = [inventory_item(binding) for binding in bindings]
    response = api_request(
        "POST",
        "/client/inventory",
        token,
        machine_id,
        {"service": "nginx", "items": items},
    )
    log(f"Inventory submitted: {response.get('summary', {})}")
    return response


def binding_groups(bindings):
    groups = {}
    for binding in bindings:
        key = (binding["certificate_write_path"], binding["key_write_path"])
        groups.setdefault(key, []).append(binding)
    return [groups[key] for key in sorted(groups)]


def managed_certificate_paths(desired):
    certificate_id = int(desired["certificate_id"])
    if certificate_id < 1:
        raise RuntimeError("Desired certificate_id must be positive")
    root = Path(
        CONFIG.get("paths", {}).get(
            "managed_certificate_root",
            "/etc/certm/live",
        )
    )
    allowed_roots = CONFIG.get("discovery", {}).get("allowed_certificate_roots", [])
    directory = root / f"certificate-{certificate_id}"
    certificate = directory / "fullchain.pem"
    key = directory / "privkey.pem"
    certificate_write = certificate.resolve(strict=False)
    key_write = key.resolve(strict=False)
    for path in (certificate, key, certificate_write, key_write):
        if not path_is_allowed(path, allowed_roots):
            raise RuntimeError(f"Managed certificate path is outside allowed roots: {path}")
    if certificate_write == key_write:
        raise RuntimeError("Managed certificate and key paths resolve to the same file")
    return {
        "certificate_path": str(certificate),
        "key_path": str(key),
        "certificate_write_path": str(certificate_write),
        "key_write_path": str(key_write),
    }


def split_plan(bindings, desired_values):
    if len(bindings) != len(desired_values):
        raise RuntimeError("Internal error: binding and desired counts differ")
    servers = {}
    for binding, desired in zip(bindings, desired_values):
        server_id = binding.get("config_server_id")
        if not server_id:
            raise RuntimeError(
                f"Cannot locate nginx server block for {binding['domain']}:{binding['port']}"
            )
        item = servers.setdefault(
            server_id,
            {
                "binding": binding,
                "bindings": [],
                "desired": [],
            },
        )
        item["bindings"].append(binding)
        item["desired"].append(desired)

    for item in servers.values():
        identities = {
            desired_identity(value) if value is not None else None
            for value in item["desired"]
        }
        if len(identities) != 1:
            domains = sorted({binding["domain"] for binding in item["bindings"]})
            raise RuntimeError(
                "One nginx server block cannot use different CertM assignments: "
                + ", ".join(domains)
                + ". Split these server_name values into separate server blocks first"
            )
        item["desired"] = item["desired"][0]

    targets = {}
    untouched = []
    for item in servers.values():
        desired = item["desired"]
        if desired is None:
            untouched.extend(item["bindings"])
            continue
        identity = desired_identity(desired)
        target = targets.setdefault(
            identity,
            {
                "desired": desired,
                "bindings": [],
                "servers": [],
                "paths": managed_certificate_paths(desired),
            },
        )
        target["bindings"].extend(item["bindings"])
        target["servers"].append(item)
    target_values = list(targets.values())
    path_owners = {}
    for identity, target in targets.items():
        path_key = (
            target["paths"]["certificate_write_path"],
            target["paths"]["key_write_path"],
        )
        previous = path_owners.get(path_key)
        if previous is not None and previous != identity:
            raise RuntimeError(
                "Different desired certificate revisions resolve to the same managed paths"
            )
        path_owners[path_key] = identity
    return target_values, untouched


def nginx_path_literal(path):
    value = str(path)
    if not re.fullmatch(r"[A-Za-z0-9_./:+-]+", value):
        raise RuntimeError(f"Managed nginx path contains unsupported characters: {value}")
    return value


def render_split_config_updates(targets):
    changes = {}
    allowed_roots = CONFIG.get("discovery", {}).get(
        "allowed_config_roots",
        ["/etc/nginx"],
    )
    for target in targets:
        paths = target["paths"]
        certificate_literal = nginx_path_literal(paths["certificate_path"])
        key_literal = nginx_path_literal(paths["key_path"])
        for server in target["servers"]:
            binding = server["binding"]
            source_value = binding.get("config_file")
            expected = binding.get("config_server_text")
            if not source_value or expected is None:
                raise RuntimeError(
                    f"nginx -T did not identify an editable config file for {binding['domain']}"
                )
            source = Path(source_value)
            if not source.is_absolute():
                raise RuntimeError(f"nginx config path is not absolute: {source}")
            try:
                write_path = source.resolve(strict=True)
            except FileNotFoundError as exc:
                raise RuntimeError(f"nginx config file disappeared: {source}") from exc
            if not path_is_allowed(source, allowed_roots) or not path_is_allowed(
                write_path,
                allowed_roots,
            ):
                raise RuntimeError(f"nginx config path is outside allowed roots: {source}")
            key = str(write_path)
            entry = changes.setdefault(
                key,
                {
                    "path": write_path,
                    "content": write_path.read_text(),
                    "replacements": [],
                },
            )
            positions = [
                match.start()
                for match in re.finditer(re.escape(expected), entry["content"])
            ]
            if len(positions) != 1:
                raise RuntimeError(
                    f"nginx server block changed or is not unique in {source}; rerun discovery"
                )
            base = positions[0]
            entry["replacements"].extend(
                [
                    (
                        base + int(binding["certificate_directive_start"]),
                        base + int(binding["certificate_directive_end"]),
                        f"ssl_certificate {certificate_literal};",
                    ),
                    (
                        base + int(binding["key_directive_start"]),
                        base + int(binding["key_directive_end"]),
                        f"ssl_certificate_key {key_literal};",
                    ),
                ]
            )

    rendered = {}
    for entry in changes.values():
        content = entry["content"]
        replacements = sorted(entry["replacements"], reverse=True)
        previous_start = len(content) + 1
        for start, end, replacement in replacements:
            if not 0 <= start < end <= len(content) or end > previous_start:
                raise RuntimeError(f"Overlapping or invalid nginx edit in {entry['path']}")
            content = content[:start] + replacement + content[end:]
            previous_start = start
        rendered[str(entry["path"])] = content
    return rendered


def create_file_set_backup(bindings, paths):
    root = Path(CONFIG.get("paths", {}).get("backup_root", "/opt/certm-agent/bkup"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = root / group_id(bindings) / f"{stamp}-config-split"
    suffix = 0
    while target.exists():
        suffix += 1
        target = root / group_id(bindings) / f"{stamp}-config-split-{suffix}"
    target.mkdir(parents=True, exist_ok=False)
    manifest = []
    for index, value in enumerate(sorted({str(Path(item)) for item in paths}), start=1):
        path = Path(value)
        record = {
            "path": str(path),
            "backup": None,
        }
        if path.exists():
            destination = target / f"{index:03d}-{path.name}"
            shutil.copy2(path, destination)
            record["backup"] = str(destination)
        manifest.append(record)
    atomic_write(target / "manifest.json", json.dumps(manifest, indent=2) + "\n", 0o600)
    return target, manifest


def restore_file_set(manifest):
    restored = []
    for record in manifest:
        path = Path(record["path"])
        backup = record.get("backup")
        if backup:
            atomic_write(path, Path(backup).read_bytes())
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        restored.append(path)
    restore_selinux_context(restored)


def binding_with_managed_paths(binding, paths):
    updated = dict(binding)
    updated.update(paths)
    updated["binding_id"] = make_binding_id(
        updated["domain"],
        int(updated["port"]),
        updated["certificate_path"],
        updated["key_path"],
    )
    return updated


def nginx_test_reload():
    run(["nginx", "-t"])
    unit = str(CONFIG.get("service", {}).get("systemd_unit", "nginx"))
    run(["systemctl", "reload", unit])


def deploy_group(bindings, desired, token, machine_id, dry_run=False):
    expected = normalize_fingerprint(desired.get("fingerprint_sha256"))
    revision = str(desired.get("deployment_revision", ""))
    domains = [binding["domain"] for binding in bindings]
    certificate_path = bindings[0]["certificate_write_path"]
    local_fingerprint = fingerprint_file(certificate_path)
    states_current = all(
        load_state(binding).get("deployment_revision") == revision for binding in bindings
    )
    if local_fingerprint == expected:
        try:
            for binding in bindings:
                verify_served(binding, expected)
                save_state(binding, desired, expected)
            note = "state refreshed" if not states_current else "already current"
            log(f"Group {group_id(bindings)} {note} and verified for {', '.join(domains)}")
            return False
        except Exception as exc:
            warn(f"Local certificate matches but served verification failed; redeploying: {exc}")

    if dry_run:
        log(
            f"DRY RUN would deploy {revision} to group {group_id(bindings)} "
            f"for {', '.join(domains)}"
        )
        return False

    representative = bindings[0]
    response = api_request(
        "GET",
        "/cert/download",
        token,
        machine_id,
        query={
            "domain": representative["domain"],
            "service": "nginx",
            "port": int(representative["port"]),
        },
    )
    package = decode_package(response, desired, domains)
    deployment_id = package["deployment_id"]
    _, manifest = create_backup(bindings)
    complete_backup = bool(manifest["certificate_backup"] and manifest["key_backup"])
    try:
        install_package(bindings, package)
        nginx_test_reload()
        installed = fingerprint_file(certificate_path)
        if installed != expected:
            raise RuntimeError("Installed fingerprint does not match desired certificate")
        served_values = [verify_served(binding, expected) for binding in bindings]
        report = report_deployment(
            token,
            machine_id,
            deployment_id,
            "SUCCESS",
            installed=installed,
            served=served_values[-1],
            message=(
                f"Certificate installed, nginx reloaded and {len(bindings)} binding(s) verified"
            ),
        )
        if report.get("status") != "ok":
            raise RuntimeError(f"CertM rejected SUCCESS report: {report}")
        for binding in bindings:
            save_state(binding, desired, expected)
        log(f"CERTIFICATE UPDATE SUCCESSFUL: {revision} for {', '.join(domains)}")
        return True
    except Exception as exc:
        failure = str(exc)
        if complete_backup:
            try:
                restore_backup(manifest)
                nginx_test_reload()
                rollback_text = "Rollback completed successfully"
            except Exception as rollback_exc:
                rollback_text = f"Rollback failed: {rollback_exc}"
        else:
            rollback_text = "No complete previous certificate/key pair was available for rollback"
        try:
            report_deployment(
                token,
                machine_id,
                deployment_id,
                "FAILED",
                message=f"{failure}. {rollback_text}",
            )
        except Exception as report_exc:
            warn(f"Unable to report failed deployment: {report_exc}")
        raise RuntimeError(f"Deployment failed: {failure}. {rollback_text}")


def deploy_split_group(bindings, desired_values, token, machine_id, dry_run=False):
    targets, untouched = split_plan(bindings, desired_values)
    if not targets:
        return False

    for target in targets:
        domains = sorted({binding["domain"] for binding in target["bindings"]})
        paths = target["paths"]
        log(
            f"{'DRY RUN would split' if dry_run else 'Splitting'} nginx config for "
            f"{', '.join(domains)} -> {paths['certificate_path']}"
        )
    if untouched:
        domains = sorted({binding["domain"] for binding in untouched})
        log(
            "No CertM assignment for "
            + ", ".join(domains)
            + "; their current nginx paths will remain unchanged"
        )
    config_updates = render_split_config_updates(targets)
    if dry_run:
        log(
            "DRY RUN validated nginx config edits for: "
            + ", ".join(sorted(config_updates))
        )
        return False

    deployments = []
    manifest = None
    local_changes_started = False
    try:
        for target in targets:
            representative = target["bindings"][0]
            response = api_request(
                "GET",
                "/cert/download",
                token,
                machine_id,
                query={
                    "domain": representative["domain"],
                    "service": "nginx",
                    "port": int(representative["port"]),
                },
            )
            domains = sorted({binding["domain"] for binding in target["bindings"]})
            package = decode_package(response, target["desired"], domains)
            deployments.append(
                {
                    "target": target,
                    "package": package,
                    "bindings": [
                        binding_with_managed_paths(binding, target["paths"])
                        for binding in target["bindings"]
                    ],
                }
            )

        changed_paths = list(config_updates)
        for deployment in deployments:
            paths = deployment["target"]["paths"]
            changed_paths.extend(
                [paths["certificate_write_path"], paths["key_write_path"]]
            )
        _, manifest = create_file_set_backup(bindings, changed_paths)

        local_changes_started = True
        for deployment in deployments:
            install_package([deployment["target"]["paths"]], deployment["package"])
        for path, content in config_updates.items():
            atomic_write(path, content)
        restore_selinux_context(config_updates)
        nginx_test_reload()

        for deployment in deployments:
            target = deployment["target"]
            desired = target["desired"]
            expected = normalize_fingerprint(desired.get("fingerprint_sha256"))
            installed = fingerprint_file(target["paths"]["certificate_write_path"])
            if installed != expected:
                raise RuntimeError("Installed fingerprint does not match desired certificate")
            served_values = [
                verify_served(binding, expected)
                for binding in deployment["bindings"]
            ]
            deployment["installed"] = installed
            deployment["served"] = served_values[-1]

        for deployment in deployments:
            target = deployment["target"]
            package = deployment["package"]
            domains = sorted({binding["domain"] for binding in deployment["bindings"]})
            report = report_deployment(
                token,
                machine_id,
                package["deployment_id"],
                "SUCCESS",
                installed=deployment["installed"],
                served=deployment["served"],
                message=(
                    "Certificate installed, nginx config split, nginx reloaded and "
                    f"{len(deployment['bindings'])} binding(s) verified"
                ),
            )
            if report.get("status") != "ok":
                raise RuntimeError(f"CertM rejected SUCCESS report: {report}")
            expected = normalize_fingerprint(target["desired"].get("fingerprint_sha256"))
            for binding in deployment["bindings"]:
                save_state(binding, target["desired"], expected)
            log(
                "CERTIFICATE UPDATE SUCCESSFUL: "
                f"{target['desired']['deployment_revision']} for {', '.join(domains)}"
            )
        return True
    except Exception as exc:
        failure = str(exc)
        if local_changes_started and manifest is not None:
            try:
                restore_file_set(manifest)
                nginx_test_reload()
                rollback_text = "Config and certificate rollback completed successfully"
            except Exception as rollback_exc:
                rollback_text = f"Rollback failed: {rollback_exc}"
        else:
            rollback_text = "No local changes were made"
        for deployment in deployments:
            try:
                report_deployment(
                    token,
                    machine_id,
                    deployment["package"]["deployment_id"],
                    "FAILED",
                    message=f"{failure}. {rollback_text}",
                )
            except Exception as report_exc:
                warn(f"Unable to report failed deployment: {report_exc}")
        raise RuntimeError(f"Split deployment failed: {failure}. {rollback_text}")


def read_active_identity():
    token, machine_id = load_identity()
    identity = api_request("GET", "/client/preflight", token, machine_id)
    if identity.get("status") == "pending_approval":
        raise RuntimeError(f"Client {identity.get('client_id')} is waiting for administrator approval")
    if identity.get("status") != "active":
        raise RuntimeError(f"CertM denied client identity: {identity.get('status')}")
    status = api_request("GET", "/client/status", token, machine_id)
    if status.get("status") != "active":
        raise RuntimeError(f"Client is not ACTIVE: {status.get('status')}")
    return token, machine_id


def enrollment_payload(os_release):
    machine_id = Path(CONFIG.get("machine_id_file", "/etc/machine-id")).read_text().strip()
    return {
        "machine_id": machine_id,
        "hostname": socket.gethostname(),
        "agent_type": "nginx",
        "agent_version": AGENT_VERSION,
        "os_name": os_release.get("id") or os_release.get("name") or "linux",
        "os_version": os_release.get("version_id") or "",
    }


def preflight():
    nginx_version = validate_local_environment()
    bindings = discover_bindings()
    token, machine_id = load_identity()
    os_release = read_os_release()
    log(f"CertM Agent version={AGENT_VERSION}")
    log(f"Platform={os_release.get('pretty_name', os_release.get('name', 'Linux'))}")
    log(f"Web service={nginx_version}")
    log(f"Discovered bindings={len(bindings)}")
    identity = api_request("GET", "/client/preflight", token, machine_id)
    status = str(identity.get("status", "")).lower()
    if status == "enrollment_available":
        answer = input("This server is not enrolled with CertM. Enroll now? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            log("Enrollment skipped")
            return
        response = api_request(
            "POST", "/client/enroll", token, machine_id, enrollment_payload(os_release)
        )
        if str(response.get("status", "")).lower() != "pending_approval":
            raise RuntimeError(f"Unexpected enrollment response: {response}")
        save_client_token(response.get("client_token"))
        log(
            f"Enrollment successful. Client ID={response.get('client_id')} "
            "status=PENDING_APPROVAL"
        )
        return
    if status == "pending_approval":
        log(f"Client ID={identity.get('client_id')} is PENDING_APPROVAL")
        return
    if status == "active":
        log(f"Client identity valid. Client ID={identity.get('client_id')} status=ACTIVE")
        return
    raise RuntimeError(f"CertM denied client identity: {status or identity}")


def inventory():
    validate_local_environment()
    token, machine_id = read_active_identity()
    bindings = discover_bindings()
    push_inventory(bindings, token, machine_id)


def renew(dry_run=False):
    validate_local_environment()
    token, machine_id = read_active_identity()
    bindings = discover_bindings()
    push_inventory(bindings, token, machine_id)
    changed = 0
    errors = []

    for group in binding_groups(bindings):
        try:
            desired_values = [desired_for(binding, token, machine_id) for binding in group]
            present = [value for value in desired_values if value is not None]
            domains = [binding["domain"] for binding in group]
            if not present:
                log(
                    f"Group {group_id(group)} has no assigned certificate for "
                    f"{', '.join(domains)}; keeping current files"
                )
                continue
            identities = {desired_identity(value) for value in present}
            if len(present) == len(group) and len(identities) == 1:
                changed_now = deploy_group(group, present[0], token, machine_id, dry_run)
            else:
                changed_now = deploy_split_group(
                    group,
                    desired_values,
                    token,
                    machine_id,
                    dry_run,
                )
            if changed_now:
                changed += 1
        except Exception as exc:
            errors.append(str(exc))
            log(f"ERROR {exc}", logging.ERROR)

    try:
        post_bindings = discover_bindings() if changed else bindings
        push_inventory(post_bindings, token, machine_id)
    except Exception as exc:
        warn(f"Post-renew inventory failed: {exc}")
    if errors:
        raise RuntimeError("; ".join(errors))
    log(f"Renew completed successfully; changed_groups={changed}; dry_run={dry_run}")


def parse_args():
    parser = argparse.ArgumentParser(description="CertM API v2 nginx agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_FILE))
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("preflight")
    subcommands.add_parser("discover")
    subcommands.add_parser("inventory")
    renew_parser = subcommands.add_parser("renew")
    renew_parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    load_config(args.config)
    setup_logging()
    lock_path = Path(CONFIG.get("paths", {}).get("lock_file", "/run/certm-agent.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another CertM agent process is already running")
        log(f"Starting certm-agent command={args.command} version={AGENT_VERSION}")
        if args.command == "preflight":
            preflight()
        elif args.command == "discover":
            validate_local_environment()
            print(json.dumps(discover_bindings(), indent=2))
        elif args.command == "inventory":
            inventory()
        else:
            renew(bool(args.dry_run))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        LOGGER.exception("CertM agent failed")
        print(f"ERROR {exc}", file=sys.stderr)
        sys.exit(1)
