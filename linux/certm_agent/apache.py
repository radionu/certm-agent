import glob
import hashlib
import os
import re
import shlex
from pathlib import Path


def _path_is_allowed(path, roots):
    resolved = Path(path).resolve(strict=False)
    for root in roots:
        allowed = Path(root).resolve(strict=False)
        try:
            if os.path.commonpath((str(resolved), str(allowed))) == str(allowed):
                return True
        except ValueError:
            continue
    return False


def _normalize_domain(value):
    value = str(value).strip().rstrip(".").lower()
    if value.startswith("http://") or value.startswith("https://"):
        value = value.split("://", 1)[1]
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            value = host
    if (
        not value
        or value == "_"
        or "*" in value
        or "$" in value
        or value.startswith("~")
        or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value)
    ):
        return None
    return value


def _parse_virtual_host(value):
    target = str(value).strip()
    if target.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", target)
        if not match:
            return None
        host, port_text = match.groups()
    elif ":" in target:
        host, port_text = target.rsplit(":", 1)
    else:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    if host in ("*", "0.0.0.0", "_default_"):
        host = "127.0.0.1"
    elif host == "::":
        host = "::1"
    return host, port


def _directive_values(block, name):
    pattern = re.compile(
        rf"(?im)^[ \t]*{re.escape(name)}[ \t]+([^\r\n#]+?)[ \t]*(?:#.*)?$"
    )
    values = []
    for match in pattern.finditer(block):
        try:
            args = shlex.split(match.group(1), comments=False, posix=True)
        except ValueError:
            args = []
        values.append((args, match.start(), match.end()))
    return values


def _single_path_directive(block, name):
    values = _directive_values(block, name)
    if len(values) != 1 or len(values[0][0]) != 1:
        return None
    return values[0][0][0], values[0][1], values[0][2]


def _apache_runtime_paths(run, control):
    result = run([control, "-V"], check=False)
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    root_match = re.search(r'-D HTTPD_ROOT="([^"]+)"', output)
    config_match = re.search(r'-D SERVER_CONFIG_FILE="([^"]+)"', output)
    root = Path(root_match.group(1)) if root_match else Path("/etc/apache2")
    config = Path(config_match.group(1)) if config_match else Path("apache2.conf")
    if not config.is_absolute():
        config = root / config
    return root.resolve(strict=False), config.resolve(strict=False)


def _included_files(run, control, server_root, main_config, allowed_config_roots):
    result = run([control, "-t", "-D", "DUMP_INCLUDES"], check=False, timeout=60)
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    files = []
    for line in output.splitlines():
        match = re.search(r"\((?:\d+|\*)\)[ \t]+(/\S.*)$", line.strip())
        if match:
            candidate = Path(match.group(1).strip()).resolve(strict=False)
            if candidate.is_file() and _path_is_allowed(candidate, allowed_config_roots):
                files.append(candidate)
    if files:
        if main_config.is_file() and main_config not in files:
            files.insert(0, main_config)
        return list(dict.fromkeys(files))

    found = []
    visited = set()

    def visit(path):
        path = Path(path).resolve(strict=False)
        if path in visited or not path.is_file():
            return
        if not _path_is_allowed(path, allowed_config_roots):
            return
        visited.add(path)
        found.append(path)
        content = path.read_text(errors="replace")
        for match in re.finditer(
            r"(?im)^[ \t]*(Include|IncludeOptional)[ \t]+([^\r\n#]+)", content
        ):
            optional = match.group(1).lower() == "includeoptional"
            try:
                args = shlex.split(match.group(2), comments=False, posix=True)
            except ValueError:
                args = []
            for value in args:
                value = value.replace("${APACHE_CONFDIR}", str(server_root))
                include = Path(value)
                if not include.is_absolute():
                    include = server_root / include
                matches = sorted(glob.glob(str(include)))
                if not matches and not optional:
                    continue
                for included in matches:
                    visit(included)

    visit(main_config)
    return found


def _resolved_path(value, server_root):
    if not value or "$" in str(value):
        return None
    path = Path(str(value))
    if not path.is_absolute():
        path = server_root / path
    return Path(os.path.normpath(str(path)))


def _binding_id(domain, port, certificate_path, key_path):
    digest = hashlib.sha256(
        f"apache\0{domain}\0{port}\0{certificate_path}\0{key_path}".encode()
    ).hexdigest()[:20]
    return f"apache:{domain}:{port}:{digest}"


def discover_apache_bindings(config, run, control):
    discovery = config.get("discovery", {})
    allowed_config_roots = [Path(item) for item in discovery.get(
        "allowed_config_roots", ["/etc/apache2", "/etc/httpd"]
    )]
    allowed_certificate_roots = [Path(item) for item in discovery.get(
        "allowed_certificate_roots", []
    )]
    max_bindings = int(discovery.get("max_bindings", 1000))
    server_root, main_config = _apache_runtime_paths(run, control)
    config_files = _included_files(
        run, control, server_root, main_config, allowed_config_roots
    )
    if not config_files:
        raise RuntimeError(f"Apache configuration files could not be discovered from {main_config}")

    candidates = {}
    warnings = []
    vhost_pattern = re.compile(
        r"(?is)<VirtualHost[ \t]+([^>]+)>(.*?)</VirtualHost[ \t]*>"
    )
    for source in config_files:
        content = source.read_text(errors="replace")
        for position, match in enumerate(vhost_pattern.finditer(content), start=1):
            block = match.group(0)
            listens = []
            try:
                targets = shlex.split(match.group(1), comments=False, posix=True)
            except ValueError:
                targets = []
            for target in targets:
                parsed = _parse_virtual_host(target)
                if parsed and parsed not in listens:
                    listens.append(parsed)
            if not listens:
                warnings.append(f"{source}: VirtualHost {position} has no concrete TCP port")
                continue

            domains = []
            for name in ("ServerName", "ServerAlias"):
                for args, _, _ in _directive_values(block, name):
                    for raw_domain in args:
                        domain = _normalize_domain(raw_domain)
                        if domain and domain not in domains:
                            domains.append(domain)
                        elif not domain:
                            warnings.append(
                                f"{source}: VirtualHost {position} skip non-concrete {name} {raw_domain!r}"
                            )
            if not domains:
                warnings.append(f"{source}: VirtualHost {position} has no concrete DNS name")
                continue

            certificate = _single_path_directive(block, "SSLCertificateFile")
            key = _single_path_directive(block, "SSLCertificateKeyFile")
            if certificate is None or key is None:
                warnings.append(
                    f"{source}: VirtualHost {position} requires exactly one "
                    "SSLCertificateFile and SSLCertificateKeyFile"
                )
                continue
            certificate_path = _resolved_path(certificate[0], server_root)
            key_path = _resolved_path(key[0], server_root)
            if certificate_path is None or key_path is None:
                warnings.append(f"{source}: VirtualHost {position} has a variable certificate path")
                continue
            certificate_write = certificate_path.resolve(strict=False)
            key_write = key_path.resolve(strict=False)
            if certificate_write == key_write:
                raise RuntimeError(f"Apache certificate and key resolve to the same file: {source}")
            for path, write_path, label in (
                (certificate_path, certificate_write, "certificate"),
                (key_path, key_write, "key"),
            ):
                if not _path_is_allowed(path, allowed_certificate_roots) or not _path_is_allowed(
                    write_path, allowed_certificate_roots
                ):
                    raise RuntimeError(f"Apache {label} path is outside allowed roots: {path}")

            chain = _single_path_directive(block, "SSLCertificateChainFile")
            chain_path = _resolved_path(chain[0], server_root) if chain else None
            chain_write = chain_path.resolve(strict=False) if chain_path else None
            if chain_path and (
                not _path_is_allowed(chain_path, allowed_certificate_roots)
                or not _path_is_allowed(chain_write, allowed_certificate_roots)
            ):
                raise RuntimeError(f"Apache chain path is outside allowed roots: {chain_path}")

            server_identity = hashlib.sha256(
                f"{source}\0{match.start()}\0{match.end()}\0{block}".encode()
            ).hexdigest()[:20]
            for host, port in listens:
                for domain in domains:
                    binding = {
                        "site_name": domains[0],
                        "domain": domain,
                        "port": port,
                        "protocol": "https",
                        "listen_host": host,
                        "certificate_path": str(certificate_path),
                        "key_path": str(key_path),
                        "certificate_write_path": str(certificate_write),
                        "key_write_path": str(key_write),
                        "binding_id": _binding_id(domain, port, certificate_path, key_path),
                        "config_file": str(source),
                        "config_server_id": server_identity,
                        "config_server_text": block,
                        "certificate_directive_start": certificate[1],
                        "certificate_directive_end": certificate[2],
                        "key_directive_start": key[1],
                        "key_directive_end": key[2],
                        "chain_path": str(chain_path) if chain_path else None,
                        "chain_write_path": str(chain_write) if chain_write else None,
                        "chain_directive_start": chain[1] if chain else None,
                        "chain_directive_end": chain[2] if chain else None,
                    }
                    identity = (domain, port)
                    existing = candidates.get(identity)
                    if existing:
                        old_paths = (existing["certificate_write_path"], existing["key_write_path"])
                        new_paths = (binding["certificate_write_path"], binding["key_write_path"])
                        if old_paths != new_paths:
                            raise RuntimeError(
                                f"Ambiguous apache binding {domain}:{port} uses different certificate paths"
                            )
                        continue
                    candidates[identity] = binding

    bindings = sorted(candidates.values(), key=lambda item: (item["domain"], item["port"]))
    if len(bindings) > max_bindings:
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


def render_apache_split_config_updates(targets, config, path_is_allowed):
    changes = {}
    allowed_roots = config.get("discovery", {}).get(
        "allowed_config_roots", ["/etc/apache2", "/etc/httpd"]
    )
    for target in targets:
        certificate_path = str(target["paths"]["certificate_path"])
        key_path = str(target["paths"]["key_path"])
        for server in target["servers"]:
            binding = server["binding"]
            source = Path(binding["config_file"])
            write_path = source.resolve(strict=True)
            if not path_is_allowed(source, allowed_roots) or not path_is_allowed(write_path, allowed_roots):
                raise RuntimeError(f"Apache config path is outside allowed roots: {source}")
            expected = binding["config_server_text"]
            entry = changes.setdefault(
                str(write_path),
                {"path": write_path, "content": write_path.read_text(), "replacements": []},
            )
            positions = [match.start() for match in re.finditer(re.escape(expected), entry["content"])]
            if len(positions) != 1:
                raise RuntimeError(
                    f"Apache VirtualHost changed or is not unique in {source}; rerun discovery"
                )
            base = positions[0]
            entry["replacements"].extend(
                [
                    (
                        base + int(binding["certificate_directive_start"]),
                        base + int(binding["certificate_directive_end"]),
                        f"SSLCertificateFile {certificate_path}",
                    ),
                    (
                        base + int(binding["key_directive_start"]),
                        base + int(binding["key_directive_end"]),
                        f"SSLCertificateKeyFile {key_path}",
                    ),
                ]
            )
            if binding.get("chain_directive_start") is not None:
                entry["replacements"].append(
                    (
                        base + int(binding["chain_directive_start"]),
                        base + int(binding["chain_directive_end"]),
                        "# SSLCertificateChainFile removed; full chain managed by CertM",
                    )
                )
    rendered = {}
    for entry in changes.values():
        content = entry["content"]
        previous_start = len(content) + 1
        for start, end, replacement in sorted(entry["replacements"], reverse=True):
            if not 0 <= start < end <= len(content) or end > previous_start:
                raise RuntimeError(f"Overlapping or invalid Apache edit in {entry['path']}")
            content = content[:start] + replacement + content[end:]
            previous_start = start
        rendered[str(entry["path"])] = content
    return rendered
