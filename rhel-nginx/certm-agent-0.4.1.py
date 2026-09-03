#!/usr/bin/env python3

import base64
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import urllib.error
from pathlib import Path

CORE_PATH = Path('/opt/certm-agent/certm-agent-core.py')
AGENT_VERSION = '0.4.1'

spec = importlib.util.spec_from_file_location('certm_agent_core', CORE_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError(f'Unable to load CertM core agent from {CORE_PATH}')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
core.AGENT_VERSION = AGENT_VERSION


class ApiError(RuntimeError):
    def __init__(self, code, detail):
        self.code = int(code)
        self.detail = detail
        super().__init__(f'CertM API HTTP {self.code}: {detail}')


def api_request(method, path, token, machine_id, payload=None, query=None):
    url = str(core.CONFIG['api_base']).rstrip('/') + path
    if query:
        url += '?' + core.urllib.parse.urlencode(query)
    data = None
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'X-CertM-Machine-ID': machine_id,
        'User-Agent': f'CertM-Agent/{AGENT_VERSION}',
    }
    if payload is not None:
        data = json.dumps(payload).encode()
        headers['Content-Type'] = 'application/json'
    request = core.urllib.request.Request(url, data=data, headers=headers, method=method)
    timeout = int(core.CONFIG.get('network', {}).get('api_timeout_seconds', 30))
    try:
        with core.urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors='replace')
        try:
            detail = json.loads(body)
        except Exception:
            detail = body
        raise ApiError(exc.code, detail) from exc


def desired_for(binding, token, machine_id):
    try:
        response = api_request(
            'GET', '/cert/desired', token, machine_id,
            query={'domain': binding['domain']},
        )
    except ApiError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        if exc.code == 404 and detail.get('status') == 'not_found':
            return None
        raise
    if response.get('status') != 'ok':
        raise RuntimeError(f"Unexpected desired certificate response for {binding['domain']}: {response}")
    return response


def nginx_directive_referenced(dump, directive, path):
    pattern = rf'(?m)^\s*{re.escape(directive)}\s+{re.escape(str(path))}\s*;'
    return re.search(pattern, dump) is not None


def verify_nginx_paths(binding, paths):
    dump = core.nginx_dump()
    domain = re.escape(binding['domain'])
    if not re.search(r'\bserver_name\b[^;]*\b' + domain + r'\b[^;]*;', dump):
        raise RuntimeError(f"nginx server_name not found for {binding['domain']}")
    if not any(
        nginx_directive_referenced(dump, 'ssl_certificate', path)
        for path in (paths['certificate'], paths['fullchain'])
    ):
        raise RuntimeError(f"nginx does not reference CertM certificate path for {binding['domain']}")
    if not nginx_directive_referenced(dump, 'ssl_certificate_key', paths['key']):
        raise RuntimeError(f"nginx does not reference CertM private key path for {binding['domain']}")


def validate_download_metadata(desired, meta, expected):
    checks = {
        'id': int(desired['certificate_id']),
        'certificate_version_id': int(desired['certificate_version_id']),
        'version_id': str(desired['version_id']),
        'package_revision': int(desired['package_revision']),
        'deployment_revision': str(desired['deployment_revision']),
    }
    for key, wanted in checks.items():
        if key not in meta:
            raise RuntimeError(f'Download metadata missing {key}')
        actual = meta[key]
        if key in ('id', 'certificate_version_id', 'package_revision'):
            actual = int(actual)
        else:
            actual = str(actual)
        if actual != wanted:
            raise RuntimeError(
                f'Download metadata mismatch for {key}: desired={wanted} downloaded={actual}'
            )
    if core.normalize_fp(meta.get('fingerprint_sha256')) != expected:
        raise RuntimeError('Downloaded fingerprint metadata does not match desired certificate')


def decode_package(response, domain, desired):
    if response.get('status') != 'ok':
        raise RuntimeError(f'Unexpected download response: {response}')
    deployment_id = int(response.get('deployment_id', 0))
    meta = response.get('certificate', {})
    files = response.get('files', {})
    expected = core.normalize_fp(desired.get('fingerprint_sha256'))
    if deployment_id < 1 or len(expected) != 64:
        raise RuntimeError('Invalid deployment metadata')
    validate_download_metadata(desired, meta, expected)
    try:
        cert = base64.b64decode(files['certificate.pem'], validate=True)
        key = base64.b64decode(files['privkey.pem'], validate=True)
        fullchain = (
            base64.b64decode(files['fullchain.pem'], validate=True)
            if files.get('fullchain.pem') else cert
        )
    except Exception as exc:
        raise RuntimeError(f'Invalid certificate package encoding: {exc}') from exc
    with tempfile.TemporaryDirectory(prefix='certm-package-') as tmp:
        cp = Path(tmp) / 'certificate.pem'
        kp = Path(tmp) / 'privkey.pem'
        fp = Path(tmp) / 'fullchain.pem'
        cp.write_bytes(cert)
        kp.write_bytes(key)
        fp.write_bytes(fullchain)
        core.validate_cert_key(cp, kp)
        core.validate_hostname(cp, domain)
        leaf = core.fingerprint_file(cp)
        first_fullchain = core.fingerprint_file(fp)
        if leaf != expected:
            raise RuntimeError('Downloaded certificate fingerprint does not match metadata')
        if first_fullchain != leaf:
            raise RuntimeError('fullchain.pem does not start with the downloaded leaf certificate')
    return {
        'deployment_id': deployment_id,
        'certificate': cert,
        'fullchain': fullchain,
        'key': key,
        'expected': expected,
        'meta': meta,
    }


def create_backup(binding, paths):
    root = Path(core.CONFIG.get('paths', {}).get('backup_root', '/opt/certm-agent/bkup'))
    stamp = core.datetime.now(core.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    target = root / core.binding_key(binding) / stamp
    suffix = 0
    while target.exists():
        suffix += 1
        target = root / core.binding_key(binding) / f'{stamp}-{suffix}'
    target.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for name, path in (
        ('certificate', paths['certificate']),
        ('fullchain', paths['fullchain']),
        ('key', paths['key']),
    ):
        if path.exists():
            dst = target / path.name
            core.shutil.copy2(path, dst)
            manifest[name] = str(dst)
        else:
            manifest[name] = None
    core.atomic_write(target / 'manifest.json', json.dumps(manifest, indent=2) + '\n', 0o600)
    return target, manifest


def restore_backup(manifest, paths):
    for name, path in (
        ('certificate', paths['certificate']),
        ('fullchain', paths['fullchain']),
        ('key', paths['key']),
    ):
        source = manifest.get(name)
        if source:
            core.atomic_write(path, Path(source).read_bytes(), 0o600)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def deploy_binding(binding, token, machine_id):
    paths = core.binding_paths(binding)
    desired = desired_for(binding, token, machine_id)
    if desired is None:
        core.log(
            f"Binding {binding['domain']}:{binding.get('port', 443)} has no active certificate assignment; "
            'keeping current certificate'
        )
        return False
    expected = core.normalize_fp(desired.get('fingerprint_sha256'))
    revision = str(desired.get('deployment_revision', ''))
    state = core.load_state(binding)
    local_fp = core.fingerprint_file(paths['certificate'])
    core.log(
        f"Binding {binding['domain']}:{binding.get('port', 443)} "
        f"desired={revision} local={state.get('deployment_revision', '-')}"
    )
    if state.get('deployment_revision') == revision and local_fp == expected:
        verify_nginx_paths(binding, paths)
        core.verify_served(binding, expected)
        core.log(f'Binding already current and verified: {revision}')
        return False
    response = api_request(
        'GET', '/cert/download', token, machine_id,
        query={
            'domain': binding['domain'],
            'service': 'nginx',
            'port': int(binding.get('port', 443)),
        },
    )
    package = decode_package(response, binding['domain'], desired)
    deployment_id = package['deployment_id']
    _, manifest = create_backup(binding, paths)
    had_complete_backup = all(manifest.get(k) for k in ('certificate', 'fullchain', 'key'))
    try:
        core.install_package(paths, package)
        verify_nginx_paths(binding, paths)
        core.nginx_test_reload()
        installed = core.fingerprint_file(paths['certificate'])
        if installed != expected:
            raise RuntimeError('Installed fingerprint does not match desired certificate')
        served = core.verify_served(binding, expected)
        report = core.report_deployment(
            token, machine_id, deployment_id, 'SUCCESS',
            installed=installed, served=served,
            message='Certificate installed, nginx reloaded and TLS endpoint verified',
        )
        if report.get('status') != 'ok':
            raise RuntimeError(f'CertM rejected SUCCESS report: {report}')
        core.save_state(binding, desired, expected)
        core.log(f"CERTIFICATE UPDATE SUCCESSFUL: {binding['domain']} {revision}")
        return True
    except Exception as exc:
        failure = str(exc)
        if had_complete_backup:
            try:
                restore_backup(manifest, paths)
                core.run(['nginx', '-t'])
                core.run(['systemctl', 'reload', str(core.CONFIG.get('service', {}).get('systemd_unit', 'nginx'))])
                rollback_text = 'Rollback completed successfully'
            except Exception as rollback_exc:
                rollback_text = f'Rollback failed: {rollback_exc}'
        else:
            rollback_text = (
                'Bootstrap deployment had no complete previous CertM package; '
                'downloaded files were preserved and nginx was not reloaded again'
            )
        try:
            core.report_deployment(
                token, machine_id, deployment_id, 'FAILED',
                message=f'{failure}. {rollback_text}',
            )
        except Exception as report_exc:
            core.log(f'WARNING unable to report FAILED deployment: {report_exc}')
        raise RuntimeError(
            f"Deployment failed for {binding['domain']}: {failure}. {rollback_text}"
        )


core.api_request = api_request
core.desired_for = desired_for
core.verify_nginx_paths = verify_nginx_paths
core.deploy_binding = deploy_binding


if __name__ == '__main__':
    try:
        core.main()
    except KeyboardInterrupt:
        print('Interrupted', file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        core.LOGGER.exception('CertM agent failed')
        print(f'ERROR {exc}', file=sys.stderr)
        sys.exit(1)
