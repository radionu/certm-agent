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
            if isinstance(data, str): data = data.encode()
            fh.write(data); fh.flush(); os.fsync(fh.fileno())
        os.chmod(tmp, mode); os.replace(tmp, path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass


def load_config(path):
    global CONFIG, CONFIG_FILE
    CONFIG_FILE = Path(path)
    if not CONFIG_FILE.exists(): raise RuntimeError(f"Configuration file not found: {CONFIG_FILE}")
    CONFIG = json.loads(CONFIG_FILE.read_text())
    if int(CONFIG.get("config_version", 0)) != 2: raise RuntimeError("Agent 0.4.0 requires config_version=2")
    if not str(CONFIG.get("api_base", "")).rstrip("/").endswith("/api/v2"): raise RuntimeError("api_base must end with /api/v2")
    bindings = CONFIG.get("management", {}).get("bindings", [])
    if not isinstance(bindings, list) or not bindings: raise RuntimeError("management.bindings must contain at least one binding")
    seen = set()
    for item in bindings:
        domain = str(item.get("domain", "")).strip().lower().rstrip("."); port = int(item.get("port", 443)); cert_dir = str(item.get("certificate_dir", "")).strip()
        if not domain or not cert_dir or not (1 <= port <= 65535): raise RuntimeError(f"Invalid managed binding: {item}")
        key = (domain, port)
        if key in seen: raise RuntimeError(f"Duplicate managed binding: {domain}:{port}")
        seen.add(key)
    return CONFIG


def setup_logging():
    log_file = Path(CONFIG.get("paths", {}).get("log_file", "/var/log/certm/certm-agent.log")); log_file.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.setLevel(logging.INFO); LOGGER.handlers.clear(); handler = logging.FileHandler(log_file)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S"); formatter.converter = time.gmtime; handler.setFormatter(formatter); LOGGER.addHandler(handler)


def run(cmd, input_data=None, check=True, timeout=30):
    result = subprocess.run(cmd, input=input_data, text=isinstance(input_data, str) or input_data is None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode != 0: raise RuntimeError(f"Command failed ({' '.join(cmd)}): {result.stderr.strip()}")
    return result


def normalize_fp(value):
    if not value: return ""
    value = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower(); return value if re.fullmatch(r"[0-9a-f]{64}", value) else ""


def load_identity():
    token = str(CONFIG.get("client_token", "")).strip(); machine_path = Path(CONFIG.get("machine_id_file", "/etc/machine-id"))
    if not token: raise RuntimeError(f"client_token is missing in {CONFIG_FILE}")
    if not machine_path.exists(): raise RuntimeError(f"Machine ID file not found: {machine_path}")
    machine_id = machine_path.read_text().strip()
    if not machine_id: raise RuntimeError("Machine ID is empty")
    return token, machine_id


def save_client_token(token):
    token = str(token or "").strip()
    if not token: raise RuntimeError("CertM returned an empty client token")
    CONFIG["client_token"] = token; atomic_write(CONFIG_FILE, json.dumps(CONFIG, indent=2) + "\n", 0o600); log(f"Client token saved to {CONFIG_FILE}")


def api_request(method, path, token, machine_id, payload=None, query=None):
    url = str(CONFIG["api_base"]).rstrip("/") + path
    if query: url += "?" + urllib.parse.urlencode(query)
    data = None; headers = {"Accept":"application/json","Authorization":f"Bearer {token}","X-CertM-Machine-ID":machine_id,"User-Agent":f"CertM-Agent/{AGENT_VERSION}"}
    if payload is not None: data = json.dumps(payload).encode(); headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method); timeout = int(CONFIG.get("network", {}).get("api_timeout_seconds", 30))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode(); return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try: detail = json.loads(body)
        except Exception: detail = body
        raise RuntimeError(f"CertM API HTTP {exc.code}: {detail}")


def read_os_release():
    values = {}; path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" not in line or line.startswith("#"): continue
            k,v=line.split("=",1); values[k.lower()] = v.strip().strip('"')
    return values


def local_preflight():
    if os.geteuid()!=0: raise RuntimeError("CertM agent must run as root")
    if sys.version_info < (3,8): raise RuntimeError("Python 3.8 or newer is required")
    for command in ("openssl","nginx","systemctl"):
        if shutil.which(command) is None: raise RuntimeError(f"Required command not found: {command}")
    nginx=run(["nginx","-v"],check=False)
    if nginx.returncode!=0: raise RuntimeError("nginx -v failed")
    token,machine_id=load_identity(); osrel=read_os_release(); log(f"CertM Agent version={AGENT_VERSION}"); log(f"Platform={osrel.get('pretty_name',osrel.get('name','Linux'))}"); log(f"Web service={nginx.stderr.strip() or nginx.stdout.strip()}"); log(f"Managed bindings={len(CONFIG['management']['bindings'])}"); log("Local preflight successful"); return token,machine_id,osrel


def enrollment_payload(osrel):
    return {"machine_id":Path(CONFIG.get("machine_id_file","/etc/machine-id")).read_text().strip(),"hostname":socket.gethostname(),"agent_type":"nginx","agent_version":AGENT_VERSION,"os_name":osrel.get("id") or osrel.get("name") or "linux","os_version":osrel.get("version_id") or ""}


def preflight():
    token,machine_id,osrel=local_preflight(); identity=api_request("GET","/client/preflight",token,machine_id); status=str(identity.get("status","")).lower()
    if status=="enrollment_available":
        answer=input("This server is not enrolled with CertM. Enroll now? [y/N]: ").strip().lower()
        if answer not in ("y","yes"): log("Enrollment skipped"); return
        response=api_request("POST","/client/enroll",token,machine_id,enrollment_payload(osrel))
        if str(response.get("status","")).lower()!="pending_approval": raise RuntimeError(f"Unexpected enrollment response: {response}")
        save_client_token(response.get("client_token")); log(f"Enrollment successful. Client ID={response.get('client_id')} status=PENDING_APPROVAL"); return
    if status=="pending_approval": log(f"Client ID={identity.get('client_id')} is PENDING_APPROVAL"); return
    if status=="active": log(f"Client identity valid. Client ID={identity.get('client_id')} status=ACTIVE"); return
    raise RuntimeError(f"CertM denied client identity: {status or identity}")


def binding_paths(binding):
    d=Path(binding["certificate_dir"]); return {"dir":d,"certificate":d/str(binding.get("certificate_file","certificate.pem")),"fullchain":d/str(binding.get("fullchain_file","fullchain.pem")),"key":d/str(binding.get("private_key_file","privkey.pem"))}

def binding_key(binding): return f"{re.sub(r'[^a-zA-Z0-9_.-]+','_',binding['domain'])}-{int(binding.get('port',443))}"
def state_path(binding): return Path(CONFIG.get("paths",{}).get("state_root","/var/lib/certm/bindings"))/f"{binding_key(binding)}.json"
def load_state(binding):
    p=state_path(binding)
    if not p.exists(): return {}
    try: return json.loads(p.read_text())
    except Exception: return {}

def save_state(binding,desired,fingerprint):
    payload={"domain":binding["domain"],"port":int(binding.get("port",443)),"certificate_id":desired["certificate_id"],"certificate_version_id":desired["certificate_version_id"],"version_id":desired["version_id"],"package_revision":int(desired["package_revision"]),"deployment_revision":desired["deployment_revision"],"fingerprint_sha256":fingerprint,"certificate_dir":str(binding["certificate_dir"]),"verified_at":datetime.now(timezone.utc).isoformat()}; atomic_write(state_path(binding),json.dumps(payload,indent=2)+"\n",0o600)

def fingerprint_file(path):
    if not Path(path).exists(): return ""
    r=run(["openssl","x509","-in",str(path),"-noout","-fingerprint","-sha256"]); return normalize_fp(r.stdout.split("=",1)[-1])

def openssl_date_iso(value): return datetime.strptime(value.strip(),"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
def inspect_certificate(path):
    if not Path(path).exists(): return {}
    r=run(["openssl","x509","-in",str(path),"-noout","-subject","-issuer","-serial","-dates"]); info={"fingerprint_sha256":fingerprint_file(path)}
    for line in r.stdout.splitlines():
        if line.startswith("subject="): info["subject"]=line.split("=",1)[1].strip()
        elif line.startswith("issuer="): info["issuer"]=line.split("=",1)[1].strip()
        elif line.startswith("serial="): info["serial_number"]=line.split("=",1)[1].strip()
        elif line.startswith("notBefore="): info["not_before"]=openssl_date_iso(line.split("=",1)[1])
        elif line.startswith("notAfter="): info["not_after"]=openssl_date_iso(line.split("=",1)[1])
    return info

def served_fingerprint(domain,port):
    host=str(CONFIG.get("verify",{}).get("connect_host","127.0.0.1")); timeout=int(CONFIG.get("network",{}).get("api_timeout_seconds",30)); ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    with socket.create_connection((host,int(port)),timeout=timeout) as sock:
        with ctx.wrap_socket(sock,server_hostname=domain) as tls: return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
def verify_served(binding,expected):
    timeout=int(CONFIG.get("verify",{}).get("retry_timeout_seconds",30)); interval=float(CONFIG.get("verify",{}).get("retry_interval_seconds",1)); deadline=time.monotonic()+timeout; last=""
    while True:
        try:
            last=normalize_fp(served_fingerprint(binding["domain"],binding.get("port",443)))
            if last==expected: return last
        except Exception as exc: last=f"ERROR:{exc}"
        if time.monotonic()>=deadline: break
        time.sleep(interval)
    raise RuntimeError(f"{binding['domain']}:{binding.get('port',443)} does not serve expected certificate; last={last}")
def validate_cert_key(cert,key):
    a=run(["openssl","x509","-in",str(cert),"-pubkey","-noout"]).stdout; b=run(["openssl","pkey","-in",str(key),"-pubout"]).stdout
    if hashlib.sha256(a.encode()).digest()!=hashlib.sha256(b.encode()).digest(): raise RuntimeError("Certificate and private key do not match")
def validate_hostname(cert,domain):
    r=run(["openssl","x509","-in",str(cert),"-noout","-checkhost",domain],check=False)
    if r.returncode!=0: raise RuntimeError(f"Downloaded certificate does not cover {domain}")
def decode_package(response,domain):
    if response.get("status")!="ok": raise RuntimeError(f"Unexpected download response: {response}")
    deployment_id=int(response.get("deployment_id",0)); meta=response.get("certificate",{}); files=response.get("files",{}); expected=normalize_fp(meta.get("fingerprint_sha256"))
    if deployment_id<1 or len(expected)!=64: raise RuntimeError("Invalid deployment metadata")
    try: cert=base64.b64decode(files["certificate.pem"],validate=True); key=base64.b64decode(files["privkey.pem"],validate=True); fullchain=base64.b64decode(files.get("fullchain.pem"),validate=True) if files.get("fullchain.pem") else cert
    except Exception as exc: raise RuntimeError(f"Invalid certificate package encoding: {exc}")
    with tempfile.TemporaryDirectory(prefix="certm-package-") as tmp:
        cp=Path(tmp)/"certificate.pem"; kp=Path(tmp)/"privkey.pem"; cp.write_bytes(cert); kp.write_bytes(key); validate_cert_key(cp,kp); validate_hostname(cp,domain); actual=fingerprint_file(cp)
        if actual!=expected: raise RuntimeError("Downloaded certificate fingerprint does not match metadata")
    return {"deployment_id":deployment_id,"certificate":cert,"fullchain":fullchain,"key":key,"expected":expected,"meta":meta}

def create_backup(binding,paths):
    root=Path(CONFIG.get("paths",{}).get("backup_root","/opt/certm-agent/bkup")); stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"); target=root/binding_key(binding)/stamp; target.mkdir(parents=True,exist_ok=False); manifest={}
    for name,path in (("certificate",paths["certificate"]),("fullchain",paths["fullchain"]),("key",paths["key"])):
        if path.exists(): dst=target/path.name; shutil.copy2(path,dst); manifest[name]=str(dst)
        else: manifest[name]=None
    atomic_write(target/"manifest.json",json.dumps(manifest,indent=2)+"\n",0o600); return target

def restore_backup(backup,paths):
    manifest=json.loads((Path(backup)/"manifest.json").read_text())
    for name,path in (("certificate",paths["certificate"]),("fullchain",paths["fullchain"]),("key",paths["key"])):
        src=manifest.get(name)
        if src: atomic_write(path,Path(src).read_bytes(),0o600)
        else:
            try: path.unlink()
            except FileNotFoundError: pass

def install_package(paths,pkg):
    paths["dir"].mkdir(parents=True,exist_ok=True); atomic_write(paths["certificate"],pkg["certificate"],0o600); atomic_write(paths["fullchain"],pkg["fullchain"],0o600); atomic_write(paths["key"],pkg["key"],0o600); validate_cert_key(paths["certificate"],paths["key"])
def nginx_dump():
    r=run(["nginx","-T"]); return r.stdout+"\n"+r.stderr
def verify_nginx_paths(binding,paths):
    dump=nginx_dump(); domain=re.escape(binding["domain"])
    if not re.search(r"\bserver_name\b[^;]*\b"+domain+r"\b[^;]*;",dump): raise RuntimeError(f"nginx server_name not found for {binding['domain']}")
    if not any(f"ssl_certificate {p};" in dump for p in {str(paths['certificate']),str(paths['fullchain'])}): raise RuntimeError(f"nginx does not reference CertM certificate path for {binding['domain']}")
    if f"ssl_certificate_key {paths['key']};" not in dump: raise RuntimeError(f"nginx does not reference CertM private key path for {binding['domain']}")
def nginx_test_reload(): run(["nginx","-t"]); run(["systemctl","reload",str(CONFIG.get("service",{}).get("systemd_unit","nginx"))])
def desired_for(binding,token,machine_id):
    response=api_request("GET","/cert/desired",token,machine_id,query={"domain":binding["domain"]})
    if response.get("status")!="ok": raise RuntimeError(f"No desired certificate for {binding['domain']}: {response}")
    return response
def report_deployment(token,machine_id,deployment_id,status,installed=None,served=None,message=""):
    payload={"deployment_id":deployment_id,"status":status,"message":message}
    if installed: payload["installed_fingerprint"]=installed
    if served: payload["served_fingerprint"]=served
    return api_request("POST","/deployment/report",token,machine_id,payload)
def inventory_item(binding):
    paths=binding_paths(binding); info=inspect_certificate(paths["certificate"]); served=""
    try: served=normalize_fp(served_fingerprint(binding["domain"],binding.get("port",443)))
    except Exception: pass
    return {"site_name":binding.get("site_name") or binding["domain"],"domain":binding["domain"],"port":int(binding.get("port",443)),"protocol":"https","subject":info.get("subject"),"issuer":info.get("issuer"),"serial_number":info.get("serial_number"),"fingerprint_sha256":info.get("fingerprint_sha256") or None,"served_fingerprint_sha256":served or None,"not_before":info.get("not_before"),"not_after":info.get("not_after"),"cert_path":str(paths["certificate"]),"key_path":str(paths["key"]),"binding_id":binding_key(binding)}
def push_inventory(token,machine_id):
    items=[inventory_item(b) for b in CONFIG["management"]["bindings"]]; response=api_request("POST","/client/inventory",token,machine_id,{"service":"nginx","items":items}); log(f"Inventory submitted: {response.get('summary',{})}"); return response

def deploy_binding(binding,token,machine_id):
    paths=binding_paths(binding); desired=desired_for(binding,token,machine_id); expected=normalize_fp(desired.get("fingerprint_sha256")); revision=str(desired.get("deployment_revision","")); state=load_state(binding); local_fp=fingerprint_file(paths["certificate"]); log(f"Binding {binding['domain']}:{binding.get('port',443)} desired={revision} local={state.get('deployment_revision','-')}")
    if state.get("deployment_revision")==revision and local_fp==expected:
        verify_nginx_paths(binding,paths); verify_served(binding,expected); log(f"Binding already current and verified: {revision}"); return False
    response=api_request("GET","/cert/download",token,machine_id,query={"domain":binding["domain"],"service":"nginx","port":int(binding.get("port",443))}); package=decode_package(response,binding["domain"]); deployment_id=package["deployment_id"]
    if package["expected"]!=expected: report_deployment(token,machine_id,deployment_id,"FAILED",message="Desired certificate changed during download"); raise RuntimeError("Desired certificate changed during download")
    backup=create_backup(binding,paths)
    try:
        install_package(paths,package); verify_nginx_paths(binding,paths); nginx_test_reload(); installed=fingerprint_file(paths["certificate"])
        if installed!=expected: raise RuntimeError("Installed fingerprint does not match desired certificate")
        served=verify_served(binding,expected); report=report_deployment(token,machine_id,deployment_id,"SUCCESS",installed=installed,served=served,message="Certificate installed, nginx reloaded and TLS endpoint verified")
        if report.get("status")!="ok": raise RuntimeError(f"CertM rejected SUCCESS report: {report}")
        save_state(binding,desired,expected); log(f"CERTIFICATE UPDATE SUCCESSFUL: {binding['domain']} {revision}"); return True
    except Exception as exc:
        failure=str(exc)
        try: restore_backup(backup,paths); run(["nginx","-t"]); run(["systemctl","reload",str(CONFIG.get("service",{}).get("systemd_unit","nginx"))]); rollback_text="Rollback completed successfully"
        except Exception as rollback_exc: rollback_text=f"Rollback failed: {rollback_exc}"
        try: report_deployment(token,machine_id,deployment_id,"FAILED",message=f"{failure}. {rollback_text}")
        except Exception as report_exc: log(f"WARNING unable to report FAILED deployment: {report_exc}")
        raise RuntimeError(f"Deployment failed for {binding['domain']}: {failure}. {rollback_text}")

def renew():
    token,machine_id,_=local_preflight(); status=api_request("GET","/client/status",token,machine_id)
    if status.get("status")!="active": raise RuntimeError(f"Client is not ACTIVE: {status.get('status')}")
    push_inventory(token,machine_id); changed=0; errors=[]
    for binding in CONFIG["management"]["bindings"]:
        try:
            if deploy_binding(binding,token,machine_id): changed+=1
        except Exception as exc: errors.append(str(exc)); log(f"ERROR {exc}")
    try: push_inventory(token,machine_id)
    except Exception as exc: log(f"WARNING post-renew inventory failed: {exc}")
    if errors: raise RuntimeError("; ".join(errors))
    log(f"Renew completed successfully; changed_bindings={changed}")

def parse_args():
    p=argparse.ArgumentParser(description="CertM native v2 nginx agent"); p.add_argument("--config",default=str(DEFAULT_CONFIG_FILE)); p.add_argument("command",choices=["preflight","renew"]); return p.parse_args()
def main():
    args=parse_args(); load_config(args.config); setup_logging(); lock_path=Path(CONFIG.get("paths",{}).get("lock_file","/run/certm-agent.lock")); lock_path.parent.mkdir(parents=True,exist_ok=True)
    with open(lock_path,"w") as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError("Another CertM agent process is already running")
        log(f"Starting certm-agent command={args.command}")
        if args.command=="preflight": preflight()
        else: renew()

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print("Interrupted",file=sys.stderr); sys.exit(130)
    except Exception as exc: LOGGER.exception("CertM agent failed"); print(f"ERROR {exc}",file=sys.stderr); sys.exit(1)
