# CertM Agent

Public deployment agents for CertM.

Current implementation:

- `rhel-nginx/` — native CertM API v2 agent for RHEL-family Linux + nginx.

The agent repository intentionally contains no enrollment keys, client tokens, private keys, production configuration, or server-side CertM source.

## RHEL/nginx quick start

```bash
git clone https://github.com/radionu/certm-agent.git
cd certm-agent/rhel-nginx
sudo ./install.sh
```

See `rhel-nginx/README.md` before enabling the systemd timer.
