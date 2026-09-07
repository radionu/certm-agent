# Deprecated compatibility installer

The Linux agent now supports nginx and Apache across Debian-family and
RHEL-family distributions from `linux/`.

This directory remains so existing RC7 source checkouts and upgrade procedures
continue to work:

```bash
cd /opt/certm-agent-src/rhel-nginx
sudo ./install.sh
```

The wrapper invokes `../linux/install.sh --web-server nginx` and preserves
`/etc/certm/agent.json`, client identity, state, backups, logs, and timer state.

For every later upgrade, use the unified path instead:

```bash
cd /opt/certm-agent-src/linux
sudo ./install.sh --web-server nginx
```

Once no managed server or operations script calls the old `rhel-nginx` path,
this compatibility directory may be deleted.
