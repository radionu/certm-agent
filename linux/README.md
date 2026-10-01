# CertM Linux Agent

The Linux agent supports nginx and Apache on Ubuntu, Debian, RHEL, AlmaLinux and
Rocky Linux. The same agent also supports a single-server Zimbra 9 installation.

Use the main operator guide for installation and troubleshooting:

- [English guide](../README.md#linux-agent-nginx-apache-and-zimbra)
- [Hướng dẫn tiếng Việt](../README_vi.MD)

Common commands:

```bash
sudo /opt/certm-agent/certm-agent.py inventory
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew
sudo systemctl status certm-agent.timer --no-pager
sudo tail -n 100 /var/log/certm/certm-agent.log
```

Zimbra verification without deployment or restart:

```bash
sudo /opt/certm-agent/certm-agent.py verify
```

Version history is maintained in [CHANGELOG.md](../CHANGELOG.md). Design and
release details are maintained in
[docs/TECHNICAL_NOTES.md](../docs/TECHNICAL_NOTES.md).
