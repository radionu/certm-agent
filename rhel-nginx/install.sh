#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/../linux" && pwd)"
echo "NOTICE: rhel-nginx/install.sh is deprecated; use linux/install.sh --web-server nginx for future upgrades." >&2
exec "${BASE_DIR}/install.sh" --web-server nginx "$@"
