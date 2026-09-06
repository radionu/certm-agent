#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/../linux" && pwd)"
exec "${BASE_DIR}/install.sh" --web-server nginx "$@"
