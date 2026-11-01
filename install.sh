#!/usr/bin/env bash
# Install mantis (MCP mode) into a target project's .claude/ directory.
# The real installer ships in the wheel at mantis/resources/install.sh; this
# wrapper keeps `./install.sh [target_dir]` working from a source checkout.
# For standalone CLI installation, use: pipx install mantis-sast
set -euo pipefail
exec bash "$(cd "$(dirname "$0")" && pwd)/mantis/resources/install.sh" "$@"
