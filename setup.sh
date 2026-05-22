#!/usr/bin/env bash
# Install everything mantis needs: OpenGrep binary, the mantis Python package,
# and a discoverable share/ location so the installed CLI can find rules/agents.
#
# Idempotent — safe to re-run. Pass --reinstall to force.
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
OPENGREP_VERSION="${OPENGREP_VERSION:-v1.22.0}"
FORCE=0
SKIP_OPENGREP=0
SKIP_MANTIS=0

for arg in "$@"; do
  case "$arg" in
    --reinstall|--force) FORCE=1 ;;
    --no-opengrep) SKIP_OPENGREP=1 ;;
    --no-mantis)   SKIP_MANTIS=1 ;;
    -h|--help)
      cat <<EOF
usage: ./setup.sh [--reinstall] [--no-opengrep] [--no-mantis]

Installs:
  - OpenGrep \$OPENGREP_VERSION binary into ~/.local/bin
  - mantis (this repo) via pipx (creates an isolated venv with deps)

The pipx-installed CLI finds agents/rules/checklists inside its own venv
(packaged under mantis/resources/); a host-level symlink is no longer
required. For dev installs where you edit the source tree, the CLI will
also pick up mantis/resources/ under the repo automatically.

Run ./doctor.sh afterward to verify.
EOF
      exit 0
      ;;
  esac
done

say()  { printf "\033[1;36m[setup]\033[0m %s\n" "$*"; }
ok()   { printf "\033[1;32m  OK\033[0m   %s\n" "$*"; }
warn() { printf "\033[1;33m  WARN\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m  ERR\033[0m  %s\n" "$*" >&2; }

# ---------- prereqs ----------
say "checking prerequisites"

PY="$(command -v python3 || true)"
if [[ -z "$PY" ]]; then
  err "python3 not on PATH; install Python 3.10+"
  exit 1
fi
PY_VER="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_OK="$("$PY" -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')"
if [[ "$PY_OK" != "1" ]]; then
  err "python $PY_VER too old; need 3.10+"
  exit 1
fi
ok "python $PY_VER"

if ! command -v pipx >/dev/null 2>&1; then
  warn "pipx not installed — installing via pip"
  "$PY" -m pip install --user pipx
  "$PY" -m pipx ensurepath >/dev/null 2>&1 || true
fi
ok "pipx $(pipx --version)"

mkdir -p "$HOME/.local/bin" "$HOME/.local/share"

# ---------- opengrep ----------
if [[ "$SKIP_OPENGREP" != "1" ]]; then
  say "installing OpenGrep ($OPENGREP_VERSION)"

  case "$(uname -s)" in
    Linux)
      case "$(uname -m)" in
        x86_64|amd64) OG_ASSET="opengrep_manylinux_x86" ;;
        aarch64|arm64) OG_ASSET="opengrep_manylinux_aarch64" ;;
        *) err "unsupported arch: $(uname -m)"; exit 1 ;;
      esac
      ;;
    Darwin)
      case "$(uname -m)" in
        x86_64) OG_ASSET="opengrep_osx_x86" ;;
        arm64) OG_ASSET="opengrep_osx_arm64" ;;
        *) err "unsupported macOS arch"; exit 1 ;;
      esac
      ;;
    *)
      err "unsupported OS: $(uname -s); install OpenGrep manually from https://github.com/opengrep/opengrep/releases"
      exit 1
      ;;
  esac

  OG_PATH="$HOME/.local/bin/opengrep"
  if [[ -x "$OG_PATH" && "$FORCE" != "1" ]] && "$OG_PATH" --version >/dev/null 2>&1; then
    EXISTING="$("$OG_PATH" --version 2>&1 | head -1)"
    ok "opengrep already at $OG_PATH ($EXISTING)"
  else
    URL="https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OG_ASSET}"
    say "  downloading $URL"
    curl -fsSL "$URL" -o "$OG_PATH"
    chmod +x "$OG_PATH"
    ok "opengrep installed -> $OG_PATH ($("$OG_PATH" --version 2>&1 | head -1))"
  fi
else
  warn "skipping OpenGrep (--no-opengrep)"
fi

# ---------- mantis (pipx) ----------
if [[ "$SKIP_MANTIS" != "1" ]]; then
  say "installing mantis (pipx)"

  EXTRA_FLAGS=()
  if [[ "$FORCE" == "1" ]]; then
    EXTRA_FLAGS+=(--force)
  fi

  if pipx list 2>/dev/null | grep -q "package mantis-sast" && [[ "$FORCE" != "1" ]]; then
    ok "mantis already installed via pipx ($(mantis --version 2>&1))"
  else
    pipx install "${EXTRA_FLAGS[@]}" "$REPO"
    ok "mantis installed ($(mantis --version 2>&1))"
  fi

  # Resources ship inside the wheel under mantis/resources/ — no share-dir
  # symlink needed. We keep a back-compat symlink only if one already exists
  # so older installs don't break; point it at the package resources.
  SHARE_LINK="$HOME/.local/share/mantis"
  if [[ -L "$SHARE_LINK" ]]; then
    ln -sfn "$REPO/mantis/resources" "$SHARE_LINK"
    ok "updated legacy share link $SHARE_LINK -> $REPO/mantis/resources"
  fi
else
  warn "skipping mantis (--no-mantis)"
fi

# ---------- final hint ----------
say "done — next steps:"
cat <<EOF

  1. Make sure ~/.local/bin is on your PATH (pipx ensurepath helps).
  2. Run ./doctor.sh to verify everything resolves.
  3. Copy .mantis.example.yaml to <target>/.mantis.yaml and set models.
  4. Export your provider key (e.g. export GEMINI_API_KEY=...).
  5. mantis check <target>      # validates config
     mantis audit <target>      # runs the audit
EOF
