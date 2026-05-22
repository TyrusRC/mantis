#!/usr/bin/env bash
# Thin bootstrap: defers to `mantis doctor` once mantis is on PATH.
# Falls back to a minimal in-shell probe if mantis isn't installed yet.
set -uo pipefail

if command -v mantis >/dev/null 2>&1; then
  exec mantis doctor "${@:-.}"
fi

echo "mantis is not on PATH yet — running minimal pre-install probe."
echo

FAIL=0
pass() { printf "  PASS  %s\n" "$*"; }
warn() { printf "  WARN  %s\n" "$*"; }
fail() { printf "  FAIL  %s\n" "$*"; FAIL=1; }

if command -v python3 >/dev/null 2>&1; then
  PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')
  [[ "$PY_OK" == "1" ]] && pass "python $PY_VER" || fail "python $PY_VER (need 3.10+)"
else
  fail "python3 not on PATH"
fi

command -v pipx >/dev/null 2>&1 && pass "pipx $(pipx --version)" || fail "pipx not on PATH"
command -v opengrep >/dev/null 2>&1 && pass "opengrep $(opengrep --version 2>&1 | head -1)" \
  || (command -v semgrep >/dev/null 2>&1 && warn "semgrep present; opengrep recommended (./setup.sh)" \
      || fail "no SAST binary; run ./setup.sh")

echo
if [[ "$FAIL" == "0" ]]; then
  echo "Pre-install checks passed. Run ./setup.sh next, then re-run ./doctor.sh."
  exit 0
else
  echo "Pre-install checks failed — fix the above before running ./setup.sh."
  exit 1
fi
