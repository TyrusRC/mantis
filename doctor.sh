#!/usr/bin/env bash
# Diagnose the mantis install. Read-only — never modifies anything.
# Exit code: 0 if all critical checks pass, 1 otherwise.
set -uo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
FAIL=0

pass() { printf "\033[1;32m PASS\033[0m  %s\n" "$*"; }
warn() { printf "\033[1;33m WARN\033[0m  %s\n" "$*"; }
fail() { printf "\033[1;31m FAIL\033[0m  %s\n" "$*"; FAIL=1; }
info() { printf "\033[1;34m INFO\033[0m  %s\n" "$*"; }
section() { printf "\n\033[1;36m== %s ==\033[0m\n" "$*"; }

# ---------- environment ----------
section "environment"
if command -v python3 >/dev/null 2>&1; then
  PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')"
  if [[ "$PY_OK" == "1" ]]; then pass "python $PY_VER"; else fail "python $PY_VER (need 3.10+)"; fi
else
  fail "python3 not on PATH"
fi

if command -v pipx >/dev/null 2>&1; then
  pass "pipx $(pipx --version)"
else
  fail "pipx not on PATH"
fi

if command -v git >/dev/null 2>&1; then
  pass "git $(git --version | awk '{print $3}')"
else
  warn "git missing — --fix mode requires it"
fi

# ---------- scanner ----------
section "SAST scanner"
SAST=""
if command -v opengrep >/dev/null 2>&1; then
  SAST=opengrep
  pass "opengrep $(opengrep --version 2>&1 | head -1)"
elif command -v semgrep >/dev/null 2>&1; then
  SAST=semgrep
  pass "semgrep $(semgrep --version 2>&1 | head -1)  (opengrep is recommended; ./setup.sh installs it)"
else
  fail "no SAST binary found; run ./setup.sh"
fi

# ---------- mantis CLI ----------
section "mantis CLI"
if command -v mantis >/dev/null 2>&1; then
  pass "mantis $(mantis --version 2>&1)"
else
  fail "mantis not on PATH; run ./setup.sh"
fi

# ---------- resource resolution ----------
section "resource discovery"
EXPECTED=(agents commands rules checklists scripts)

# Discoverable share dir?
SHARE_LINK="$HOME/.local/share/mantis"
RESOLVED=""
if [[ -n "${MANTIS_HOME:-}" && -d "${MANTIS_HOME}/agents" ]]; then
  RESOLVED="$MANTIS_HOME"
  info "MANTIS_HOME=$MANTIS_HOME"
elif [[ -L "$SHARE_LINK" || -d "$SHARE_LINK" ]]; then
  TARGET="$(readlink -f "$SHARE_LINK" 2>/dev/null || echo "$SHARE_LINK")"
  if [[ -d "$TARGET/agents" ]]; then
    RESOLVED="$TARGET"
    info "share link: $SHARE_LINK -> $TARGET"
  else
    fail "$SHARE_LINK exists but is missing agents/"
  fi
fi

if [[ -z "$RESOLVED" && -d "$REPO/agents" ]]; then
  RESOLVED="$REPO"
  info "falling back to source repo: $REPO"
fi

if [[ -n "$RESOLVED" ]]; then
  for dir in "${EXPECTED[@]}"; do
    if [[ -d "$RESOLVED/$dir" ]]; then
      pass "$RESOLVED/$dir/"
    else
      fail "$RESOLVED/$dir/ missing"
    fi
  done
  N_AGENTS=$(ls "$RESOLVED/agents/" 2>/dev/null | grep -c '\.md$' || true)
  if [[ "$N_AGENTS" -ge 1 ]]; then
    pass "$N_AGENTS agent file(s) discovered"
  else
    fail "no agent files discovered"
  fi
  if [[ -f "$RESOLVED/rules/_manifest.yaml" ]]; then
    N_RULES=$(awk '/^summary:/{flag=1} flag && /total_rules:/{print $2; exit}' "$RESOLVED/rules/_manifest.yaml")
    pass "manifest present (${N_RULES:-?} rules indexed)"
  else
    warn "rules/_manifest.yaml missing — run: python3 scripts/build_manifest.py"
  fi
else
  fail "could not locate a resource directory; set MANTIS_HOME or run ./setup.sh"
fi

# ---------- provider keys ----------
section "LLM provider keys (env)"
saw_any=0
for var in ANTHROPIC_API_KEY GEMINI_API_KEY GOOGLE_API_KEY OPENAI_API_KEY OPENROUTER_API_KEY; do
  if [[ -n "${!var:-}" ]]; then
    VAL="${!var}"
    pass "$var set (length ${#VAL})"
    saw_any=1
  fi
done

if [[ "$saw_any" == "0" ]]; then
  if [[ -f "$REPO/.env" ]]; then
    info "no provider keys in shell env; $REPO/.env exists — source it or use a wrapper"
  else
    warn "no provider keys set; standalone audits will fail at triage"
  fi
fi

# ---------- python deps in installed venv ----------
section "mantis venv health"
if command -v mantis >/dev/null 2>&1; then
  TMP_TARGET="$(mktemp -d)"
  trap 'rm -rf "$TMP_TARGET"' EXIT
  # Synthesize a minimal config so check exercises the agents+sast path
  # without requiring real provider creds.
  cat > "$TMP_TARGET/.mantis.yaml" <<EOF
provider: probe
models:
  fast: probe/x
  mid:  probe/y
  deep: probe/z
sast_bin: auto
EOF
  if OUT="$(mantis check "$TMP_TARGET" 2>&1)"; then
    pass "mantis check exercises agents + scanner discovery"
  else
    fail "mantis check failed:"
    printf "        %s\n" "$OUT" | head -6
  fi
fi

# ---------- summary ----------
echo
if [[ "$FAIL" == "0" ]]; then
  printf "\033[1;32mAll critical checks passed.\033[0m\n"
  exit 0
else
  printf "\033[1;31mOne or more critical checks failed — see above.\033[0m\n"
  exit 1
fi
