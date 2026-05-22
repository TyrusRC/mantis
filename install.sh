#!/usr/bin/env bash
# Install mantis (MCP mode) into a target project's .claude/ directory.
# For standalone CLI installation, use: pipx install mantis-sast
# Usage: ./install.sh [target_dir]   (default: current directory)
set -euo pipefail

TARGET="${1:-$PWD}"
SRC="$(cd "$(dirname "$0")" && pwd)"
RES="$SRC/mantis/resources"

if [[ ! -d "$TARGET" ]]; then
  echo "target not found: $TARGET" >&2
  exit 1
fi
if [[ ! -d "$RES/agents" ]]; then
  echo "resources not found at $RES; expected mantis/resources/agents/" >&2
  exit 1
fi

mkdir -p "$TARGET/.claude/agents" "$TARGET/.claude/commands"

echo "installing agents -> $TARGET/.claude/agents/"
cp -v "$RES/agents/"*.md "$TARGET/.claude/agents/"

echo "installing commands -> $TARGET/.claude/commands/"
cp -v "$RES/commands/"*.md "$TARGET/.claude/commands/"

# Link directories so updates flow through. Falls back to copy on filesystems
# that don't support symlinks (Windows / WSL crossings / sandboxed runners).
link_or_copy() {
  local src="$1" dst="$2" label="$3"
  if [[ -e "$dst" ]]; then
    return 0
  fi
  if ln -s "$src" "$dst" 2>/dev/null; then
    echo "linked ${label} -> $dst"
  else
    cp -r "$src" "$dst"
    echo "copied ${label} -> $dst  (symlink unavailable on this filesystem)"
  fi
}

link_or_copy "$RES/rules"      "$TARGET/.claude/sast-rules"      "rules"
link_or_copy "$RES/checklists" "$TARGET/.claude/sast-checklists" "checklists"
link_or_copy "$RES/scripts"    "$TARGET/.claude/sast-scripts"    "scripts"

# Build / refresh the rule manifest
if command -v python3 >/dev/null 2>&1; then
  echo "building rule manifest..."
  python3 "$RES/scripts/build_manifest.py" || echo "  (manifest build failed, continuing)"
fi

cat <<EOF

mantis installed (MCP mode). local only.

one command:
  /audit                 -- auto-detect stack, hybrid pipeline, write ./security-audit-report.md
  /audit quick           -- fast static + triage, low FP
  /audit deep            -- every rule, full pipeline
  /audit bugbounty       -- exploit-first, gates on reachability
  /audit cve             -- SCA / lockfile only
  /audit mobile|web|llm  -- pack-scoped
  /audit deep focus:auth -- narrow deep review to a domain
  /audit --fix           -- apply patches in a local worktree, re-verify
  /audit --lite          -- skip slicing + deep review, token-conservative

SAST binary: opengrep is preferred; semgrep also works. install one:
  pipx install opengrep        (recommended; ships cross-function intrafile taint)
  pipx install semgrep         (fallback; both consume the same rule YAML)

for standalone CLI mode (any LLM provider — anthropic, google, openai, ollama):
  pipx install mantis-sast
  mantis audit /path/to/target
EOF
