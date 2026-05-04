#!/usr/bin/env bash
# Install the audit toolkit into a target project's .claude/ directory.
# Usage: ./install.sh [target_dir]   (default: current directory)
set -euo pipefail

TARGET="${1:-$PWD}"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "$TARGET" ]]; then
  echo "target not found: $TARGET" >&2
  exit 1
fi

mkdir -p "$TARGET/.claude/agents" "$TARGET/.claude/commands"

echo "installing agents -> $TARGET/.claude/agents/"
cp -v "$SRC/agents/"*.md "$TARGET/.claude/agents/"

echo "installing commands -> $TARGET/.claude/commands/"
cp -v "$SRC/commands/"*.md "$TARGET/.claude/commands/"

# Link rule packs so updates flow through
if [[ ! -e "$TARGET/.claude/sast-rules" ]]; then
  ln -s "$SRC/rules" "$TARGET/.claude/sast-rules"
  echo "linked rules -> $TARGET/.claude/sast-rules"
fi

# Link checklists (deep-reviewer consults these for findings Semgrep can't pattern-match)
if [[ ! -e "$TARGET/.claude/sast-checklists" ]]; then
  ln -s "$SRC/checklists" "$TARGET/.claude/sast-checklists"
  echo "linked checklists -> $TARGET/.claude/sast-checklists"
fi

# Build / refresh the rule manifest
if command -v python3 >/dev/null 2>&1; then
  echo "building rule manifest..."
  python3 "$SRC/scripts/build_manifest.py" || echo "  (manifest build failed, continuing)"
fi

cat <<EOF

installed.

one command, local only:
  /audit                 -- auto-detect stack, hybrid pipeline, write ./security-audit-report.md
  /audit quick           -- fast static + triage, low FP
  /audit deep            -- every rule, full pipeline
  /audit bugbounty       -- exploit-first, gates on reachability
  /audit cve             -- SCA / lockfile only
  /audit mobile|web|llm  -- pack-scoped
  /audit deep focus:auth -- narrow deep review to a domain
  /audit --fix           -- apply patches in a local worktree, re-verify
  /audit --lite          -- skip slicing + deep review, token-conservative

semgrep is the only external dependency. install: pipx install semgrep
optional MCP wiring: claude mcp add semgrep -- semgrep mcp
EOF
