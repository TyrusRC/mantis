#!/usr/bin/env bash
# Install mantis (MCP mode) into a target project's .claude/ directory.
# Ships inside the wheel; pipx users find it via `mantis doctor` ("resources at <dir>").
# Usage: bash <resources>/install.sh [target_dir]   (default: current directory)
set -euo pipefail

TARGET="${1:-$PWD}"
RES="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "$TARGET" ]]; then
  echo "target not found: $TARGET" >&2
  exit 1
fi
if [[ ! -d "$RES/agents" ]]; then
  echo "resources not found at $RES; expected agents/ next to install.sh" >&2
  exit 1
fi

mkdir -p "$TARGET/.claude/agents" "$TARGET/.claude/commands"

echo "installing agents -> $TARGET/.claude/agents/"
cp -v "$RES/agents/"*.md "$TARGET/.claude/agents/"

echo "installing commands -> $TARGET/.claude/commands/"
cp -v "$RES/commands/"*.md "$TARGET/.claude/commands/"

# Build the manifest before linking/copying so a copy-fallback install gets it.
if command -v python3 >/dev/null 2>&1; then
  echo "building rule manifest..."
  python3 "$RES/scripts/build_manifest.py" || echo "  (manifest build failed, continuing)"
fi

# Link directories so updates flow through. Falls back to copy on filesystems
# that don't support symlinks (Windows / WSL crossings / sandboxed runners).
# A pre-existing dir may come from the audited repo itself; never pre-approve
# running scripts we did not put there.
FOREIGN=0
link_or_copy() {
  local src="$1" dst="$2" label="$3"
  if [[ -L "$dst" && "$(readlink "$dst")" == "$src" ]] \
     || [[ ! -L "$dst" && "$(cat "$dst/.mantis-installed" 2>/dev/null)" == "$src" ]]; then
    return 0
  fi
  if [[ -e "$dst" ]]; then
    echo "WARNING: $dst already exists and is not linked to $src; left untouched." >&2
    echo "         Remove it and re-run to install, or review its contents first." >&2
    FOREIGN=1
    return 0
  fi
  if ln -s "$src" "$dst" 2>/dev/null; then
    echo "linked ${label} -> $dst"
  else
    cp -r "$src" "$dst"
    printf '%s' "$src" > "$dst/.mantis-installed"
    echo "copied ${label} -> $dst  (symlink unavailable on this filesystem)"
  fi
}

link_or_copy "$RES/rules"      "$TARGET/.claude/sast-rules"      "rules"
link_or_copy "$RES/checklists" "$TARGET/.claude/sast-checklists" "checklists"
link_or_copy "$RES/scripts"    "$TARGET/.claude/sast-scripts"    "scripts"

# Pre-approve only the exact commands the pipeline runs, so unattended /audit
# runs don't stall on prompts. Additive merge into the per-user, untracked
# settings.local.json; existing entries are never removed or reordered.
SETTINGS="$TARGET/.claude/settings.local.json"
if [[ "$FOREIGN" == 1 ]]; then
  echo "permissions NOT granted: an existing .claude/sast-* dir was not installed by mantis" >&2
elif command -v python3 >/dev/null 2>&1; then
  python3 - "$RES/permissions.json" "$SETTINGS" <<'PY' || echo "  (permission merge skipped; see message above)"
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
want = json.load(open(src))["permissions"]["allow"]
cur = {}
if os.path.exists(dst):
    try:
        cur = json.load(open(dst))
    except json.JSONDecodeError as e:
        sys.exit(f"  {dst} is not valid JSON ({e}); not touching it")
allow = cur.setdefault("permissions", {}).setdefault("allow", [])
added = [r for r in want if r not in allow]
allow.extend(added)
tmp = dst + ".tmp"
with open(tmp, "w") as f:
    json.dump(cur, f, indent=2)
    f.write("\n")
os.replace(tmp, dst)
print(f"permissions -> {dst}: +{len(added)} rule(s)")
for r in added:
    print(f"  allow {r}")
PY
fi

cat <<EOF

mantis installed (MCP mode). local only.

one command:
  /audit                       -- auto-detect stack, hybrid pipeline, write ./security-audit-report.md
  /audit quick                 -- fast static + triage, low FP
  /audit deep                  -- every rule, full pipeline
  /audit bugbounty             -- exploit-first, gates on reachability
  /audit cve                   -- SCA / lockfile only
  /audit mobile|mobile-ios|mobile-android|web|desktop|llm|taint|secrets|iac|cloud
                               -- pack-scoped
  /audit deep focus:auth       -- narrow deep review to a domain
  /audit --fix                 -- apply patches in a local worktree, re-verify
  /audit --lite                -- skip slicing + deep review, token-conservative
  /audit bugbounty --experimental-toast  -- extra ToAST hunt on confirmed slices

SAST engine: opengrep. install it:
  pipx install opengrep        (ships cross-function intrafile taint)

for standalone CLI mode (any LLM provider: anthropic, google, openai, ollama):
  pipx install mantis-sast
  mantis audit /path/to/target
EOF
