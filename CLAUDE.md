# CLAUDE.md

Project conventions for future Claude sessions in this repo. Read this before making changes.

## What this repo is

**Mantis** — a hybrid SAST + LLM toolkit for local code-security audits. Distributed on PyPI as `mantis-sast`; the CLI binary is `mantis`. Source-of-truth files for the audit pipeline live under `mantis/resources/` so they ship inside the published wheel.

Two execution modes, one pipeline:

- **MCP mode** (default in Claude Code): `./install.sh` copies agents and the `/audit` slash command into the target project's `.claude/`. The orchestrator subagent dispatches the pipeline using Claude Code's host session. No API key, no model name configuration.
- **Standalone CLI mode**: `mantis audit <path>` runs the same pipeline directly, calling a user-configured LLM provider (Anthropic, Google Gemini, OpenAI, OpenRouter, Ollama). The user supplies the API key and chooses which model maps to each tier. No model names are hardcoded.

Layout:

- `mantis/` — standalone CLI Python package (loads agents, runs pipeline, routes to configured provider)
- `mantis/resources/agents/` — subagent definitions (markdown with `model:` + `tier:` frontmatter; both modes consume them)
- `mantis/resources/commands/` — one slash command (`/audit`), MCP-mode only
- `mantis/resources/rules/` — OpenGrep / Semgrep YAML rules + pack specs + manifest
- `mantis/resources/scripts/` — manifest builder + pack composer
- `mantis/resources/checklists/` — OWASP Testing Guide chapters for the deep-reviewer

The CLI resolves resources via `Path(__file__).parent/'resources'` first (the canonical location for pipx/pip installs and editable source checkouts), then `$MANTIS_HOME`, then a top-level fallback for legacy layouts.

The SAST scanner binary is **OpenGrep** by default with **Semgrep** as a transparent fallback (see "SAST binary" below). Rules are written in the Semgrep YAML schema which OpenGrep consumes unchanged.

## Hard rules

### Local-only

This toolkit is local-only by design. Never add CI integration, GitHub Action workflows, PR-comment plumbing, or remote-upload behavior. Never call `gh pr`, `git push`, or any forge API from agents or scripts. Never post findings anywhere. The only artifact a run produces is a local Markdown file at `./security-audit-report.md` (and, with `--fix`, patches inside a sibling git worktree).

If a future feature request implies CI behavior, push back: this toolkit explicitly skips CI.

### One command

There is one slash command, `/audit`. Modes (`quick`, `deep`, `bugbounty`, `cve`, `mobile`, `web`, `desktop`, `llm`) and flags (`--fix`, `--lite`, `focus:<area>`) are positional/flag arguments to that one command. Do not split modes back into separate commands.

The `web` pack covers Java/Spring, Node.js, Python (Django/Flask/FastAPI), Go, .NET (C#), and PHP. The `desktop` pack covers Electron. Mobile (`mobile`, `mobile-ios`, `mobile-android`) covers native iOS / Android plus cross-platform Flutter and React Native.

The standalone CLI additionally exposes `--skip-llm` for SAST-only diagnostic runs (no provider config needed). This is CLI-only — the MCP slash command always runs the full pipeline.

### No icons / emojis

Do not add emoji or icons to user-facing output, agent definitions, command files, README, or new rule files. Pre-existing rule files (`rules/android/*-improved.yaml`, `rules/cross-platform/*-insecure.yaml`, etc.) contain icons inside their `message:` strings — leave those alone unless explicitly asked to clean them up. Do not propagate that style to new content.

### Token discipline

The whole architecture is built around token economy. Preserve it.

- **Triage** runs on the `fast` tier (Haiku in MCP mode; user-configured cheap model in standalone), reads a +/-40-line window only.
- **Slice extraction** runs on the `mid` tier (Sonnet in MCP mode), hard cap of 4000 tokens of code in the slice output.
- **Deep review** runs on the `deep` tier (Opus in MCP mode), only on slices, only on REACHABLE survivors.
- The orchestrator never reads source files end-to-end. It reads inventory only (manifests, lockfiles, top-level dirs) and dispatches subagents for everything else.

When editing agent prompts: do not relax these caps. If the user reports the audit is missing things, the answer is usually a better slice, not a wider read.

### Tier vs model

Agent frontmatter carries both `model: haiku|sonnet|opus` (consumed by Claude Code's subagent system in MCP mode) and `tier: fast|mid|deep` (consumed by the standalone CLI's provider router). Never hardcode a provider's model name (e.g. `gemini-2.5-flash`, `gpt-4o`, `llama3:70b`) inside agent prompts, scripts, or rules. The standalone CLI's config is the only place model strings appear.

### SAST binary

`OpenGrep` is the default scanner; `Semgrep` is accepted as a fallback. The binary is resolved at runtime: `$AUDIT_SAST_BIN` overrides; otherwise `opengrep` is tried, then `semgrep`. Rules are written in the Semgrep YAML schema; both binaries consume the same rule files. Do not split the rule library by binary.

## File-format conventions

### Semgrep rule YAML

Every rule needs:
- `id`, `severity` (ERROR / WARNING / INFO), `languages`, `message`, `patterns` or a top-level `pattern`.
- `metadata` block with at least `category` (security / privacy / performance), `cwe`, `confidence` (HIGH / MEDIUM / LOW).
- For mobile rules: also `owasp-mobile-2024`, `masvs-v2`, ideally `maswe`.
- For web rules: also `owasp` (e.g. `"A03:2025 Injection"`).
- For LLM rules: also `owasp` with the LLM Top 10 id.
- For CVE-specific rules: `cve` and ideally `cvss_score`.
- `pack: [<list>]` to opt the rule into named packs via the `pack_tag:` filter. Currently dormant — no pack spec uses `pack_tag:`. The `fast`, `bugbounty`, and `cve` packs select rules by `severity` / `confidence` / `has_cve` only. All filters in a pack spec are AND'd together; `pack_compose.py` does not support OR semantics.

### YAML quoting

PyYAML (and Semgrep's own loader on some versions) misparses pattern values that contain an unquoted `: ` (colon-space). Always single-quote pattern scalars whose value contains `: ` outside of a string literal:

```yaml
- pattern: 'URL(string: "http://...")'                # required
- pattern: app.use(cors({ origin: "*" }))             # also required
```

If you add a rule with `setValue(..., forHTTPHeaderField: ...)`-style Swift, `__html: ...`-style JSX, or anything with a colon-space inside a function call, single-quote it. The script that fixed this historically lives at the inline Python in past commits — re-run the same idea if a new file has the same issue.

### paths.include / exclude

Semgrep `paths.include` accepts fnmatch globs (`*`, `**`, `?`, `[...]`) — **not** brace expansion. `"**/main.{js,ts}"` silently matches nothing. Use separate entries:

```yaml
paths:
  include:
    - "**/main.js"
    - "**/main.ts"
```

Scope cross-platform rules with `paths.include` to project-typical paths so a rule named `react-native-*` doesn't fire on a Spring template `.js` file. Always pair with an `exclude` for `node_modules`, `build`, `dist`, `target`, `vendor`.

### Pack specs

`rules/packs/*.yaml` are NOT Semgrep rules. They are filter specs over the manifest. Schema:

```yaml
name: <pack-name>
description: <one paragraph>
filters:                       # AND'd
  severity: [ERROR]
  confidence: [HIGH]
  languages_any: [swift, objc]
  pack_tag: [fast]
  paths_under: [rules/ios/]
  rule_id_globs: []
  has_cve: true
exclude:
  rule_id_globs: []
  paths_under: []
```

`scripts/build_manifest.py` skips `rules/packs/`. Don't add `rules:` keys to pack files; they are not Semgrep configs.

## Workflow

### After changing rules

```bash
python3 scripts/build_manifest.py
```

This rewrites `rules/_manifest.yaml`. Commit the manifest with the rule changes — it is the index that pack composition depends on.

### Validating a rule

The repo doesn't ship the scanner binary. Install OpenGrep (`pipx install opengrep`) or Semgrep (`pipx install semgrep`) separately. Validate a rule with:

```bash
opengrep --validate --config rules/<dir>/<file>.yaml   # or: semgrep --validate ...
```

This catches schema errors the manifest builder doesn't (the builder only checks YAML syntax, not scanner semantics).

### Composing a pack

```bash
python3 scripts/pack_compose.py rules/packs/<name>.yaml --as-args
# emits: --config rules/x.yaml --config rules/y.yaml ...
opengrep $(python3 scripts/pack_compose.py rules/packs/<name>.yaml --as-args) --json <target>
```

### Adding a new mode to /audit

1. Update `commands/audit.md` mode table.
2. Update `agents/sast-orchestrator.md` mode-to-pack table.
3. If the mode needs new rules, create them under `rules/<area>/` and tag with `pack: [<mode>]`.
4. Add a pack spec at `rules/packs/<mode>.yaml`.
5. Re-run `build_manifest.py`.

### Adding a new subagent

1. Write `agents/<name>.md` with `name`, `description`, `tools`, `model` AND `tier` frontmatter. `tier` must be one of `fast` / `mid` / `deep`. Both fields are required: `model` for Claude Code MCP mode, `tier` for the standalone CLI.
2. Reference it from `sast-orchestrator.md` in the dispatch table.
3. Update `install.sh` if the install copy step needs to know.
4. Update `README.md` subagent table.
5. The standalone CLI auto-discovers agents from `agents/*.md` — no registration needed.

## Things to avoid

- Don't write planning / decision / analysis documents unless asked. Conversation is the source of truth, not extra `.md` scratch files.
- Don't add `docs/` files; `docs/` is gitignored and reserved for local scratch.
- Don't restore the deleted `commands/audit-fast.md`, `audit-deep.md`, `audit-bugbounty.md`, `audit-cve.md`, `fix.md`. Mode flags on `/audit` replaced them.
- Don't introduce backwards-compatibility shims for modes that were never released — just change the code.
- Don't add error handling for impossible cases (e.g. validating that `pack_compose.py` got both `--as-args` and `--print-files`; the CLI is for one user, you).
- Don't add comments that explain *what* the code does. Use comments only when *why* is non-obvious.

## Things to do proactively

- When adding a new web / LLM / SCA rule, also tag `pack:` and re-run `build_manifest.py` in the same change so the manifest stays consistent.
- When fixing a YAML parse error in a rule file, scan the rest of the file for the same root cause (unquoted `: ` inside a function-call pattern is rarely a one-off).
- When updating an agent's prompt, re-read the orchestrator's dispatch table to confirm the agent's interface contract still matches.

## License

MIT (LICENSE).
