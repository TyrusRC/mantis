# CLAUDE.md

Project conventions for future Claude sessions in this repo. Read this before making changes.

## What this repo is

A hybrid Semgrep + Claude SAST toolkit. Source-of-truth files for the audit pipeline live at the repo root and are installed into a target project's `.claude/` by `install.sh`. The repo itself is not a runnable Claude Code project — it is a distributable toolkit.

- `agents/` — six subagent definitions
- `commands/` — one slash command (`/audit`)
- `rules/` — Semgrep YAML rules + pack specs + manifest
- `scripts/` — manifest builder + pack composer
- `checklists/` — OWASP Testing Guide chapters for the deep-reviewer

The single user-facing entrypoint is `/audit` after `./install.sh` has copied the agents/commands into the target project.

## Hard rules

### Local-only

This toolkit is local-only by design. Never add CI integration, GitHub Action workflows, PR-comment plumbing, or remote-upload behavior. Never call `gh pr`, `git push`, or any forge API from agents or scripts. Never post findings anywhere. The only artifact a run produces is a local Markdown file at `./security-audit-report.md` (and, with `--fix`, patches inside a sibling git worktree).

If a future feature request implies CI behavior, push back: this toolkit explicitly skips CI.

### One command

There is one slash command, `/audit`. Modes (`quick`, `deep`, `bugbounty`, `cve`, `mobile`, `web`, `llm`) and flags (`--fix`, `--lite`, `focus:<area>`) are positional/flag arguments to that one command. Do not split modes back into separate commands.

### No icons / emojis

Do not add emoji or icons to user-facing output, agent definitions, command files, README, or new rule files. Pre-existing rule files (`rules/android/*-improved.yaml`, `rules/cross-platform/*-insecure.yaml`, etc.) contain icons inside their `message:` strings — leave those alone unless explicitly asked to clean them up. Do not propagate that style to new content.

### Token discipline

The whole architecture is built around token economy. Preserve it.

- **Triage** runs on Haiku (cheap), reads a +/-40-line window only.
- **Slice extraction** runs on Sonnet, hard cap of 4000 tokens of code in the slice output.
- **Deep review** runs on Opus, only on slices, only on REACHABLE survivors.
- The orchestrator never reads source files end-to-end. It reads inventory only (manifests, lockfiles, top-level dirs) and dispatches subagents for everything else.

When editing agent prompts: do not relax these caps. If the user reports the audit is missing things, the answer is usually a better slice, not a wider read.

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

The repo doesn't ship Semgrep — install separately (`pipx install semgrep`). Validate a rule with:

```bash
semgrep --validate --config rules/<dir>/<file>.yaml
```

This catches schema errors the manifest builder doesn't (the builder only checks YAML syntax, not Semgrep semantics).

### Composing a pack

```bash
python3 scripts/pack_compose.py rules/packs/<name>.yaml --as-args
# emits: --config rules/x.yaml --config rules/y.yaml ...
semgrep $(python3 scripts/pack_compose.py rules/packs/<name>.yaml --as-args) --json <target>
```

### Adding a new mode to /audit

1. Update `commands/audit.md` mode table.
2. Update `agents/sast-orchestrator.md` mode-to-pack table.
3. If the mode needs new rules, create them under `rules/<area>/` and tag with `pack: [<mode>]`.
4. Add a pack spec at `rules/packs/<mode>.yaml`.
5. Re-run `build_manifest.py`.

### Adding a new subagent

1. Write `agents/<name>.md` with `name`, `description`, `tools`, `model` frontmatter.
2. Reference it from `sast-orchestrator.md` in the dispatch table.
3. Update `install.sh` if the install copy step needs to know.
4. Update `README.md` subagent table.

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
