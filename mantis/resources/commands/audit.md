---
description: Run a hybrid Semgrep + Claude security audit on the local codebase. One command, full coverage, local only.
argument-hint: [path] [mode] [--fix] [--lite] [focus:<area>]
---

Run a hybrid Semgrep + Claude security audit on the local target. **Local only — no CI, no network calls beyond Semgrep registry refresh, no PR comments.** Output goes to `./security-audit-report.md` in the target repo.

**Arguments (free-form):** $ARGUMENTS

Parse arguments in this order:

1. **Path** — first positional arg. If absent, use the current working directory. Must be a directory inside the local filesystem; reject anything that looks like a URL or remote host.
2. **Mode** — second positional arg, one of:
   - `quick` — ERROR-severity, HIGH-confidence rules only. Triage only, no slicing or deep review. ~30 seconds on a normal repo.
   - `deep` — everything. Slow and expensive — every pipeline stage runs.
   - `bugbounty` — ERROR-severity, gates on **entrypoint reachability**, leads with PoC + CVSS. Exploit-first reporting.
   - `cve` — SCA / dependency lockfile scan only. No source-code SAST.
   - `mobile` — mobile rule packs only (iOS / Android / Flutter / RN).
   - `web` — web rule pack only (OWASP Top 10:2025, Java/Spring + Node + Python + Go + .NET + PHP).
   - `desktop` — desktop rule pack (Electron BrowserWindow misconfig, IPC, openExternal).
   - `llm` — LLM rule pack only (OWASP LLM Top 10:2025).
   - *omitted* — auto-detect stack, run the default hybrid pipeline.
3. **Flags** (any order):
   - `--fix` — after deep review, dispatch `fix-author` on confirmed findings, write patches in a worktree, re-run Semgrep to confirm. Diff is included in the report.
   - `--lite` — skip stages 6 (slice + reachability) and 7 (deep review). Static + triage only. Use when token budget is tight.
   - `focus:<area>` — narrow deep review to a domain. Areas: `auth`, `crypto`, `injection`, `storage`, `network`, `webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`. Useful with `deep`.

# Pipeline

Dispatch the `sast-orchestrator` subagent. Pass it the parsed `path`, `mode`, and flags. The orchestrator runs the pipeline below, enforces token budgets, and writes the report.

```
0. Inventory       (always)  — stack detection, lockfiles, entrypoints, pack pick
1. Static wide     (always)  — Semgrep with the chosen pack
2. SCA             (skipped if mode=web|llm and no lockfile detected) — lockfile dep-CVE pass
3. Secrets         (always)  — secrets pack
4. Deobf gate      (always)  — minified/packed files routed to deobfuscator
5. Triage (cheap)  (always)  — Haiku per finding, kill FPs
6. Slice + reach   (skipped in --lite, mandatory in bugbounty)
7. Deep review     (skipped in --lite, focus-scoped if focus:<area>)
8. Fix loop        (only with --fix)
9. Report          (always)  — write ./security-audit-report.md
```

# Local-only guarantees

- No `gh pr` calls, no `git push`, no GitHub API.
- No outbound HTTP except `semgrep --update` for rule registry refresh, and only if Semgrep itself decides to run it. The orchestrator never initiates a network audit.
- Findings are written to a local file. Nothing is posted anywhere.
- If `--fix` is passed, patches are applied in a **local git worktree** (`../<repo>.audit-fix-<short>/`) so the working tree is untouched. The orchestrator never commits, pushes, or opens a PR.

# Output

Single Markdown report at `./security-audit-report.md` (or `<path>/security-audit-report.md` if `path` was given). Sections:

1. Header — target, mode, pack, scan duration, total findings, token cost
2. Executive summary — counts by severity, OWASP / MASVS / MASWE / CWE / CVE distribution
3. Findings — severity-grouped, each with file:line, rule_id, mapping tags, impact, fix recommendation
4. Exploit notes — only in `bugbounty` mode, with PoC outline + CVSS vector
5. Fixes — only with `--fix`, unified diffs + Semgrep re-verify result
6. Coverage gaps — areas where rules did not exist for the detected stack
7. Footer — manifest hash, rule pack identity, agent versions

When the orchestrator returns the path to the report, surface a 5-line summary to the user and the absolute path. Do **not** dump the whole report into the chat — it's on disk.

# Stop conditions

- Path doesn't exist → ask user to specify a valid local path.
- Semgrep not installed → tell user `pipx install semgrep` and stop.
- Findings exceed 200 in default mode → ask user to narrow with a mode (`mobile` / `web` / `cve`) or a path.
- `--fix` requested but git worktree creation fails → fall back to proposing diffs in the report, do not modify files.
