---
description: Run a hybrid OpenGrep + Claude security audit on the local codebase. One command, full coverage, local only.
argument-hint: [path] [mode] [--fix] [--lite] [--experimental-toast] [focus:<area>]
allowed-tools: Bash(opengrep --version), Bash(xargs opengrep scan *), Bash(opengrep scan *), Bash(python3 .claude/sast-scripts/pack_compose.py *), Bash(python3 .claude/sast-scripts/project_findings.py *), Bash(python3 .claude/sast-scripts/asset_map.py *), Bash(sha256sum .claude/sast-rules/_manifest.yaml), Bash(git rev-parse *), Bash(git status *), Bash(git ls-files *)
---

Run a hybrid OpenGrep + Claude security audit on the local target. **Local only — no CI, no network calls initiated by the pipeline, no PR comments.** Output goes to `./security-audit-report.md` in the target repo.

**Arguments (free-form):** $ARGUMENTS

Parse arguments in this order:

1. **Path** — first positional arg. If absent, use the current working directory. Must be a directory inside the local filesystem; reject anything that looks like a URL or remote host.
2. **Mode** — second positional arg, one of:
   - `quick` — ERROR-severity, HIGH-confidence rules only. Triage only, no slicing or deep review. ~30 seconds on a normal repo.
   - `deep` — everything. Slow and expensive — every pipeline stage runs.
   - `bugbounty` — ERROR-severity, gates on **entrypoint reachability**, leads with PoC + CVSS. Exploit-first reporting.
   - `cve` — SCA / dependency lockfile scan only. No source-code SAST.
   - `mobile` — mobile rule packs (iOS / Android / Flutter / RN); auto-narrows to one platform when the stack is single-platform.
   - `mobile-ios` / `mobile-android` — native iOS or native Android rules only.
   - `web` — web rule pack only (OWASP Top 10:2025, Java/Spring + Node + Python + Go + .NET + PHP).
   - `desktop` — desktop rule pack (Electron BrowserWindow misconfig, IPC, openExternal).
   - `llm` — LLM rule pack only (OWASP LLM Top 10:2025).
   - `taint` — taint-mode rules only (cross-function source-to-sink flows via OpenGrep `--taint-intrafile`).
   - `secrets` — hardcoded credentials / API tokens / private keys.
   - `iac` — infrastructure-as-code: Terraform (AWS), Dockerfile, Kubernetes manifests.
   - `cloud` — cloud SDK misuse in application code (AWS / GCP / Azure).
   - *omitted* — auto-detect stack, run the default hybrid pipeline.
3. **Flags** (any order):
   - `--fix` — after deep review, dispatch `fix-author` on confirmed findings, write patches in a worktree, re-run opengrep to confirm. Diff is included in the report.
   - `--lite` — skip stages 6 (slice + reachability) and 7 (deep review). Static + triage only. Use when token budget is tight.
   - `--experimental-toast` — `bugbounty` only: run the experimental ToAST hunter on confirmed slices to look for issues beyond the rule set.
   - `focus:<area>` — narrow deep review to a domain. Areas: `auth`, `crypto`, `injection`, `storage`, `network`, `webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`. Useful with `deep`.

# Pipeline

Dispatch the `sast-orchestrator` subagent. Pass it the parsed `path`, `mode`, and flags. The orchestrator runs the pipeline below, enforces token budgets, and writes the report.

```
0.  Inventory       (always)  — stack detection, lockfiles, entrypoints, pack pick
0b. Asset map       (always)  — entry points, auth, data stores; STRIDE threat model
1.  Static wide     (always)  — OpenGrep with the chosen pack(s)
2.  SCA             (skipped if mode=web|llm and no lockfile detected) — lockfile dep-CVE pass
3.  Secrets         (always except cve)  — secrets pack
4.  Deobf gate      (always except cve)  — minified/packed files routed to deobfuscator
5.  Triage (cheap)  (always)  — fast tier, same-file clusters of up to 8, kill FPs
6.  Slice + reach   (skipped in quick, cve, --lite; mandatory in bugbounty) — TRUE + NEEDS-DEEP
7.  Deep review     (skipped in quick, cve, --lite; focus-scoped if focus:<area>)
7b. ToAST hunt      (only bugbounty + --experimental-toast)
8.  Fix loop        (only with --fix)
9.  Report          (always)  — write ./security-audit-report.md
```

# Local-only guarantees

- No `gh pr` calls, no `git push`, no GitHub API.
- No outbound HTTP initiated by the pipeline; only local rule files are passed to OpenGrep.
- Findings are written to a local file. Nothing is posted anywhere.
- If `--fix` is passed, patches are applied in a **local git worktree** (`../<repo>.audit-fix-<short>/`) so the working tree is untouched. The orchestrator never commits, pushes, or opens a PR.

# Output

Single Markdown report at `./security-audit-report.md` (or `<path>/security-audit-report.md` if `path` was given). Sections:

1. Header — target, mode, pack, scan duration, total findings, token cost
2. Executive summary — counts by severity, OWASP / MASVS / MASWE / CWE / CVE distribution
3. Threat model — STRIDE, from the stage-0b asset map (or a labeled inventory-only fallback)
4. Findings — severity-grouped, each with file:line, rule_id, mapping tags, impact, fix recommendation
5. Exploit notes — only in `bugbounty` mode, with PoC outline + CVSS vector
6. Fixes — only with `--fix`, unified diffs + opengrep re-verify result
7. Coverage gaps — areas where rules did not exist for the detected stack
8. Footer — manifest hash, rule pack identity, agent versions

When the orchestrator returns the path to the report, surface a 5-line summary to the user and the absolute path. Do **not** dump the whole report into the chat — it's on disk.

# Stop conditions

- Path doesn't exist → ask user to specify a valid local path.
- opengrep not installed → tell user `pipx install opengrep` and stop.
- Findings exceed 200 in default mode → ask user to narrow with a mode (`mobile` / `web` / `cve`) or a path.
- `--fix` requested but git worktree creation fails → fall back to proposing diffs in the report, do not modify files.
