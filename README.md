# automated-code-examination-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Semgrep](https://img.shields.io/badge/Semgrep-required-2bbc8a.svg)](https://semgrep.dev/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)
[![Rules](https://img.shields.io/badge/rules-782-informational.svg)](rules/_manifest.yaml)

Hybrid Semgrep + Claude SAST toolkit. One slash command, local only.

Semgrep does the cheap wide pass. Claude does targeted deep reasoning only on what Semgrep flags. A controller agent orchestrates the loop and enforces a token budget.

## Status

Alpha. Mobile rules are mature (carried over from the prior version of this repo). Web, LLM, and SCA rule packs are starter sets that need expansion. The orchestrator and pipeline are functional but unverified against a wide corpus.

## Requirements

- Python 3.8+ with PyYAML (`pip install pyyaml`)
- [Semgrep](https://semgrep.dev/) (`pipx install semgrep`)
- [Claude Code](https://docs.claude.com/claude-code) for the slash command and subagents

## Installation

```bash
git clone https://github.com/<user>/automated-code-examination-mcp.git
cd automated-code-examination-mcp
python3 scripts/build_manifest.py
./install.sh /path/to/target/project
```

`install.sh` copies `agents/` and `commands/` into the target's `.claude/` directory and symlinks `rules/` into `.claude/sast-rules/`.

Optional: register Semgrep MCP with Claude Code.

```bash
claude mcp add semgrep -- semgrep mcp
```

## Usage

```
/audit [path] [mode] [--fix] [--lite] [focus:<area>]
```

| Invocation | Behavior |
|---|---|
| `/audit` | auto-detect stack, full hybrid pipeline |
| `/audit ./src` | scope to a subdirectory |
| `/audit quick` | ERROR severity, HIGH confidence, triage only |
| `/audit deep` | every rule, full pipeline |
| `/audit bugbounty` | exploit-first, gates on entrypoint reachability |
| `/audit cve` | SCA / lockfile dependency scan only |
| `/audit mobile` | mobile rule pack only |
| `/audit web` | OWASP Top 10:2025 pack only |
| `/audit llm` | OWASP LLM Top 10:2025 pack only |
| `/audit deep focus:auth` | full pipeline, deep review only on auth-tagged findings |
| `/audit --fix` | apply patches in a local worktree, re-verify |
| `/audit --lite` | skip slicing and deep review |

`focus:<area>` accepts: `auth`, `crypto`, `injection`, `storage`, `network`, `webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`.

Output: `./security-audit-report.md`. With `--fix`, patches are applied in a sibling git worktree (`../<repo>.audit-fix-<short>/`). The working tree is never modified.

## Pipeline

```
0. Inventory       detect stack, lockfiles, entrypoints, pick pack
1. Static wide     Semgrep with chosen pack
2. SCA             lockfile dep-CVE rules
3. Secrets         high-confidence secrets pack
4. Deobf gate      route minified / packed files to deobfuscator
5. Triage          Haiku per finding, drop FPs (isolated context)
6. Slice + reach   depth-limited callgraph, entrypoint reachability
7. Deep review     Opus only on REACHABLE TRUE / NEEDS-DEEP slices
8. Fix             patch in worktree, re-run Semgrep        (only with --fix)
9. Report          write ./security-audit-report.md
```

Ten stages, indexed 0–9. Stages 6–8 are conditionally skipped based on mode and flags.

Triage and slicing run in subagents with isolated context. The main thread sees verdicts only.

## Repository layout

```
agents/        six subagent definitions
commands/      one slash command (/audit)
rules/         Semgrep YAML rules + pack specs + manifest
scripts/       build_manifest.py, pack_compose.py
checklists/    OWASP Testing Guide chapters Semgrep cannot pattern-match
install.sh     install agents/commands into a target project
CLAUDE.md      project conventions for future Claude sessions
```

| Subagent | Role | Model |
|---|---|---|
| sast-orchestrator | plan, dispatch, write report | sonnet |
| triage-analyst | classify findings, drop FPs | haiku |
| slice-extractor | depth-limited interprocedural slice | sonnet |
| deep-reviewer | confirm vulnerability, CVSS, mapping, PoC | opus |
| fix-author | minimal patch in worktree, re-verify | sonnet |
| deobfuscator | minified / packed / encoded files (static analysis only) | sonnet |

| Pack | Selects |
|---|---|
| `fast` | severity ERROR, confidence HIGH |
| `deep` | everything |
| `bugbounty` | severity ERROR, confidence HIGH or MEDIUM |
| `cve` | rules with `metadata.cve` set |
| `sca` | dependency / lockfile rules |
| `mobile`, `mobile-ios`, `mobile-android` | by language and path |
| `web`, `llm` | by path |

Pack composition:

```bash
python3 scripts/pack_compose.py rules/packs/fast.yaml --as-args
# emits: --config rules/x.yaml --config rules/y.yaml ...
semgrep $(python3 scripts/pack_compose.py rules/packs/fast.yaml --as-args) --json <target>
```

## Coverage

- Mobile: OWASP MASVS 2.1 + MASTG (iOS, Android, Flutter, React Native)
- Web: OWASP Top 10:2025 — A01, A02, A03, A05, A08, A10
- LLM: OWASP LLM Top 10:2025 — LLM01, LLM02, LLM05, LLM07, LLM10
- SCA: npm, pip, gradle (Log4Shell, Spring4Shell, event-stream, ua-parser-js, lodash, PyYAML, requests)
- Testing Guide: business-logic and LLM checklists for findings Semgrep cannot pattern-match

## Local-only guarantees

- No `gh pr`, `git push`, or forge API calls
- No findings posted to any external service
- No CI integration, no GitHub Action, no webhook
- `--fix` writes to a local git worktree, never the working tree

## Contributing

Read `CLAUDE.md` first. It documents conventions, the YAML quoting gotcha for Semgrep patterns, and the workflow for adding rules, packs, modes, and subagents.

After changing any rule, run `python3 scripts/build_manifest.py` and commit the updated `rules/_manifest.yaml` alongside the change.

## License

[MIT](LICENSE)

## Acknowledgments

Architecture: [AGHAST](https://www.bouncesecurity.com/blog/2026/04/14/introducing-aghast), [Slice](https://noperator.dev/posts/slice/).
UX: [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review), [afiqiqmal/claude-security-audit](https://github.com/afiqiqmal/claude-security-audit), [HarmonicSecurity/claudit-sec](https://github.com/HarmonicSecurity/claudit-sec).
Skills: [trailofbits/skills](https://github.com/trailofbits/skills), [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents).
Tooling: [Semgrep](https://github.com/semgrep/semgrep).
Standards: [OWASP MASVS](https://mas.owasp.org/MASVS/), [MASTG](https://mas.owasp.org/MASTG/), [LLM Top 10:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).
