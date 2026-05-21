# mantis

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![SAST](https://img.shields.io/badge/SAST-OpenGrep_or_Semgrep-2bbc8a.svg)](https://www.opengrep.dev/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#status)

Hybrid SAST + LLM toolkit for local code-security audits. One pipeline, two execution modes, any LLM provider.

A wide static pass (OpenGrep or Semgrep) finds candidates. An LLM does targeted deep reasoning only on what the scanner flags. An orchestrator enforces a token budget. Local only — no CI integration, no remote upload, no telemetry.

## Two modes

**MCP mode** — drop into Claude Code, no API key required:

```bash
./install.sh /path/to/target/project
# then in Claude Code, inside the target:
/audit
```

The orchestrator subagent dispatches the pipeline using the host Claude Code session. Model tiers (`fast` / `mid` / `deep`) map to Haiku / Sonnet / Opus via each agent's `model:` frontmatter.

**Standalone CLI** — bring your own LLM provider (Anthropic, Google, OpenAI, OpenRouter, Ollama):

```bash
pipx install ./   # installs the `mantis` CLI from this repo
mantis audit /path/to/target/project
```

Configure `.mantis.yaml` in the target project (see `.mantis.example.yaml`). The CLI reads the same `agents/*.md` files, parses each agent's `tier:` (`fast` / `mid` / `deep`), and routes each call to the model you mapped that tier to. **No model names are hardcoded anywhere in this repo.**

## Status

Alpha. Mobile rules are mature (carried over from the prior version of this repo). Web, LLM, and SCA rule packs are starter sets that need expansion. The standalone CLI is scaffolded but the pipeline runner is in active development — full feature parity with the MCP path is incremental.

## Requirements

- Python 3.10+
- One of:
  - **[OpenGrep](https://www.opengrep.dev/)** (recommended; `pipx install opengrep`)
  - **[Semgrep](https://semgrep.dev/)** (`pipx install semgrep`)
- MCP mode: **[Claude Code](https://docs.claude.com/claude-code)**
- Standalone mode: an LLM provider account or local Ollama install

## Installation

```bash
git clone https://github.com/<user>/mantis.git
cd mantis
python3 scripts/build_manifest.py
```

**MCP mode** (target a project for the slash command):

```bash
./install.sh /path/to/target/project
```

Copies `agents/*.md` and `commands/audit.md` into the target's `.claude/`, and symlinks `rules/`, `checklists/`, `scripts/` for live updates.

**Standalone mode** (CLI on your `$PATH`):

```bash
pipx install ./           # installs `mantis` CLI
cp .mantis.example.yaml /path/to/target/.mantis.yaml
# edit .mantis.yaml to point at your provider + models
mantis audit /path/to/target
```

## Usage (MCP mode)

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
| `mantis audit --skip-llm` | (standalone only) run only the SAST scan and write a raw report — no provider needed |

`focus:<area>` accepts: `auth`, `crypto`, `injection`, `storage`, `network`, `webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`.

Output: `./security-audit-report.md`. With `--fix`, patches are applied in a sibling git worktree (`../<repo>.audit-fix-<short>/`). The working tree is never modified.

## Usage (standalone CLI)

```
mantis audit [path] [--mode MODE] [--fix] [--lite] [--focus AREA] [--config PATH] [--skip-llm]
```

Same modes and flags as the slash command, plus `--skip-llm` for SAST-only runs (no provider quota consumed). The CLI prints findings to `./security-audit-report.md` and respects the same token-budget caps.

## Configuration (standalone only)

`.mantis.yaml` in the target project (or `MANTIS_CONFIG=path/to/config.yaml`):

```yaml
provider: google   # anthropic | google | openai | openrouter | ollama
models:
  fast:  gemini-2.5-flash-lite       # cheap triage
  mid:   gemini-2.5-flash             # slicing, fix authoring
  deep:  gemini-2.5-pro               # deep dataflow review
budget:
  max_findings:  200
  max_deep_calls: 50
sast_bin: opengrep                    # opengrep | semgrep | auto (default)
```

Env-var override: `MANTIS_PROVIDER`, `MANTIS_MODEL_FAST`, `MANTIS_MODEL_MID`, `MANTIS_MODEL_DEEP`, `MANTIS_SAST_BIN`.

API keys come from the provider's standard env var: `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`. Ollama needs no key; set `endpoint: http://localhost:11434` instead.

### Free / self-hosted setups

| Setup | Provider | Notes |
|---|---|---|
| **Gemini free tier** | `google` | `GEMINI_API_KEY` from aistudio.google.com; rate-limited |
| **Ollama self-host** | `ollama` | No key; pick coder models e.g. `qwen2.5-coder:32b` for the `deep` tier |
| **OpenRouter** | `openrouter` | One key, many models including free DeepSeek / Llama variants |

## Pipeline

```
0. Inventory       detect stack, lockfiles, entrypoints, pick pack
1. Static wide     OpenGrep (or Semgrep) with chosen pack
2. SCA             lockfile dep-CVE rules
3. Secrets         high-confidence secrets pack
4. Deobf gate      route minified / packed files to deobfuscator
5. Triage          fast tier per finding, drop FPs (isolated context)
6. Slice + reach   depth-limited callgraph, entrypoint reachability
7. Deep review     deep tier only on REACHABLE TRUE / NEEDS-DEEP slices
8. Fix             patch in worktree, re-run scanner          (only with --fix)
9. Report          write ./security-audit-report.md
```

Ten stages, indexed 0–9. Stages 6–8 are conditionally skipped based on mode and flags. Triage and slicing run in isolated contexts.

## Repository layout

```
agents/        six subagent definitions (markdown with model: + tier:)
commands/      one slash command (/audit) — MCP mode only
rules/         OpenGrep / Semgrep YAML rules + pack specs + manifest
scripts/       build_manifest.py, pack_compose.py
checklists/    OWASP Testing Guide chapters for the deep-reviewer
mantis/        standalone CLI Python package
install.sh     install agents/commands into a target project (MCP mode)
pyproject.toml package metadata for the standalone CLI
CLAUDE.md      project conventions for future Claude sessions
```

| Subagent | Role | Tier |
|---|---|---|
| sast-orchestrator | plan, dispatch, write report | mid |
| triage-analyst | classify findings, drop FPs | fast |
| slice-extractor | depth-limited interprocedural slice | mid |
| deep-reviewer | confirm vulnerability, CVSS, mapping, PoC | deep |
| fix-author | minimal patch in worktree, re-verify | mid |
| deobfuscator | minified / packed / encoded files (static analysis only) | mid |

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
opengrep $(python3 scripts/pack_compose.py rules/packs/fast.yaml --as-args) --json <target>
```

## Coverage

- Mobile: OWASP MASVS 2.1 + MASTG (iOS, Android, Flutter, React Native)
- Web: OWASP Top 10:2025 — A01, A02, A03, A05, A08, A10
- LLM: OWASP LLM Top 10:2025 — LLM01, LLM02, LLM05, LLM07, LLM10
- SCA: npm, pip, gradle (Log4Shell, Spring4Shell, event-stream, ua-parser-js, lodash, PyYAML, requests)
- Testing Guide: business-logic and LLM checklists for findings the scanner cannot pattern-match

## Local-only guarantees

- No `gh pr`, `git push`, or forge API calls
- No findings posted to any external service
- No CI integration, no GitHub Action, no webhook
- `--fix` writes to a local git worktree, never the working tree
- The standalone CLI calls the LLM provider you configure; no telemetry to mantis

## Contributing

Read `CLAUDE.md` first. It documents conventions, the YAML quoting gotcha for scanner patterns, the model-name-never-hardcoded rule, and the workflow for adding rules, packs, modes, and subagents.

After changing any rule, run `python3 scripts/build_manifest.py` and commit the updated `rules/_manifest.yaml` alongside the change.

## License

[MIT](LICENSE)

## Acknowledgments

Architecture: [AGHAST](https://www.bouncesecurity.com/blog/2026/04/14/introducing-aghast), [Slice](https://noperator.dev/posts/slice/), [Vulnhuntr](https://github.com/protectai/vulnhuntr), [Tree-of-AST (Black Hat USA 2025)](https://ruik.ai/).
UX: [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review), [afiqiqmal/claude-security-audit](https://github.com/afiqiqmal/claude-security-audit), [HarmonicSecurity/claudit-sec](https://github.com/HarmonicSecurity/claudit-sec).
Skills: [trailofbits/skills](https://github.com/trailofbits/skills), [VoltAgent/awesome-claude-code-subagents](https://github.com/VoltAgent/awesome-claude-code-subagents).
Tooling: [OpenGrep](https://github.com/opengrep/opengrep), [Semgrep](https://github.com/semgrep/semgrep), [litellm](https://github.com/BerriAI/litellm).
Standards: [OWASP MASVS](https://mas.owasp.org/MASVS/), [MASTG](https://mas.owasp.org/MASTG/), [LLM Top 10:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).
