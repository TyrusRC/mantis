# mantis

Hybrid SAST + LLM toolkit for local code-security audits.

OpenGrep (or Semgrep) finds candidates; an LLM reasons on the slices the
scanner flags. Runs as a Claude Code slash command, or as a standalone
CLI against any litellm-supported provider. Local only.

## Requirements

- Python 3.10+
- [OpenGrep](https://www.opengrep.dev/) or [Semgrep](https://semgrep.dev/)
- MCP mode: [Claude Code](https://docs.claude.com/claude-code)
- Standalone mode: an LLM provider (Anthropic, Google, OpenAI, OpenRouter, Ollama, ...)

## Install

```bash
git clone https://github.com/TyrusRC/automated-code-examination-mcp.git mantis
cd mantis
./setup.sh           # installs opengrep + the `mantis` CLI via pipx
./doctor.sh          # verifies the install
```

For MCP mode, copy agents and the slash command into a target project:

```bash
./install.sh /path/to/target/project
```

## Usage

### MCP (inside Claude Code)

```
/audit [path] [mode] [--fix] [--lite] [focus:<area>]
```

| Invocation | Behavior |
|---|---|
| `/audit` | auto-detect stack, full pipeline |
| `/audit quick` | ERROR severity, HIGH confidence, triage only |
| `/audit deep` | every rule, full pipeline |
| `/audit bugbounty` | exploit-first, gates on entrypoint reachability |
| `/audit cve` | SCA / lockfile dependency scan only |
| `/audit mobile` \| `web` \| `llm` | scope to a single rule pack |
| `/audit deep focus:auth` | full pipeline, deep review only on auth-tagged findings |
| `/audit --fix` | apply patches in a worktree, re-verify |
| `/audit --lite` | skip slicing and deep review |

`focus:<area>` accepts: `auth`, `crypto`, `injection`, `storage`, `network`,
`webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`.

### Standalone CLI

```
mantis audit [path] [--mode MODE] [--fix] [--lite] [--focus AREA] [--config PATH] [--skip-llm]
mantis check [path]
```

`--skip-llm` runs the SAST + slice stages only; no provider needed.

Output: `./security-audit-report.md`. With `--fix`, patches are applied in
`../<repo>.audit-fix-<short>/`; the working tree is never modified.

## Configuration (standalone)

`.mantis.yaml` in the target project (see `.mantis.example.yaml`):

```yaml
provider: google     # anthropic | google | openai | openrouter | ollama
models:
  fast: gemini-2.5-flash-lite
  mid:  gemini-2.5-flash
  deep: gemini-2.5-pro
budget:
  max_findings: 200
  max_deep_calls: 50
sast_bin: opengrep   # opengrep | semgrep | auto
triage:
  mode: single       # single | dual
```

Environment overrides: `MANTIS_PROVIDER`, `MANTIS_MODEL_FAST`,
`MANTIS_MODEL_MID`, `MANTIS_MODEL_DEEP`, `MANTIS_API_BASE`,
`MANTIS_SAST_BIN`, `MANTIS_CONFIG`, `MANTIS_TRIAGE_MODE`.

API keys come from the provider's standard env var:
`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`,
`OPENROUTER_API_KEY`. Ollama needs no key; set `api_base: http://localhost:11434`.

Model names are read verbatim from this file. None are hardcoded in the toolkit.

## Pipeline

```
0  inventory      detect stack, lockfiles, entrypoints
1  static wide    opengrep/semgrep with the selected pack
2  SCA            lockfile dependency-CVE rules
3  secrets        high-confidence secrets pack
4  deobf gate     route minified/packed files to the deobfuscator
5  triage         fast tier per finding (single or dual chain)
6  slice          depth-limited callgraph, entrypoint reachability
7  deep review    deep tier on reachable TRUE / NEEDS-DEEP slices
8  fix            patch in worktree, re-run scanner   (only with --fix)
9  report         write ./security-audit-report.md
```

Stages 6–8 are conditionally skipped based on mode and flags. Triage and
slicing run in isolated contexts to keep the orchestrator's window small.

## Repository layout

```
agents/        subagent definitions (markdown, model: + tier: frontmatter)
commands/      slash command for MCP mode
rules/         opengrep/semgrep YAML rules + pack specs + manifest
scripts/       build_manifest.py, pack_compose.py
checklists/    OWASP Testing Guide chapters for the deep-reviewer
mantis/        standalone CLI Python package
install.sh     install agents/commands into a target (MCP mode)
setup.sh       install opengrep + mantis CLI
doctor.sh      verify install
CLAUDE.md      conventions for future contributors / Claude sessions
```

### Subagents

| Name | Role | Tier |
|---|---|---|
| sast-orchestrator | plan, dispatch, write report | mid |
| triage-analyst | classify findings, drop FPs | fast |
| slice-extractor | interprocedural slice with entrypoint reachability | mid |
| deep-reviewer | confirm vulnerability, map CWE/CVSS, PoC | deep |
| fix-author | minimal patch in worktree, re-verify | mid |
| deobfuscator | minified / packed / encoded files (static only) | mid |

### Packs

| Pack | Selects |
|---|---|
| `fast` | severity ERROR, confidence HIGH |
| `deep` | everything |
| `bugbounty` | severity ERROR, confidence HIGH or MEDIUM |
| `cve` | rules with `metadata.cve` set |
| `sca` | dependency / lockfile rules |
| `mobile`, `mobile-ios`, `mobile-android` | by language and path |
| `web`, `llm`, `taint` | by path |

Compose a pack:

```bash
python3 scripts/pack_compose.py rules/packs/fast.yaml --as-args
opengrep $(python3 scripts/pack_compose.py rules/packs/fast.yaml --as-args) --json <target>
```

## Local-only

No CI integration, no forge API calls, no telemetry. `--fix` writes to a
sibling git worktree, never the working tree. The only artifact a run
produces is `./security-audit-report.md` (and, with `--fix`, patches inside
the worktree).

## Contributing

Read [CLAUDE.md](CLAUDE.md) — it documents YAML quoting gotchas, the
tier-vs-model split, the rule-pack workflow, and what *not* to add (CI
hooks, remote upload, hardcoded model names).

After editing rules, rebuild the manifest:

```bash
python3 scripts/build_manifest.py
```

Commit the updated `rules/_manifest.yaml` alongside the rule change.

## License

[MIT](LICENSE)

## Acknowledgments

Architecture: [AGHAST](https://www.bouncesecurity.com/blog/2026/04/14/introducing-aghast), [Slice](https://noperator.dev/posts/slice/), [Vulnhuntr](https://github.com/protectai/vulnhuntr), [Tree-of-AST (Black Hat USA 2025)](https://ruik.ai/).
Tooling: [OpenGrep](https://github.com/opengrep/opengrep), [Semgrep](https://github.com/semgrep/semgrep), [litellm](https://github.com/BerriAI/litellm).
Standards: [OWASP MASVS](https://mas.owasp.org/MASVS/), [MASTG](https://mas.owasp.org/MASTG/), [OWASP Top 10:2025](https://owasp.org/Top10/), [LLM Top 10:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/).
