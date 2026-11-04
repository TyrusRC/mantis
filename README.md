# mantis

Hybrid SAST + LLM toolkit for local code-security audits.

781 OpenGrep rules across 11 languages (Python, JavaScript/TypeScript, Java, Kotlin, Swift, Go, Ruby, PHP, C#, Dart, C/C++). Covers OWASP Web Top 10 2025 A01--A09 (A10, mishandling of exceptional conditions, has no rules yet), OWASP LLM Top 10, mobile (Android + iOS + Flutter + React Native), IaC (Terraform, Dockerfile, Kubernetes), cloud SDK misuse (AWS/GCP/Azure), SCA, secrets, dataflow taint analysis (injection / SSRF / path traversal / deserialization / SSTI / XSS / LDAP / XXE / NoSQL across Python, JS/TS, Java, PHP), and native C/C++ binary analysis. 5 WSTG checklists.

Stage 0b auto-generates a **STRIDE threat model** and **asset map** (entry points, auth boundaries, data stores, external calls, sensitive data) that enriches every downstream stage. A **BM25 linker** connects findings to their most-relevant entry point when call-graph tracing falls short. An LLM reasons on the slices the scanner flags. Runs as a Claude Code slash command, or as a standalone CLI against any provider. Local only.

## Requirements

- Python 3.10+
- [OpenGrep](https://www.opengrep.dev/)
- MCP mode: [Claude Code](https://docs.claude.com/claude-code)
- Standalone mode: an LLM provider (Anthropic, Google, OpenAI, OpenRouter, Ollama, ...)

## Install

From PyPI (recommended):

```bash
pipx install mantis-sast        # the CLI binary is `mantis`
pipx install opengrep
mantis --version
```

From source (for hacking on rules/agents):

```bash
git clone https://github.com/TyrusRC/automated-code-examination-mcp.git mantis
cd mantis
./setup.sh                      # installs opengrep + mantis via pipx
./doctor.sh                     # verifies the install
```

For MCP mode (Claude Code), copy agents and the slash command into a target project:

```bash
./install.sh /path/to/target/project
```

The installer also ships inside the wheel. With a pipx/pip install, `mantis doctor`
prints `resources at <dir>`; run the installer from there:

```bash
bash <dir>/install.sh /path/to/target/project
```

It links rules, scripts, and checklists under the target's `.claude/sast-*`, and adds a
small allowlist (the exact `opengrep scan`, `.claude/sast-scripts/*.py`, and read-only
`git` commands the pipeline runs) to the target's untracked `.claude/settings.local.json`,
so unattended `/audit` runs don't stall on permission prompts. Existing entries are kept.

## Updating

`mantis` checks PyPI once per 24h on startup and prints a one-line nudge
if a newer release exists. To check explicitly or upgrade in place:

```bash
mantis update --check           # query PyPI, bypass the 24h cache
mantis update                   # upgrade via the same installer used (pipx or pip)
```

Disable the passive check by setting `MANTIS_NO_UPDATE_CHECK=1`. Editable
installs are skipped (you maintain them via git).

## Usage

### MCP (inside Claude Code)

```
/audit [path] [mode] [--fix] [--lite] [--experimental-toast] [focus:<area>]
```

| Invocation | Behavior |
|---|---|
| `/audit` | auto-detect stack, full pipeline |
| `/audit quick` | ERROR severity, HIGH confidence, triage only |
| `/audit deep` | every rule, full pipeline |
| `/audit bugbounty` | exploit-first, gates on entrypoint reachability |
| `/audit cve` | SCA / lockfile dependency scan only |
| `/audit mobile` \| `mobile-ios` \| `mobile-android` \| `web` \| `desktop` \| `llm` \| `taint` | scope to a single rule pack |
| `/audit secrets` \| `iac` \| `cloud` | hardcoded creds / Terraform+Dockerfile+K8s / AWS-GCP-Azure SDK misuse |
| `/audit deep focus:auth` | full pipeline, deep review only on auth-tagged findings |
| `/audit --fix` | apply patches in a worktree, re-verify |
| `/audit --lite` | skip slicing and deep review |
| `/audit bugbounty --experimental-toast` | also run the ToAST hunter on confirmed slices |

`focus:<area>` accepts: `auth`, `crypto`, `injection`, `storage`, `network`,
`webview`, `secrets`, `privacy`, `ipc`, `business-logic`, `prompt-injection`.

### Standalone CLI

```
mantis init [path]                    # scaffold .mantis.yaml + .env.example
mantis doctor [path]                  # probe install, scanner, agents, keys, config
mantis audit [path] [mode] [focus:<area>] [options]
mantis history [path]                 # list past runs
mantis show [ref] [--path .]          # print a past report (ref: id, prefix, latest, -N)
mantis diff [a] [b] [--path .]        # unified diff between two runs
mantis update [--check]               # query PyPI, upgrade in place
```

`audit` options worth knowing:

| Flag | Effect |
|---|---|
| `--since <ref>` | scan only files changed vs. a git ref (`main`, `HEAD~1`, `uncommitted`, `staged`) |
| `--format md\|json\|sarif\|all` | write structured output alongside the markdown report |
| `--no-cache` | bypass the per-file SAST cache and the LLM response cache (`~/.cache/mantis/llm`) |
| `--skip-llm` | SAST + inventory only; no provider needed |
| `--lite` | skip slicing + deep review |
| `--fix` | apply patches in a worktree, re-verify |
| `--fail-on low\|medium\|high\|critical` | exit non-zero if any unsuppressed finding is at or above this severity (pre-commit / local gate) |
| `--emit-context-graph <path>` | write the code context graph (nodes/edges/entry points) to `<path>` as JSON for another tool or agent to consume when integrating mantis into a flow (opt-in; no file otherwise) |
| `--engines <list\|all\|none>` | SAST engines run alongside OpenGrep **by default** (installed engines matching the tree, incl. trivy/grype): bandit, gosec, njsscan, eslint-security, checkov, trivy, grype. Pass a list to restrict, `all` for every installed engine, or `none` to disable. |
| `--engines-offline` | run the network SCA engines (trivy/grype) in offline-DB mode. trivy/grype fetch a vulnerability database (network); every other engine is fully local. |
| `--pack <name>` | run exactly this pack (repeatable), bypassing mode + inventory |
| `--decompiled` | detect the stack from source extensions alone (no build files) |

`audit` mode is positional and matches the MCP slash form:
`mantis audit quick`, `mantis audit deep focus:auth`, `mantis audit . web --since main`.

### Auditing decompiled / reverse-engineered source

Inventory keys off build files (`build.gradle`, lockfiles, `AndroidManifest.xml`).
A decompiled tree — jadx Java/Kotlin, Ghidra pseudo-C, e.g. what
[chimera](https://github.com/TyrusRC/chimera) emits when it unpacks a binary —
has source but none of those, so plain inventory would fall back to the `fast`
pack. Two knobs fix that:

```bash
# Best-effort: detect the stack from source extensions alone
mantis audit ./decompiled_out --decompiled --skip-llm

# Precise: you already know the platform, so name the packs
mantis audit ./jadx_sources --pack mobile-android --pack secrets --skip-llm
mantis audit ./ghidra_pseudo_c --pack secrets --skip-llm
```

Programmatically (SAST-only, no provider needed) — the seam a tool like chimera
calls after decompiling a binary to a source tree:

```python
from mantis import audit

findings = audit("jadx_sources", packs=["mobile-android", "secrets"])
findings = audit("decompiled_out", decompiled=True)   # auto stack detection
# each finding: {rule_id, severity, confidence, path, start_line, end_line,
#                message, metadata (cwe/owasp/masvs...), verdict}
```

Need the code graph itself (nodes, `calls`/`imports` edges, entry points) to drive
another agent in a flow? Build it and serialize it — requires `tree-sitter-language-pack`:

```python
from pathlib import Path
from mantis.context_graph import build_context_graph

g = build_context_graph(Path("src"))      # None if tree-sitter is not installed
graph = g.to_dict()                        # {schema, indexed_files, entry_points, nodes, edges}
g.write_json("context-graph.json")         # or dump it to a file for a downstream tool
```

The schema is importer-free: a consumer recomputes reachability by following
`calls` edges from an entry point. The CLI equivalent is `--emit-context-graph <path>`.

### Native C/C++ and malware analysis

The `native` pack (23 rules) covers decompiled C/C++ from Ghidra, r2ghidra, or IDA Hex-Rays — the chimera RE→SAST bridge:

- **decompiled-c-vulns** (16 rules): buffer overflows (`gets`, `strcpy`, `sprintf`, `scanf`), format string (`printf(var)`), command injection (`system(var)`, `popen`), use-after-free, hardcoded credentials, insecure random (`rand`/`srand`), integer overflow, TOCTOU race conditions
- **malware-patterns** (7 rules): process injection (`WriteProcessMemory` + `CreateRemoteThread`), shellcode execution via callback (`EnumSystemLocalesA`, `GrayStringA`), dynamic API resolution (PEB walk + `GetProcAddress` hash), anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`), registry persistence (`RegSetValueEx` on Run keys), keylogging (`GetAsyncKeyState`/`SetWindowsHookEx`), suspicious network (`InternetOpenA` + `HttpSendRequest` chains) — all tagged with MITRE ATT&CK technique IDs

```bash
# CLI
mantis audit ./ghidra_output --pack native --skip-llm
mantis audit ./r2_decompiled --pack native --language c --skip-llm

# Programmatic (chimera integration)
from mantis import audit
findings = audit("decompiled_output", packs=["native"], language="c")
findings = audit("decompiled_output", packs=["native", "secrets"], language="c", timeout=120)
```

The `language` parameter tells mantis the source language directly (skipping
extension-based detection), and `timeout` caps the OpenGrep run — both are
useful for chimera's automated decompile→audit pipeline.

Reports land under `<target>/.mantis/runs/<ts>-<sha>.md` with stable pointers at
`<target>/.mantis/latest.md` and `<target>/security-audit-report.md`. With `--fix`,
patches are applied in `../<repo>.audit-fix-<short>/`; the working tree is never modified.
A patch is kept only if the original rule fires fewer times on the patched file and
the full pack reports nothing new on the changed files; otherwise it is reverted.

### Suppressions

Drop a `.mantisignore` at the target root to silence known-but-accepted findings.
Suppressed findings never reach the LLM. The short rule id is enough; the matcher
also accepts the fully-qualified scanner id or a fnmatch glob.

```yaml
- rule_id: iac-k8s-host-network
  path: "k8s/cni/**"
  reason: hostNetwork required for our CNI in this cluster
- rule_id: iac-*
  path: "tests/fixtures/**"
  reason: deliberately vulnerable test fixtures
- rule_id: secret-generic-password-assignment
  path: "docs/examples/**"
```

Same-function findings (12 SQLi calls in one helper) are folded into one
representative before triage so the deep-reviewer doesn't get 12 near-identical
calls; the report shows `(+N similar in same function)` on the rep.

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
sast_bin: opengrep   # the only supported scanner
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
0   inventory     detect stack, lockfiles, entrypoints
0b  asset map     regex-scan for entry points, auth middleware, data stores,
                  external calls, sensitive data across all supported languages;
                  feeds triage context, reachability, slice annotations, and the
                  auto-generated STRIDE threat model in the report. When
                  tree-sitter is installed, also builds a context graph with
                  typed call edges (EXTRACTED/INFERRED) for precise multi-language
                  reachability and hop-count-to-entry-point in triage context
1   static wide   opengrep with the selected pack and --taint-intrafile
                  (cross-function flows within a file; SCA lockfile and secrets
                  rules are packs here), plus the extra engines
                  (bandit/gosec/njsscan/eslint-security/checkov/trivy/grype)
                  when installed; opt out with --engines none
5   triage        fast tier per finding (single or dual chain) — receives
                  asset context (nearest entry point, auth status, nearby stores);
                  an unparseable or failed verdict is sliced like NEEDS-DEEP and
                  marks the run incomplete, never silently passes --fail-on
5b  haruspex      optional advisory TP-likelihood ranking (MANTIS_HARUSPEX_URL)
6   slice         depth-limited callgraph, entrypoint reachability (asset map
                  extends reachability to non-Python languages); BM25 fallback
                  links findings to entry points when grep-based callers miss
7   deep review   deep tier on TRUE / NEEDS-DEEP slices whose reachability is
                  yes or unknown (yes only in bugbounty), highest severity first
                  under the budget — slice text includes ASSET_CONTEXT block
7b  toast         experimental 3-sample hunt for rule-less bugs (bugbounty,
                  --experimental-toast)
8   fix           patch in worktree; rule hit count must drop and the pack
                  must report nothing new on changed files   (only with --fix)
9   report        write <target>/.mantis/runs/<ts>-<sha>.md (+ latest.md symlink);
                  includes auto-generated STRIDE threat model section
```

Stages 6–8 are conditionally skipped based on mode and flags. Triage and
slicing run in isolated contexts to keep the orchestrator's window small.

### Asset map (stage 0b)

The asset map scans the target tree in a single pass per file, matching
language-specific regex patterns for:

| Asset kind | Examples |
|---|---|
| Entry points | Flask/FastAPI/Django routes, Express/Koa handlers, Spring `@*Mapping`, Go `http.HandleFunc`, Rails routes, Laravel `Route::`, ASP.NET `[Http*]`, Actix/Axum, iOS lifecycle, Android `onCreate` |
| Trust boundaries | `@login_required`, `passport.authenticate`, `@PreAuthorize`, `[Authorize]`, `before_action :authenticate`, JWT verification |
| Data stores | Django ORM, SQLAlchemy, Prisma, Sequelize, JDBC, GORM, ActiveRecord, Eloquent, EF Core, Redis |
| External calls | `requests`, `fetch`, `axios`, `HttpClient`, `http.Get`, `RestTemplate`, `Net::HTTP`, Guzzle |
| Sensitive data | Variable names matching password/token/api\_key/credit\_card/ssn patterns |

The map enriches every downstream stage:

- **Triage** receives a compact `Asset context` block (entry point, auth status, nearby data stores/external calls) so the fast-tier model makes better TRUE/FALSE/NEEDS-DEEP decisions
- **Reachability** uses asset-map entry points to classify non-Python findings (previously only Python had call-graph-based reachability; others fell back to path heuristics)
- **Slice** appends an `ASSET_CONTEXT` block to the slice text for the deep reviewer
- **Report** includes an auto-generated **STRIDE threat model** section: attack surface summary, unguarded entry points table, STRIDE threat matrix, and high-risk paths (unguarded endpoints touching data stores or external calls)

## Repository layout

```
mantis/                       standalone CLI Python package
mantis/asset_patterns.py      regex patterns for asset map (entry points, auth, data stores, etc.)
mantis/assetmap.py            stage 0b: asset map scanner + query API
mantis/bm25.py                BM25 scorer for finding-to-entry-point linking
mantis/context_graph.py       optional tree-sitter call graph (typed edges, BFS reachability)
mantis/threatmodel.py         STRIDE threat model generator
mantis/resources/agents/      subagent definitions (model: + tier: frontmatter)
mantis/resources/commands/    slash command for MCP mode
mantis/resources/rules/       opengrep YAML rules (Semgrep schema) + pack specs + manifest
mantis/resources/scripts/     build_manifest.py, pack_compose.py, project_findings.py, asset_map.py
mantis/resources/checklists/  OWASP Testing Guide chapters for the deep-reviewer
mantis/resources/install.sh   install agents/commands into a target (MCP mode; ./install.sh wraps it)
setup.sh                      install opengrep + mantis CLI
doctor.sh                     verify install
CLAUDE.md                     conventions for future contributors / Claude sessions
```

Resources live under `mantis/` so they ship inside the wheel published to
PyPI. The CLI resolves them via `Path(__file__).parent/'resources'` and
falls back to a top-level layout for legacy installs.

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
| `native` | decompiled C/C++ vulns + malware patterns (chimera RE bridge) |

Compose a pack:

```bash
python3 mantis/resources/scripts/pack_compose.py mantis/resources/rules/packs/fast.yaml --as-args
opengrep $(python3 mantis/resources/scripts/pack_compose.py mantis/resources/rules/packs/fast.yaml --as-args) --json <target>
```

## Network & privacy

Findings stay local: no CI integration, no forge API calls, no telemetry or
upload of findings or source. `--fix` writes to a sibling git worktree, never the
working tree; reports live under `<target>/.mantis/runs/`.

Two kinds of outbound call exist: a once-per-day PyPI version check
(`MANTIS_NO_UPDATE_CHECK=1` to disable), and — when the `trivy`/`grype` SCA engines
run (they are part of the default engine set) — a vulnerability-database fetch. To
run fully offline: `--engines none` (OpenGrep only), restrict `--engines` to the
local engines (`bandit,gosec,njsscan,eslint-security,checkov`), or
`--engines-offline`.

Optional, off unless set: `MANTIS_HARUSPEX_URL` enables Haruspex triage ranking
(stage 5b), which POSTs each finding's rule id, path, message and an ~80-line
code window to that endpoint. It is intended for a loopback Haruspex instance;
pointing it at a remote host sends source off the machine.

## Auditing untrusted code

The audited repository is treated as hostile input.

- **No code from the target runs.** git is invoked with hooks and fsmonitor
  disabled. checkov runs from a private cwd and HOME, so a planted
  `.checkov.yaml` cannot load external checks. ESLint uses mantis's own config
  and formatter, never the target's.
- **Prompt injection.** Code sent to an LLM is wrapped in nonce-tagged
  delimiters that a comment cannot close. When the code contains text aimed at
  the reviewer ("false positive", "ignore previous instructions", hidden
  Unicode), a FALSE triage verdict is escalated to NEEDS-DEEP and a deep-review
  rejection is downgraded to partial.
- **Secrets.** Key-shaped values and quoted secret assignments are masked
  before a window or slice leaves the machine. A `--fix` patch whose context
  lines contain a live secret therefore fails to apply; rotate those by hand.
- **Report.** Scanner messages, LLM replies and repo paths are written as inert
  single-line Markdown: no forged headings, table rows or raw HTML.
- **MCP install.** `install.sh` grants its command allowlist only when every
  `.claude/sast-*` dir is one it installed; a pre-existing dir from the target
  is left untouched and no permissions are granted.

- **Scanner suppressions.** OpenGrep runs with `--disable-nosem`, so
  `nosemgrep` lines still reach triage, tagged `(nosemgrep in source)`. It also
  runs with `--x-ignore-semgrepignore-files`, because a planted `.semgrepignore`
  of `*` would otherwise empty the scan; OpenGrep's default vendored/test
  excludes are re-applied explicitly. Your own suppressions go in
  `.mantisignore`. The extra engines' markers (`# nosec` for bandit and gosec)
  are still honoured.

Standalone runs cache LLM replies for deterministic calls under
`~/.cache/mantis/llm` (keyed on model, prompts and parameters), so re-auditing an
unchanged tree costs no tokens. Sampling calls (ToAST) are never cached.
`--no-cache` bypasses it.

## Contributing

Read [CLAUDE.md](CLAUDE.md) — it documents YAML quoting gotchas, the
tier-vs-model split, the rule-pack workflow, and what *not* to add (CI
hooks, remote upload, hardcoded model names).

After editing rules, rebuild the manifest:

```bash
python3 mantis/resources/scripts/build_manifest.py
```

Commit the updated `mantis/resources/rules/_manifest.yaml` alongside the rule change.

`tests/test_rules_hygiene.py` guards the rule set: every file must pass
`opengrep --validate` (a file that fails is skipped whole at scan time), rule ids
must be unique, and every rule needs `category`, `cwe` and `confidence`. Behaviour
is pinned by fixtures under `tests/fixtures/rules/<case>/`: a `ruleid: a, b`
comment names exactly the rules that must fire on that line (or on the next line,
when the comment stands alone inside a multi-line pattern); unannotated lines must
stay quiet. Add a case to `_CASES` when you fix or add a rule.

### Releasing to PyPI

```bash
# 1. bump version in pyproject.toml
# 2. clean + build
rm -rf dist build mantis_sast.egg-info
pipx run build

# 3. inspect the wheel and metadata
pipx run twine check dist/*
unzip -l dist/mantis_sast-*.whl | tail -5      # confirm resources/ shipped

# 4. upload to TestPyPI first
pipx run twine upload --repository testpypi dist/*
pipx install --index-url https://test.pypi.org/simple/ \
             --pip-args "--extra-index-url https://pypi.org/simple" \
             mantis-sast
mantis --version

# 5. tag and upload to PyPI
git tag v0.1.0 && git push origin v0.1.0
pipx run twine upload dist/*
```

Use an API token (`__token__` as the username, the token as the password) stored in
`~/.pypirc` or `TWINE_PASSWORD` — never commit it.

## Praetor Integration

[Praetor](https://github.com/TyrusRC/praetor) drives mantis via `run_mantis()` for source-audit within a pentest engagement. Findings feed into praetor's save-finding pipeline and the engagement graph. The `sast_to_endpoint_risk` tool bridges mantis SAST findings to DAST targets — a source-level SQL injection in a controller maps to the HTTP endpoint praetor tests next.

```
praetor: run_mantis(path, mode='deep') → import results → sast_to_endpoint_risk → confirm_sqli on the endpoint
```

## License

[MIT](LICENSE)

## Acknowledgments

- **Architecture**: [AGHAST](https://www.bouncesecurity.com/blog/2026/04/14/introducing-aghast), [Slice](https://noperator.dev/posts/slice/), [Vulnhuntr](https://github.com/protectai/vulnhuntr), [Tree-of-AST (Black Hat USA 2025)](https://ruik.ai/)
- **Tooling**: [OpenGrep](https://github.com/opengrep/opengrep), [Semgrep](https://github.com/semgrep/semgrep), [litellm](https://github.com/BerriAI/litellm)
- **Standards**: [OWASP MASVS](https://mas.owasp.org/MASVS/), [MASTG](https://mas.owasp.org/MASTG/), [OWASP Top 10:2025](https://owasp.org/Top10/), [LLM Top 10:2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
