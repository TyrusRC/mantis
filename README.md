# mantis

Hybrid SAST + LLM toolkit for local code-security audits.

758 OpenGrep rules across 10 languages (Python, JavaScript/TypeScript, Java, Kotlin, Swift, Go, Ruby, PHP, C#, Rust, Dart, C/C++). Covers full OWASP Web Top 10 2025 (A01--A10), OWASP LLM Top 10, mobile (Android + iOS + Flutter + React Native), IaC (Terraform, Dockerfile, Kubernetes), cloud SDK misuse (AWS/GCP/Azure), SCA, secrets, taint analysis, and native C/C++ binary analysis. 5 WSTG checklists.

Stage 0b auto-generates a **STRIDE threat model** and **asset map** (entry points, auth boundaries, data stores, external calls, sensitive data) that enriches every downstream stage. A **BM25 linker** connects findings to their most-relevant entry point when call-graph tracing falls short. An LLM reasons on the slices the scanner flags. Runs as a Claude Code slash command, or as a standalone CLI against any provider. Local only.

Tested against five deliberately vulnerable apps (96 total findings, SAST-only, no LLM):

| Target | Stack | Findings | Key catches |
|---|---|---|---|
| [Commando-X/vuln-bank](https://github.com/Commando-X/vuln-bank) | Flask/PostgreSQL | 69 | SQLi (f-string + execute_query + taint), JWT none/hardcoded, SSRF, CORS wildcard, plaintext passwords, Flask debug |
| [CrowdStrike/vulnapp](https://github.com/CrowdStrike/vulnapp) | Go net/http | 8 | OS command injection (variable shell binary), path traversal, K8s run-as-root, SSRF |
| [josh2073/vulnapp](https://github.com/josh2073/vulnapp) | Flask/SQLite | 6 | Hardcoded secret key, 4x SQLi (taint), Flask debug mode |
| [anasachoury/VulnApp](https://github.com/anasachoury/VulnApp) | Flutter/Dart | 4 | SharedPreferences sensitive storage, deeplink no validation, print() data leak, exported component |
| [appsecco/vulnerable-apps](https://github.com/appsecco/vulnerable-apps) | Python2 + Node.js | 9 | eval() RCE (Node + Python), pickle deserialization, urllib SSRF, remote file inclusion |

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
/audit [path] [mode] [--fix] [--lite] [focus:<area>]
```

| Invocation | Behavior |
|---|---|
| `/audit` | auto-detect stack, full pipeline |
| `/audit quick` | ERROR severity, HIGH confidence, triage only |
| `/audit deep` | every rule, full pipeline |
| `/audit bugbounty` | exploit-first, gates on entrypoint reachability |
| `/audit cve` | SCA / lockfile dependency scan only |
| `/audit mobile` \| `web` \| `desktop` \| `llm` | scope to a single rule pack |
| `/audit secrets` \| `iac` \| `cloud` | hardcoded creds / Terraform+Dockerfile+K8s / AWS-GCP-Azure SDK misuse |
| `/audit deep focus:auth` | full pipeline, deep review only on auth-tagged findings |
| `/audit --fix` | apply patches in a worktree, re-verify |
| `/audit --lite` | skip slicing and deep review |

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
| `--no-cache` | bypass the per-file SAST result cache |
| `--skip-llm` | SAST + inventory only; no provider needed |
| `--lite` | skip slicing + deep review |
| `--fix` | apply patches in a worktree, re-verify |
| `--fail-on low\|medium\|high\|critical` | exit non-zero if any unsuppressed finding is at or above this severity (pre-commit / local gate) |
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
                  auto-generated STRIDE threat model in the report
1   static wide   opengrep with the selected pack
2   SCA           lockfile dependency-CVE rules
3   secrets       high-confidence secrets pack
4   deobf gate    route minified/packed files to the deobfuscator
5   triage        fast tier per finding (single or dual chain) — now receives
                  asset context (nearest entry point, auth status, nearby stores)
6   slice         depth-limited callgraph, entrypoint reachability (asset map
                  extends reachability to non-Python languages); BM25 fallback
                  links findings to entry points when grep-based callers miss
7   deep review   deep tier on reachable TRUE / NEEDS-DEEP slices — slice text
                  includes ASSET_CONTEXT block
8   fix           patch in worktree, re-run scanner   (only with --fix)
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
mantis/threatmodel.py         STRIDE threat model generator
mantis/resources/agents/      subagent definitions (model: + tier: frontmatter)
mantis/resources/commands/    slash command for MCP mode
mantis/resources/rules/       opengrep YAML rules (Semgrep schema) + pack specs + manifest
mantis/resources/scripts/     build_manifest.py, pack_compose.py
mantis/resources/checklists/  OWASP Testing Guide chapters for the deep-reviewer
install.sh                    install agents/commands into a target (MCP mode)
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

## Contributing

Read [CLAUDE.md](CLAUDE.md) — it documents YAML quoting gotchas, the
tier-vs-model split, the rule-pack workflow, and what *not* to add (CI
hooks, remote upload, hardcoded model names).

After editing rules, rebuild the manifest:

```bash
python3 mantis/resources/scripts/build_manifest.py
```

Commit the updated `mantis/resources/rules/_manifest.yaml` alongside the rule change.

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
