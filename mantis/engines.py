"""Multi-engine SAST layer.

Mantis's OpenGrep pass stays primary; these engines run additional specialised
tools (bandit/gosec/njsscan/eslint-security/checkov local; trivy/grype fetch a
vuln DB) and map their SARIF into mantis's `scan.Finding`, so the findings flow
through the existing dedup -> suppress -> SARIF -> fail-on -> triage pipeline.
Engines run by default when installed (`--engines none` opts out); a
missing/failed engine is skipped, never fatal.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from mantis.scan import Finding

_LEVEL_SEV = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}


def _sev_from_score(n: float) -> str:
    if n >= 7.0:
        return "ERROR"
    if n >= 4.0:
        return "WARNING"
    return "INFO"


def sarif_to_findings(sarif: dict, engine: str) -> list[Finding]:
    """Map a SARIF log into mantis Findings (tolerant of missing fields)."""
    out: list[Finding] = []
    for run in sarif.get("runs", []) or []:
        rules = {r.get("id"): r for r in
                 ((run.get("tool", {}) or {}).get("driver", {}) or {}).get("rules", []) or []
                 if isinstance(r, dict) and r.get("id")}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId")
            rule = rules.get(rid, {})
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            sev = None
            ss = props.get("security-severity")
            if ss is not None:
                try:
                    sev = _sev_from_score(float(ss))
                except (TypeError, ValueError):
                    sev = None
            if sev is None:
                sev = _LEVEL_SEV.get(res.get("level") or "warning", "WARNING")
            path, sl, el = "", 0, 0
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0] or {}).get("physicalLocation", {}) or {}
                path = (phys.get("artifactLocation") or {}).get("uri") or ""
                region = phys.get("region") or {}
                sl = region.get("startLine") or 0
                el = region.get("endLine") or sl
            cwe = props.get("cwe") or []
            if isinstance(cwe, str):
                cwe = [cwe]
            out.append(Finding(
                rule_id=rid or f"{engine}-finding", severity=sev, confidence="MEDIUM",
                path=path, start_line=sl, end_line=el,
                message=(res.get("message") or {}).get("text") or "",
                metadata={"engine": engine, "cwe": list(cwe), "security_severity": ss},
                raw=res,
            ))
    return out


@dataclass
class EngineResult:
    engine: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


class Engine:
    name: str
    binary: str
    languages: tuple[str, ...] = ("*",)
    needs_network: bool = False
    supports_sarif: bool = True

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def command(self, tree: str, out: str) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def parse_native(self, stdout: str) -> list[Finding]:
        return []

    def env(self) -> dict | None:
        return None

    def run(self, tree: str) -> EngineResult:
        out = tempfile.NamedTemporaryFile(suffix=".sarif", delete=False).name
        try:
            res = subprocess.run(self.command(tree, out), capture_output=True,
                                 text=True, timeout=1800, env=self.env())
        except Exception as exc:  # noqa: BLE001 - any run failure -> recorded error
            Path(out).unlink(missing_ok=True)
            return EngineResult(self.name, error=f"{type(exc).__name__}: {exc}")
        try:
            if not self.supports_sarif:
                return EngineResult(self.name, self.parse_native(res.stdout))
            p = Path(out)
            if p.exists() and p.stat().st_size > 0:
                return EngineResult(self.name,
                                    sarif_to_findings(json.loads(p.read_text()), self.name))
            if res.returncode != 0:
                return EngineResult(
                    self.name,
                    error=(res.stderr or "").strip()[:300]
                    or f"{self.name} rc={res.returncode}, no SARIF")
            return EngineResult(self.name, [])
        except json.JSONDecodeError:
            return EngineResult(self.name, error="invalid SARIF output")
        finally:
            Path(out).unlink(missing_ok=True)


class BanditEngine(Engine):
    name = "bandit"; binary = "bandit"; languages = ("python",)
    def command(self, tree, out): return ["bandit", "-r", tree, "-f", "sarif", "-o", out]


class GosecEngine(Engine):
    name = "gosec"; binary = "gosec"; languages = ("go",)
    def command(self, tree, out):
        return ["gosec", "-no-fail", "-fmt", "sarif", "-out", out, tree + "/..."]


class NjsscanEngine(Engine):
    name = "njsscan"; binary = "njsscan"; languages = ("javascript", "typescript")
    def command(self, tree, out): return ["njsscan", "--sarif", "-o", out, tree]


_ESLINT_CONFIG = Path(__file__).parent / "resources" / "engines" / "eslint.config.cjs"


def _node_modules_root(binary: str) -> Path | None:
    """node_modules dir that owns `binary` (e.g. the global npm root for a global eslint)."""
    found = shutil.which(binary)
    if not found:
        return None
    for parent in Path(found).resolve().parents:
        if parent.name == "node_modules":
            return parent
    return None


class EslintSecurityEngine(Engine):
    """Runs only with Mantis's own config, formatter and plugin.

    The audited tree's eslint.config.* is JavaScript and `-f <name>` resolves a
    formatter package from cwd, so either would execute code from the target.
    """
    name = "eslint-security"; binary = "eslint"; languages = ("javascript", "typescript")

    def _formatter(self) -> Path | None:
        root = _node_modules_root(self.binary)
        pkg = root / "@microsoft" / "eslint-formatter-sarif" if root else None
        if not pkg or not (pkg / "package.json").is_file():
            return None
        main = json.loads((pkg / "package.json").read_text()).get("main") or "sarif.js"
        return pkg / main

    def available(self) -> bool:
        root = _node_modules_root(self.binary)
        return bool(root and (root / "eslint-plugin-security").is_dir() and self._formatter())

    def env(self) -> dict:
        root = _node_modules_root(self.binary)
        return {**os.environ, "NODE_PATH": str(root)} if root else dict(os.environ)

    def command(self, tree, out):
        return ["eslint", "-c", str(_ESLINT_CONFIG), "-f", str(self._formatter() or "@microsoft/eslint-formatter-sarif"),
                "-o", out, tree]


class CheckovEngine(Engine):
    name = "checkov"; binary = "checkov"
    languages = ("terraform", "kubernetes", "docker", "yaml")

    def command(self, tree, out):
        # `--directory=<tree>` as ONE argv item: checkov only searches the scanned
        # dir for .checkov.yaml when -d/--directory is a separate argument, and that
        # file's external-checks-dir executes Python from the audited tree.
        return ["checkov", f"--directory={tree}", "-o", "sarif",
                "--output-file-path", out, "--compact", "--quiet"]

    def run(self, tree: str) -> EngineResult:
        # Private dir as cwd + HOME closes the other two .checkov.yaml lookups and
        # catches the SARIF file (checkov writes it to a dir, not stdout).
        with tempfile.TemporaryDirectory(prefix="mantis-checkov-") as work:
            try:
                res = subprocess.run(self.command(tree, work), cwd=work,
                                     env={**os.environ, "HOME": work},
                                     capture_output=True, text=True, timeout=1800)
            except Exception as exc:  # noqa: BLE001 - any run failure -> recorded error
                return EngineResult(self.name, error=f"{type(exc).__name__}: {exc}")
            sarifs = sorted(Path(work).glob("*.sarif"))
            if not sarifs:
                if res.returncode not in (0, 1):  # 1 = checks failed
                    return EngineResult(self.name, error=(res.stderr or "").strip()[:300]
                                        or f"checkov rc={res.returncode}, no SARIF")
                return EngineResult(self.name, [])
            try:
                findings = sarif_to_findings(json.loads(sarifs[0].read_text()), self.name)
            except json.JSONDecodeError:
                return EngineResult(self.name, error="invalid SARIF output")
            for f in findings:
                f.path = _rebase_checkov_uri(f.path, tree)
            return EngineResult(self.name, findings)


def _rebase_checkov_uri(uri: str, tree: str) -> str:
    """checkov emits URIs relative to the filesystem root minus its first part
    (`/tmp/x/main.tf` -> `x/main.tf`); anchor them back onto the scanned tree."""
    if not uri or os.path.isabs(uri):
        return uri
    root = Path(tree).resolve()
    parts = Path(uri).parts
    for i in range(len(root.parts)):
        tail = root.parts[i:]
        if parts[:len(tail)] == tail:
            return str(root.joinpath(*parts[len(tail):]))
    return str(root / uri)


class TrivyEngine(Engine):
    name = "trivy"; binary = "trivy"; languages = ("*",); needs_network = True
    offline = False
    def command(self, tree, out):
        cmd = ["trivy", "fs", "--quiet", "--format", "sarif",
               "--scanners", "vuln,misconfig"]
        if self.offline:
            cmd.append("--offline-scan")
        return cmd + ["--output", out, tree]


class GrypeEngine(Engine):
    name = "grype"; binary = "grype"; languages = ("*",); needs_network = True
    def command(self, tree, out):
        return ["grype", "dir:" + tree, "-o", "sarif", "--file", out]


ENGINES: list[type[Engine]] = [
    BanditEngine, GosecEngine, NjsscanEngine, EslintSecurityEngine,
    CheckovEngine, TrivyEngine, GrypeEngine,
]



_LANG_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript",
             ".mjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
             ".go": "go", ".tf": "terraform"}
_SKIP = {".git", "node_modules", "vendor", "build", "dist", ".venv", "venv"}


def detect_languages(tree) -> set[str]:
    """Cheap language/ecosystem detection for the `auto` engine selection."""
    root = Path(tree)
    langs: set[str] = set()
    seen = 0
    for pth in root.rglob("*"):
        if any(part in _SKIP for part in pth.parts) or not pth.is_file():
            continue
        seen += 1
        if seen > 100000:
            break
        langs.add(_LANG_EXT.get(pth.suffix.lower(), ""))
        if pth.name in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"):
            langs.add("python")
        elif pth.name == "package.json":
            langs.add("javascript")
        elif pth.name == "go.mod":
            langs.add("go")
        elif pth.name == "Dockerfile":
            langs.add("docker")
        elif pth.suffix.lower() in (".yaml", ".yml"):
            langs.add("yaml")
    langs.discard("")
    return langs


_OFF = {"none", "off", "", "false", "0", "no"}


def _normalize(requested):
    """None -> default ON ('auto'); an explicit off value -> None; else pass through."""
    if requested is None:
        return "auto"
    if isinstance(requested, str):
        return None if requested.strip().lower() in _OFF else requested
    if not requested:            # empty list
        return None
    return list(requested)


def select(requested, languages, *, classes=None):
    """Return (list[Engine], skipped_names). Engines run BY DEFAULT: `requested`
    None/"auto" = every installed engine whose languages match the tree (trivy/grype
    included); "all" = every installed engine (ignore language); an explicit csv/list
    = just those (installed); "none"/"off"/[] = disabled."""
    pool = [c() if isinstance(c, type) else c
            for c in (classes if classes is not None else ENGINES)]
    req = _normalize(requested)
    if req is None:
        return [], []
    is_auto = req == "auto"
    is_all = req == "all"
    names = None
    if not (is_auto or is_all):
        names = ({n.strip() for n in req.split(",")}
                 if isinstance(req, str) else set(req))
    chosen, skipped = [], []
    langs = set(languages or ())
    for e in pool:
        if names is not None and e.name not in names:
            continue
        if is_auto and not ("*" in e.languages or set(e.languages) & langs):
            continue  # "auto" is language-gated; "all" and explicit names are not
        if not e.available():
            skipped.append(e.name)
            continue
        chosen.append(e)
    return chosen, skipped


def run_selected(tree, languages, requested=None, *, offline: bool = False, classes=None):
    """Run the selected engines over `tree`; return (findings, errors, skipped)."""
    chosen, skipped = select(requested, languages, classes=classes)
    findings: list[Finding] = []
    errors: list[str] = []
    for e in chosen:
        if offline and hasattr(e, "offline"):
            e.offline = True
        r = e.run(tree)
        if r.error:
            errors.append(f"{e.name}: {r.error}")
        findings.extend(r.findings)
    return findings, errors, skipped
