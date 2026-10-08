"""Multi-engine SAST layer.

Mantis's OpenGrep pass stays primary; these engines run additional specialised
tools (bandit/gosec/njsscan/eslint-security/checkov local, trivy/grype opt-in) and
map their SARIF into mantis's `scan.Finding`, so the findings flow through the
existing dedup -> suppress -> SARIF -> fail-on -> triage pipeline. Engines are
opt-in and default-off; a missing/failed engine is skipped, never fatal.
"""

from __future__ import annotations

import json
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

    def run(self, tree: str) -> EngineResult:
        out = tempfile.NamedTemporaryFile(suffix=".sarif", delete=False).name
        try:
            res = subprocess.run(self.command(tree, out), capture_output=True,
                                 text=True, timeout=1800)
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


class EslintSecurityEngine(Engine):
    name = "eslint-security"; binary = "eslint"; languages = ("javascript", "typescript")
    def command(self, tree, out):
        return ["eslint", tree, "-f", "@microsoft/sarif", "-o", out]


class CheckovEngine(Engine):
    name = "checkov"; binary = "checkov"
    languages = ("terraform", "kubernetes", "docker", "yaml")
    supports_sarif = False  # checkov --output-file-path is a dir; use stdout SARIF
    def command(self, tree, out):
        return ["checkov", "-d", tree, "-o", "sarif", "--compact", "--quiet"]
    def parse_native(self, stdout):
        text = (stdout or "").strip(); i = text.find("{")
        if i < 0:
            return []
        try:
            data = json.loads(text[i:])
        except ValueError:
            return []
        return sarif_to_findings(data, self.name)


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


def select(requested, languages, *, allow_network: bool = False, classes=None):
    """Return (list[Engine], skipped_names). `requested`: None/[] off; "auto" =
    installed engines whose languages intersect the tree (network excluded); "all" =
    every installed engine (network only if allow_network); or an explicit name list/
    csv (those engines regardless of language; an explicitly-named network engine is
    its own opt-in)."""
    pool = [c() if isinstance(c, type) else c
            for c in (classes if classes is not None else ENGINES)]
    if not requested:
        return [], []
    is_auto = requested == "auto"
    is_all = requested == "all"
    names = None
    if not (is_auto or is_all):
        names = ({n.strip() for n in requested.split(",")}
                 if isinstance(requested, str) else set(requested))
    chosen, skipped = [], []
    langs = set(languages or ())
    for e in pool:
        if names is not None and e.name not in names:
            continue
        if is_auto:
            if not ("*" in e.languages or set(e.languages) & langs):
                continue
            if e.needs_network:
                continue
        elif is_all:
            if e.needs_network and not allow_network:
                continue
        # explicit names: run regardless of language; a named network engine is allowed.
        if not e.available():
            skipped.append(e.name)
            continue
        chosen.append(e)
    return chosen, skipped


def run_selected(tree, languages, requested, *, allow_network: bool = True,
                 offline: bool = False, classes=None):
    """Run the selected engines over `tree`; return (findings, errors, skipped)."""
    chosen, skipped = select(requested, languages, allow_network=allow_network,
                             classes=classes)
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
