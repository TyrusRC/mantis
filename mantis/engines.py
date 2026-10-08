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
