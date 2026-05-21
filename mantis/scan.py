"""Stage 1: invoke the SAST binary and parse its JSON output.

The scanner is invoked with one ``--config <file>`` per rule file. Pack
spec files (whose paths are produced by ``scripts/pack_compose.py``) are
deduplicated and turned into ``Path`` instances so paths with spaces
survive the subprocess call (we never split() a shell line).

``--severity`` is passed once per level — both Semgrep and OpenGrep
accept the flag as repeatable. Their behavior on the comma-list form
(``--severity ERROR,WARNING``) varies across versions.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    severity: str
    confidence: str
    path: str
    start_line: int
    end_line: int
    message: str
    metadata: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.rule_id, self.path, self.start_line)

    @property
    def id(self) -> str:
        """Canonical finding identifier used as a join key across stages."""
        return f"{self.rule_id}@{self.path}:{self.start_line}"


class ScanError(Exception):
    pass


@dataclass
class ScanOutput:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def compose_pack_files(pack_specs: list[str], scripts_dir: Path) -> list[Path]:
    """Run pack_compose.py for each pack name; return the deduplicated rule files."""
    composer = scripts_dir / "pack_compose.py"
    if not composer.is_file():
        raise ScanError(f"pack composer not found: {composer}")
    repo_root = scripts_dir.parent
    seen: set[Path] = set()
    out: list[Path] = []
    for spec in pack_specs:
        spec_path = repo_root / "rules" / "packs" / f"{spec}.yaml"
        if not spec_path.is_file():
            raise ScanError(f"pack spec not found: {spec_path}")
        result = subprocess.run(
            [sys.executable, str(composer), str(spec_path)],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise ScanError(
                f"pack_compose failed for {spec!r}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            p = (repo_root / line).resolve()
            if p in seen:
                continue
            seen.add(p)
            out.append(p)
    return out


# Backwards-compat alias for tests / older callers expecting the previous API.
def compose_pack_args(pack_specs: list[str], scripts_dir: Path) -> list[Path]:
    return compose_pack_files(pack_specs, scripts_dir)


_VALIDATE_CACHE: dict[tuple[str, Path], bool] = {}


def validate_rule_file(sast_bin: str, path: Path, timeout: int = 30) -> bool:
    """Return True if the scanner accepts the rule file. Cached per (bin, path)."""
    key = (sast_bin, path.resolve())
    if key in _VALIDATE_CACHE:
        return _VALIDATE_CACHE[key]
    try:
        res = subprocess.run(
            [sast_bin, "--quiet", "--validate", "--config", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        ok = res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        ok = False
    _VALIDATE_CACHE[key] = ok
    return ok


def filter_valid_rule_files(rule_files: list[Path], sast_bin: str) -> tuple[list[Path], list[Path]]:
    """Split rule files into (valid, invalid) using the scanner's own validator."""
    valid: list[Path] = []
    invalid: list[Path] = []
    for f in rule_files:
        if validate_rule_file(sast_bin, f):
            valid.append(f)
        else:
            invalid.append(f)
    return valid, invalid


def run_scan(
    target: Path,
    rule_files: list[Path],
    sast_bin: str,
    severities: tuple[str, ...] = ("ERROR", "WARNING"),
    timeout_seconds: int = 1800,
) -> ScanOutput:
    if not rule_files:
        raise ScanError("no rule files; pack composition produced empty result")

    cmd: list[str] = [sast_bin, "--quiet"]
    for f in rule_files:
        cmd.extend(["--config", str(f)])
    cmd.append("--json")
    for sev in severities:
        cmd.extend(["--severity", sev])
    cmd.append(str(target))

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanError(f"{sast_bin} timed out after {timeout_seconds}s") from e
    except FileNotFoundError as e:
        raise ScanError(f"{sast_bin} not found on PATH") from e

    if result.returncode >= 2 and not result.stdout.strip():
        raise ScanError(
            f"{sast_bin} failed (rc={result.returncode}): {result.stderr.strip()[:500]}"
        )

    return parse_scan_output(result.stdout)


def parse_scan_output(stdout: str) -> ScanOutput:
    if not stdout.strip():
        return ScanOutput()
    # Some scanners (e.g. opengrep in non-quiet mode) prepend a status panel
    # before the JSON object. Strip everything before the first '{'.
    raw = stdout
    brace = raw.find("{")
    if brace > 0:
        raw = raw[brace:]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ScanError(f"could not parse scanner JSON output: {e}") from e

    out = ScanOutput()
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        out.findings.append(Finding(
            rule_id=r.get("check_id") or "unknown",
            severity=str(extra.get("severity") or meta.get("severity") or "INFO").upper(),
            confidence=str(meta.get("confidence") or "UNKNOWN").upper(),
            path=r.get("path") or "",
            start_line=int((r.get("start") or {}).get("line") or 0),
            end_line=int((r.get("end") or {}).get("line") or 0),
            message=str(extra.get("message") or "").strip(),
            metadata=meta,
            raw=r,
        ))

    # Surface scanner-level errors so the runner can decide what to do.
    for err in data.get("errors") or []:
        if isinstance(err, dict):
            msg = err.get("message") or err.get("long_msg") or err.get("type") or "unknown error"
            out.errors.append(str(msg)[:400])
        elif isinstance(err, str):
            out.errors.append(err[:400])
    return out


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    out: list[Finding] = []
    for f in findings:
        if f.key in seen:
            continue
        seen.add(f.key)
        out.append(f)
    return out
