"""Per-file SAST result cache.

Cache key: (pack_hash, scanner_version, file_hash). Each entry stores the
findings the scanner reported for one file. Re-running a scan with the
same rule pack and unchanged file contents reuses the cached findings;
only changed files round-trip through the scanner.

Cache layout: ~/.cache/mantis/sast/<scanner>/<pack_hash[:16]>/<file_hash>.json
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from mantis.scan import Finding, ScanOutput, run_scan


_SCANNABLE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".swift", ".m", ".mm",
    ".go", ".cs", ".php", ".rb",
    ".dart", ".sh", ".bash",
    ".yaml", ".yml", ".xml", ".json",
}
_SKIP_DIRS = {
    "node_modules", "vendor", "build", "dist", "target",
    ".git", ".venv", "venv", "__pycache__", ".cache",
    ".mantis",
}


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mantis" / "sast"


def hash_pack(rule_files: list[Path]) -> str:
    h = hashlib.sha256()
    for rf in sorted(rule_files, key=lambda p: str(p)):
        try:
            h.update(rf.name.encode("utf-8"))
            h.update(b"\0")
            h.update(rf.read_bytes())
            h.update(b"\0\0")
        except OSError:
            continue
    return h.hexdigest()


def scanner_version(sast_bin: str) -> str:
    try:
        out = subprocess.run([sast_bin, "--version"], capture_output=True,
                             text=True, timeout=5).stdout.strip()
        return out.splitlines()[0] if out else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "0" * 64
    return h.hexdigest()


def enumerate_scannable(target: Path) -> list[Path]:
    out: list[Path] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        rp = Path(root)
        for name in files:
            ext = Path(name).suffix.lower()
            if ext in _SCANNABLE_EXT:
                out.append(rp / name)
    return out


def _entry_path(scanner: str, pack_hash: str, file_hash: str) -> Path:
    return _cache_root() / scanner / pack_hash[:16] / f"{file_hash}.json"


def _load_entry(p: Path) -> list[Finding] | None:
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    out: list[Finding] = []
    for d in data.get("findings", []):
        try:
            out.append(Finding(
                rule_id=d["rule_id"], severity=d["severity"],
                confidence=d["confidence"], path=d["path"],
                start_line=d["start_line"], end_line=d["end_line"],
                message=d["message"], metadata=d.get("metadata") or {},
                raw=d.get("raw") or {},
            ))
        except KeyError:
            continue
    return out


def _save_entry(p: Path, findings: list[Finding]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {"findings": [asdict(f) for f in findings]}
    try:
        p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def run_scan_cached(
    target: Path,
    rule_files: list[Path],
    sast_bin: str,
    *,
    paths: list[Path] | None = None,
    severities: tuple[str, ...] = ("ERROR", "WARNING"),
    timeout_seconds: int = 1800,
    use_cache: bool = True,
) -> tuple[ScanOutput, dict[str, int]]:
    """Like `run_scan` but with a per-file content-addressed cache.

    Returns (ScanOutput, stats) where stats reports hits/misses/scanned.
    `use_cache=False` falls through to the plain scanner (still returns stats
    for a uniform call site).
    """
    if paths is None:
        paths = enumerate_scannable(target)
    paths = [p.resolve() for p in paths if p.is_file()]

    stats = {"files": len(paths), "hits": 0, "misses": 0, "scanned": 0}

    if not use_cache or not paths:
        scan_out = run_scan(target, rule_files, sast_bin, severities, timeout_seconds,
                            paths=paths if paths else None)
        stats["scanned"] = len(paths)
        return scan_out, stats

    pack_h = hash_pack(rule_files)
    scanner = Path(sast_bin).name
    sv = scanner_version(sast_bin)
    # fold scanner version into pack hash so a scanner upgrade invalidates entries
    pack_h = hashlib.sha256((pack_h + sv).encode("utf-8")).hexdigest()

    cached: list[Finding] = []
    missed: list[Path] = []
    miss_paths_str: set[str] = set()
    for p in paths:
        fh = hash_file(p)
        entry = _entry_path(scanner, pack_h, fh)
        loaded = _load_entry(entry)
        if loaded is None:
            missed.append(p)
            miss_paths_str.add(str(p))
            stats["misses"] += 1
        else:
            cached.extend(loaded)
            stats["hits"] += 1

    fresh = ScanOutput()
    if missed:
        fresh = run_scan(target, rule_files, sast_bin, severities, timeout_seconds,
                         paths=missed)
        stats["scanned"] = len(missed)

        by_path: dict[str, list[Finding]] = {}
        for f in fresh.findings:
            fp = Path(f.path)
            if not fp.is_absolute():
                fp = (target / fp).resolve()
            else:
                fp = fp.resolve()
            by_path.setdefault(str(fp), []).append(f)
        for p in missed:
            findings_for_file = by_path.get(str(p), [])
            fh = hash_file(p)
            _save_entry(_entry_path(scanner, pack_h, fh), findings_for_file)

    combined = ScanOutput(
        findings=cached + fresh.findings,
        errors=list(fresh.errors),
    )
    return combined, stats
