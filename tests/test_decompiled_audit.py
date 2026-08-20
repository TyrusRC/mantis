"""Auditing decompiled / reverse-engineered source (the chimera integration).

A decompiled tree (jadx Java/Kotlin, Ghidra pseudo-C) has source files but no
build.gradle / lockfile / manifest, so normal inventory reduces it to the
`fast` pack. `decompiled=True` detects the stack from extensions alone, and an
explicit `packs=[...]` override lets a caller pick packs directly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mantis.cli import REPO_ROOT
from mantis.inventory import (
    known_packs, packs_for, resolve_pack_override, take_inventory, validate_packs,
)

_PACKS_DIR = REPO_ROOT / "rules" / "packs"


# ---- inventory-level (pure, no scanner) -----------------------------------

def test_bare_java_without_gradle_is_fast_normally(tmp_path):
    (tmp_path / "App.java").write_text("class App {}")
    inv = take_inventory(tmp_path)
    assert inv.stack.detected == set()
    assert inv.packs == ["fast"]


def test_decompiled_bare_java_selects_real_packs(tmp_path):
    (tmp_path / "App.java").write_text("class App {}")
    inv = take_inventory(tmp_path, decompiled=True)
    assert "jvm" in inv.stack.detected
    assert "web" in inv.packs and "secrets" in inv.packs
    assert inv.packs != ["fast"]


def test_decompiled_recognises_native_c(tmp_path):
    (tmp_path / "sub.c").write_text("int main(){return 0;}")
    inv = take_inventory(tmp_path, decompiled=True)
    assert "native" in inv.stack.detected
    # No C/C++ rule pack exists, but secrets still runs over the pseudo-C.
    assert inv.packs == ["secrets"]


def test_decompiled_swift_is_ios(tmp_path):
    (tmp_path / "V.swift").write_text("import Foundation")
    inv = take_inventory(tmp_path, decompiled=True)
    assert "ios" in inv.stack.detected


def test_packs_for_explicit_beats_mode_and_inventory(tmp_path):
    inv = take_inventory(tmp_path)  # empty -> ['fast']
    got = packs_for("web", inv, explicit=["mobile-android", "secrets", "secrets"])
    assert got == ["mobile-android", "secrets"]  # deduped, order preserved


def test_validate_packs_flags_unknown_only(tmp_path):
    assert validate_packs(["secrets", "nope"], _PACKS_DIR) == ["nope"]
    assert validate_packs(["secrets", "web"], _PACKS_DIR) == []
    assert "secrets" in known_packs(_PACKS_DIR)


def test_resolve_pack_override_lowercases_and_dedups():
    # Case-normalised (parity with how `mode` is lowercased) and deduped.
    assert resolve_pack_override(["Secrets", "WEB", "secrets"], _PACKS_DIR) == \
        ["secrets", "web"]


def test_resolve_pack_override_rejects_unknown():
    with pytest.raises(ValueError, match="unknown pack"):
        resolve_pack_override(["nope"], _PACKS_DIR)


# ---- api-level (fake scanner on PATH) -------------------------------------

def _fake_sast(tmp_path, results):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "opengrep"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        "if '--validate' in sys.argv:\n"
        "    sys.exit(0)\n"
        f"print(json.dumps({{'results': {results!r}}}))\n"
    )
    fake.chmod(0o755)
    return bin_dir


_FINDING = [{
    "check_id": "secret-x", "path": "App.java",
    "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9},
    "extra": {"severity": "ERROR", "message": "hardcoded secret",
              "metadata": {"confidence": "HIGH"}},
}]


@pytest.fixture
def decompiled_target(tmp_path, monkeypatch):
    bin_dir = _fake_sast(tmp_path, _FINDING)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    monkeypatch.delenv("MANTIS_SAST_BIN", raising=False)
    proj = tmp_path / "decomp"
    proj.mkdir()
    (proj / "App.java").write_text('class App { String k = "AKIA..."; }')
    return proj


def test_audit_packs_override_runs_and_returns(decompiled_target):
    from mantis import audit
    findings = audit(str(decompiled_target), packs=["secrets", "mobile-android"])
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "secret-x"


def test_audit_decompiled_flag_runs(decompiled_target):
    from mantis import audit
    # Would be the `fast` pack without decompiled=True; here it scans as jvm.
    assert len(audit(str(decompiled_target), decompiled=True)) == 1


def test_audit_rejects_mode_and_packs_together(decompiled_target):
    from mantis import audit
    with pytest.raises(ValueError, match="either"):
        audit(str(decompiled_target), mode="web", packs=["secrets"])


def test_audit_rejects_unknown_pack(decompiled_target):
    from mantis import audit
    with pytest.raises(ValueError, match="unknown pack"):
        audit(str(decompiled_target), packs=["nonexistent-pack"])
