"""MCP-mode helper scripts and prompt markers that the installed /audit relies on."""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from mantis.scan import compose_pack_files

RES = Path(__file__).resolve().parent.parent / "mantis" / "resources"
SCRIPTS = RES / "scripts"
PACKS = RES / "rules" / "packs"


def _compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "pack_compose.py"), *args],
        capture_output=True, text=True, check=True, cwd="/",
    )


def test_pack_compose_prints_absolute_existing_paths_from_any_cwd():
    lines = _compose(str(PACKS / "taint.yaml")).stdout.splitlines()
    assert lines
    for line in lines:
        p = Path(line)
        assert p.is_absolute() and p.is_file(), line


def test_pack_compose_unions_specs_without_duplicates():
    one = _compose(str(PACKS / "taint.yaml")).stdout.splitlines()
    both = _compose(str(PACKS / "taint.yaml"), str(PACKS / "fast.yaml")).stdout.splitlines()
    assert len(both) == len(set(both))
    assert set(one) <= set(both)


def test_pack_compose_as_args_round_trips_through_shell_quoting():
    files = _compose(str(PACKS / "taint.yaml")).stdout.splitlines()
    args = shlex.split(_compose(str(PACKS / "taint.yaml"), "--as-args").stdout)
    assert args[0::2] == ["--config"] * (len(args) // 2)
    assert args[1::2] == [f for f in files if f]


def test_scan_compose_pack_files_accepts_absolute_lines():
    out = compose_pack_files(["taint"], SCRIPTS)
    assert out and all(p.is_file() for p in out)


def test_project_findings_strips_config_path_prefix(tmp_path):
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({
        "results": [{
            "check_id": "claude.sast-rules.web.web-a05-flask-debug-mode",
            "path": "app.py", "start": {"line": 28},
            "extra": {"severity": "ERROR", "message": "line one\n  line two"},
        }],
        "errors": [{"type": "InvalidRuleSchemaError", "message": "bad\nrule"}],
    }))
    out = subprocess.run(
        [sys.executable, str(SCRIPTS / "project_findings.py"), str(scan)],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert out == [
        "# results=1 errors=1",
        "ERR | InvalidRuleSchemaError | bad rule",
        "f1 | web-a05-flask-debug-mode | app.py:28 | ERROR | line one line two",
    ]


def test_mcp_only_markers_are_balanced():
    for md in list((RES / "agents").glob("*.md")) + list((RES / "commands").glob("*.md")):
        tags = re.findall(r"^<!-- (/?)mcp-only -->$", md.read_text(), flags=re.M)
        assert tags == ["", "/"] * (len(tags) // 2), f"{md.name}: unbalanced mcp-only markers"
