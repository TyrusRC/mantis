"""External engines must not execute code or config planted in the audited tree."""
from __future__ import annotations

import shutil

import pytest

from mantis.engines import CheckovEngine

_TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'


@pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")
def test_checkov_finds_issues_and_ignores_planted_config(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    (tree / "evilchecks").mkdir(parents=True)
    marker = tmp_path / "PWNED"
    (tree / "evilchecks" / "__init__.py").write_text("")
    (tree / "evilchecks" / "pwn.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    (tree / ".checkov.yaml").write_text(f"external-checks-dir:\n  - {tree / 'evilchecks'}\n")
    (tree / "main.tf").write_text(_TF)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    res = CheckovEngine().run(str(tree))

    assert not marker.exists(), "checkov executed a check planted in the audited tree"
    assert res.error is None, res.error
    assert any("CKV_AWS_20" in f.rule_id for f in res.findings)
    assert {f.path for f in res.findings} == {str((tree / "main.tf").resolve())}
    assert list(cwd.iterdir()) == [], "checkov wrote output into the caller's cwd"


def test_eslint_uses_only_mantis_config_formatter_and_plugin(tmp_path, monkeypatch):
    from mantis import engines
    gl = tmp_path / "global" / "lib" / "node_modules"
    (gl / "eslint" / "bin").mkdir(parents=True)
    (gl / "eslint" / "bin" / "eslint.js").write_text("")
    (gl / "eslint" / "bin" / "eslint.js").chmod(0o755)
    (gl / "eslint-plugin-security").mkdir()
    fmt = gl / "@microsoft" / "eslint-formatter-sarif"
    fmt.mkdir(parents=True)
    (fmt / "package.json").write_text('{"main": "sarif.js"}')
    bindir = tmp_path / "global" / "bin"
    bindir.mkdir()
    (bindir / "eslint").symlink_to(gl / "eslint" / "bin" / "eslint.js")
    monkeypatch.setenv("PATH", str(bindir))
    tree = tmp_path / "tree"
    tree.mkdir()

    eng = engines.EslintSecurityEngine()
    cmd = eng.command(str(tree), "/out.sarif")

    assert eng.available()
    assert cmd[cmd.index("-c") + 1] == str(engines._ESLINT_CONFIG)
    assert engines._ESLINT_CONFIG.is_file()
    assert cmd[cmd.index("-f") + 1] == str(fmt.resolve() / "sarif.js")
    assert eng.env()["NODE_PATH"] == str(gl.resolve())


def test_eslint_unavailable_without_global_plugin(tmp_path, monkeypatch):
    from mantis import engines
    gl = tmp_path / "lib" / "node_modules" / "eslint" / "bin"
    gl.mkdir(parents=True)
    (gl / "eslint.js").write_text("")
    (gl / "eslint.js").chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "eslint").symlink_to(gl / "eslint.js")
    monkeypatch.setenv("PATH", str(bindir))
    assert not engines.EslintSecurityEngine().available()
