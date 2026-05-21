from __future__ import annotations

from pathlib import Path

import pytest

from mantis.cli import main


REPO = Path(__file__).resolve().parent.parent


def _write_min_config(target: Path) -> None:
    (target / ".mantis.yaml").write_text("""
provider: google
models:
  fast: gemini/gemini-2.5-flash-lite
  mid:  gemini/gemini-2.5-flash
  deep: gemini/gemini-2.5-pro
sast_bin: auto
""")


def test_check_command_smoke(tmp_path, monkeypatch, capsys):
    _write_min_config(tmp_path)
    # Pretend opengrep is installed.
    monkeypatch.setattr("mantis.sast.shutil.which",
                        lambda n: "/usr/bin/opengrep" if n == "opengrep" else None)
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)

    code = main(["check", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "mantis" in out
    assert "tier mapping:" in out
    assert "agents discovered: 7" in out


def test_audit_help_lists_modes(capsys):
    import pytest
    with pytest.raises(SystemExit) as ei:
        main(["audit", "--help"])
    assert ei.value.code == 0
    out = capsys.readouterr().out
    for mode in ("quick", "deep", "bugbounty", "cve", "mobile", "web", "llm"):
        assert mode in out


def test_audit_missing_target_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("MANTIS_CONFIG", raising=False)
    code = main(["audit", str(tmp_path / "does-not-exist")])
    assert code == 2
    err = capsys.readouterr().err
    assert "target not found" in err


def test_audit_missing_config_errors(tmp_path, monkeypatch, capsys):
    for v in ("MANTIS_CONFIG", "MANTIS_MODEL_FAST", "MANTIS_MODEL_MID",
              "MANTIS_MODEL_DEEP"):
        monkeypatch.delenv(v, raising=False)
    code = main(["audit", str(tmp_path)])
    assert code == 2
    err = capsys.readouterr().err
    assert "config error" in err
