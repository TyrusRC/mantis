from __future__ import annotations

import pytest

from mantis import sast as sast_mod
from mantis.sast import SastError, resolve_sast_binary


def _mock_which(monkeypatch, available):
    """Make shutil.which return a path for any binary in `available`, else None."""
    def fake(name):
        return f"/usr/bin/{name}" if name in available else None
    monkeypatch.setattr(sast_mod.shutil, "which", fake)


def test_env_var_wins(monkeypatch):
    monkeypatch.setenv("AUDIT_SAST_BIN", "my-custom")
    _mock_which(monkeypatch, {"my-custom"})
    assert resolve_sast_binary("opengrep") == "my-custom"


def test_env_var_set_but_not_on_path_raises(monkeypatch):
    monkeypatch.setenv("AUDIT_SAST_BIN", "nonexistent")
    _mock_which(monkeypatch, set())
    with pytest.raises(SastError) as ei:
        resolve_sast_binary(None)
    assert "AUDIT_SAST_BIN" in str(ei.value)


def test_auto_prefers_opengrep(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"opengrep", "semgrep"})
    assert resolve_sast_binary("auto") == "opengrep"


@pytest.mark.parametrize("pref", [None, "auto"])
def test_default_never_falls_back_to_semgrep(monkeypatch, pref):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"semgrep"})
    with pytest.raises(SastError) as ei:
        resolve_sast_binary(pref)
    assert "opengrep" in str(ei.value)


def test_auto_with_none_preference_is_auto(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"opengrep"})
    assert resolve_sast_binary(None) == "opengrep"


def test_auto_no_binary_raises(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, set())
    with pytest.raises(SastError) as ei:
        resolve_sast_binary("auto")
    assert "OpenGrep not on PATH" in str(ei.value)


def test_explicit_opengrep_pref(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"opengrep", "semgrep"})
    assert resolve_sast_binary("opengrep") == "opengrep"
    # semgrep is no longer an accepted explicit value
    with pytest.raises(SastError):
        resolve_sast_binary("semgrep")


def test_explicit_pref_not_on_path_raises(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"semgrep"})
    with pytest.raises(SastError) as ei:
        resolve_sast_binary("opengrep")
    assert "not on PATH" in str(ei.value)


def test_unknown_pref_raises(monkeypatch):
    monkeypatch.delenv("AUDIT_SAST_BIN", raising=False)
    _mock_which(monkeypatch, {"opengrep"})
    with pytest.raises(SastError) as ei:
        resolve_sast_binary("ripgrep")
    assert "unknown sast_bin" in str(ei.value)
