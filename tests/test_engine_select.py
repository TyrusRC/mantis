import mantis.engines as eng
from mantis.engines import Engine


class _Py(Engine):
    name = "pyeng"; binary = "pyeng"; languages = ("python",)
    def command(self, t, o): return ["pyeng"]


class _Net(Engine):
    name = "neteng"; binary = "neteng"; languages = ("*",); needs_network = True
    def command(self, t, o): return ["neteng"]


def _which(installed):
    return lambda b: ("/x/" + b) if b in installed else None


def test_auto_includes_network_and_matches_language(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which({"pyeng", "neteng"}))
    names = {e.name for e in eng.select("auto", {"python"}, classes=[_Py, _Net])[0]}
    assert names == {"pyeng", "neteng"}       # net ("*") included by default now
    # a language the local engine doesn't match -> only the "*" engine runs
    names2 = {e.name for e in eng.select("auto", {"go"}, classes=[_Py, _Net])[0]}
    assert names2 == {"neteng"}


def test_explicit_network_engine_is_opt_in(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which({"pyeng", "neteng"}))
    chosen, _ = eng.select(["neteng"], {"python"}, classes=[_Py, _Net])
    assert [e.name for e in chosen] == ["neteng"]


def test_missing_engine_is_skipped(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which(set()))  # nothing installed
    chosen, skipped = eng.select("auto", {"python"}, classes=[_Py, _Net])
    assert chosen == [] and "pyeng" in skipped


def test_none_disables_but_default_runs(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which({"pyeng"}))
    assert eng.select("none", {"python"}, classes=[_Py, _Net]) == ([], [])
    assert eng.select([], {"python"}, classes=[_Py, _Net]) == ([], [])
    chosen, _ = eng.select(None, {"python"}, classes=[_Py, _Net])  # default = on
    assert "pyeng" in {e.name for e in chosen}
