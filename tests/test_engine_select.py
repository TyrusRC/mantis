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


def test_auto_matches_language_and_excludes_network(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which({"pyeng", "neteng"}))
    chosen, _ = eng.select("auto", {"python"}, classes=[_Py, _Net])
    assert [e.name for e in chosen] == ["pyeng"]          # net excluded under auto
    assert eng.select("auto", {"go"}, classes=[_Py, _Net])[0] == []  # no lang match


def test_explicit_network_engine_is_opt_in(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which({"pyeng", "neteng"}))
    chosen, _ = eng.select(["neteng"], {"python"}, classes=[_Py, _Net])
    assert [e.name for e in chosen] == ["neteng"]


def test_missing_engine_is_skipped(monkeypatch):
    monkeypatch.setattr(eng.shutil, "which", _which(set()))  # nothing installed
    chosen, skipped = eng.select("auto", {"python"}, classes=[_Py, _Net])
    assert chosen == [] and "pyeng" in skipped


def test_off_by_default():
    assert eng.select(None, {"python"}, classes=[_Py, _Net]) == ([], [])
