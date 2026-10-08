import mantis.engines as eng
from mantis.scan import Finding, ScanOutput


class _Fake(eng.Engine):
    name = "fake"; binary = "fake"; languages = ("*",)
    def command(self, t, o): return ["fake"]
    def available(self): return True
    def run(self, tree):
        return eng.EngineResult("fake", [Finding(
            rule_id="E1", severity="ERROR", confidence="MEDIUM",
            path="a.py", start_line=1, end_line=1, message="engine finding")])


def test_seam_merges_engine_findings_into_scan_output():
    # Mirrors api.audit's seam: run_selected -> scan_out.findings.extend(...).
    so = ScanOutput(findings=[Finding(
        rule_id="OG1", severity="WARNING", confidence="LOW",
        path="b.py", start_line=2, end_line=2, message="opengrep finding")])
    f, e, skipped = eng.run_selected("/tree", {"python"}, ["fake"], classes=[_Fake])
    so.findings.extend(f)
    so.errors.extend(e)
    assert {x.rule_id for x in so.findings} == {"OG1", "E1"}
    assert e == [] and skipped == []


def test_engines_none_is_noop():
    f, e, skipped = eng.run_selected("/tree", {"python"}, None, classes=[_Fake])
    assert f == [] and e == [] and skipped == []


def test_audit_accepts_engine_params():
    import inspect

    import mantis.api as api
    sig = inspect.signature(api.audit)
    assert "engines" in sig.parameters and "engines_offline" in sig.parameters
