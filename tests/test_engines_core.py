import json

from mantis.engines import Engine, EngineResult, sarif_to_findings

SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "bandit", "rules": [
            {"id": "B602", "name": "subprocess_popen_with_shell",
             "properties": {"cwe": ["CWE-78"], "security-severity": "8.0"}}]}},
        "results": [{
            "ruleId": "B602", "level": "warning", "message": {"text": "shell=True"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app.py"}, "region": {"startLine": 7}}}],
        }],
    }],
}


def test_sarif_to_findings_maps_fields():
    fs = sarif_to_findings(SARIF, "bandit")
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id == "B602" and f.path == "app.py" and f.start_line == 7
    assert f.severity == "ERROR"            # security-severity 8.0 -> ERROR
    assert f.confidence == "MEDIUM"
    assert f.metadata["engine"] == "bandit" and f.metadata["cwe"] == ["CWE-78"]


def test_sarif_tolerates_missing_and_zero():
    assert sarif_to_findings({"runs": [{"results": []}]}, "x") == []
    fs = sarif_to_findings({"runs": [{"results": [{"message": {"text": "m"}}]}]}, "x")
    assert len(fs) == 1 and fs[0].path == "" and fs[0].start_line == 0


class _Dummy(Engine):
    name = "dummy"
    binary = "dummy"

    def command(self, tree, out):
        return ["dummy", tree, "-o", out]


def test_engine_run_reads_sarif(monkeypatch):
    import subprocess

    class _Res:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        open(out, "w").write(json.dumps(SARIF))
        return _Res()

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = _Dummy().run("/tree")
    assert isinstance(res, EngineResult) and res.error is None
    assert len(res.findings) == 1 and res.findings[0].rule_id == "B602"


def test_engine_run_crash_records_error(monkeypatch):
    import subprocess

    def boom(cmd, **kw):
        raise FileNotFoundError("dummy")

    monkeypatch.setattr(subprocess, "run", boom)
    res = _Dummy().run("/tree")
    assert res.error is not None and res.findings == []
