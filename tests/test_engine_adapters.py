from mantis.engines import (
    ENGINES, BanditEngine, CheckovEngine, EslintSecurityEngine, GosecEngine,
    GrypeEngine, NjsscanEngine, TrivyEngine,
)


def test_metadata_and_commands():
    assert BanditEngine().languages == ("python",)
    assert GosecEngine().languages == ("go",)
    assert set(NjsscanEngine().languages) == {"javascript", "typescript"}
    assert CheckovEngine().supports_sarif is False
    assert TrivyEngine().needs_network is True and GrypeEngine().needs_network is True
    assert BanditEngine().command("/s", "/o")[:3] == ["bandit", "-r", "/s"]
    assert "@microsoft/sarif" in EslintSecurityEngine().command("/s", "/o")
    assert "dir:/s" in GrypeEngine().command("/s", "/o")
    assert "sarif" in " ".join(CheckovEngine().command("/s", "/o"))
    assert len(ENGINES) == 7


def test_checkov_parse_native_from_stdout():
    stdout = ('checkov banner\n{"runs":[{"results":[{"ruleId":"CKV_1","level":"error",'
              '"message":{"text":"x"},"locations":[{"physicalLocation":'
              '{"artifactLocation":{"uri":"main.tf"},"region":{"startLine":3}}}]}]}]}')
    fs = CheckovEngine().parse_native(stdout)
    assert len(fs) == 1 and fs[0].rule_id == "CKV_1" and fs[0].path == "main.tf"


def test_trivy_offline_flag():
    t = TrivyEngine(); t.offline = True
    assert "--offline-scan" in t.command("/s", "/o")
