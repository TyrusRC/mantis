from mantis.engines import (
    ENGINES, BanditEngine, CheckovEngine, EslintSecurityEngine, GosecEngine,
    GrypeEngine, NjsscanEngine, TrivyEngine,
)


def test_metadata_and_commands():
    assert BanditEngine().languages == ("python",)
    assert GosecEngine().languages == ("go",)
    assert set(NjsscanEngine().languages) == {"javascript", "typescript"}
    assert TrivyEngine().needs_network is True and GrypeEngine().needs_network is True
    assert BanditEngine().command("/s", "/o")[:3] == ["bandit", "-r", "/s"]
    assert "-c" in EslintSecurityEngine().command("/s", "/o")
    assert "dir:/s" in GrypeEngine().command("/s", "/o")
    assert "sarif" in " ".join(CheckovEngine().command("/s", "/o"))
    assert len(ENGINES) == 7


def test_checkov_uri_rebased_onto_scanned_tree(tmp_path):
    from mantis.engines import _rebase_checkov_uri
    tree = tmp_path / "proj"
    rel = "/".join(tree.resolve().parts[2:]) + "/main.tf"   # checkov drops the first part
    assert _rebase_checkov_uri(rel, str(tree)) == str(tree.resolve() / "main.tf")
    assert _rebase_checkov_uri("main.tf", str(tree)) == str(tree.resolve() / "main.tf")


def test_trivy_offline_flag():
    t = TrivyEngine(); t.offline = True
    assert "--offline-scan" in t.command("/s", "/o")
