import shutil

import pytest


@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")
def test_bandit_engine_real(tmp_path):
    (tmp_path / "v.py").write_text(
        "import subprocess\nsubprocess.call(cmd, shell=True)\n")
    from mantis.engines import BanditEngine
    res = BanditEngine().run(str(tmp_path))
    assert res.error is None and len(res.findings) >= 1
    assert all(f.metadata["engine"] == "bandit" for f in res.findings)
    assert all(f.severity in ("ERROR", "WARNING", "INFO") for f in res.findings)
