def test_probe_engines_covers_all_seven():
    from mantis.doctor import _probe_engines
    msgs = " ".join(r.message for r in _probe_engines())
    for name in ("bandit", "gosec", "njsscan", "eslint-security",
                 "checkov", "trivy", "grype"):
        assert name in msgs


def test_probe_engines_never_fail_status():
    from mantis.doctor import _probe_engines
    assert all(r.status in ("pass", "warn") for r in _probe_engines())
