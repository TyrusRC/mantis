import dataclasses


def test_cli_parses_engines_flags():
    from mantis.cli import _build_parser
    args = _build_parser().parse_args(
        ["audit", ".", "--engines", "bandit,gosec", "--engines-offline"])
    assert args.engines == "bandit,gosec" and args.engines_offline is True


def test_cli_engines_default_off():
    from mantis.cli import _build_parser
    args = _build_parser().parse_args(["audit", "."])
    assert args.engines is None and args.engines_offline is False


def test_pipeline_has_engine_fields():
    from mantis.runner import Pipeline
    names = {f.name for f in dataclasses.fields(Pipeline)}
    assert {"engines", "engines_offline"} <= names
