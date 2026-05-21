from __future__ import annotations

from pathlib import Path

import pytest

from mantis.config import Config, ConfigError, REQUIRED_TIERS, load_config


def _write(path: Path, body: str) -> Path:
    path.write_text(body)
    return path


def test_missing_config_and_no_env_raises(tmp_path, monkeypatch):
    for var in ("MANTIS_CONFIG", "MANTIS_PROVIDER", "MANTIS_MODEL_FAST",
                "MANTIS_MODEL_MID", "MANTIS_MODEL_DEEP"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "missing model mapping" in str(ei.value)


def test_skip_provider_validation_allows_missing_tiers(tmp_path, monkeypatch):
    """skip_provider_validation=True lets the LLM tiers be empty (--skip-llm path)."""
    for var in ("MANTIS_CONFIG", "MANTIS_PROVIDER", "MANTIS_MODEL_FAST",
                "MANTIS_MODEL_MID", "MANTIS_MODEL_DEEP"):
        monkeypatch.delenv(var, raising=False)
    cfg = load_config(tmp_path, skip_provider_validation=True)
    assert cfg.models == {}


def test_valid_yaml_loads(tmp_path, monkeypatch):
    for var in ("MANTIS_CONFIG", "MANTIS_MODEL_FAST", "MANTIS_MODEL_MID",
                "MANTIS_MODEL_DEEP", "MANTIS_PROVIDER", "MANTIS_API_BASE",
                "MANTIS_SAST_BIN"):
        monkeypatch.delenv(var, raising=False)
    _write(tmp_path / ".mantis.yaml", """
provider: google
models:
  fast: gemini/gemini-2.5-flash-lite
  mid:  gemini/gemini-2.5-flash
  deep: gemini/gemini-2.5-pro
sast_bin: opengrep
budget:
  max_findings: 50
  max_deep_calls: 10
""")
    cfg = load_config(tmp_path)
    assert cfg.provider == "google"
    assert cfg.models["fast"] == "gemini/gemini-2.5-flash-lite"
    assert cfg.models["deep"] == "gemini/gemini-2.5-pro"
    assert cfg.sast_bin == "opengrep"
    assert cfg.max_findings == 50
    assert cfg.max_deep_calls == 10


def test_missing_tier_in_file_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("MANTIS_MODEL_DEEP", raising=False)
    _write(tmp_path / ".mantis.yaml", """
models:
  fast: a/b
  mid:  a/c
""")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "deep" in str(ei.value)


def test_env_overrides_file(tmp_path, monkeypatch):
    _write(tmp_path / ".mantis.yaml", """
provider: google
models:
  fast: file-fast
  mid:  file-mid
  deep: file-deep
""")
    monkeypatch.setenv("MANTIS_MODEL_DEEP", "env-deep")
    monkeypatch.setenv("MANTIS_PROVIDER", "anthropic")
    cfg = load_config(tmp_path)
    assert cfg.provider == "anthropic"
    assert cfg.models["fast"] == "file-fast"   # file kept
    assert cfg.models["deep"] == "env-deep"    # env wins


def test_env_only_satisfies_required_tiers(tmp_path, monkeypatch):
    monkeypatch.setenv("MANTIS_MODEL_FAST", "x")
    monkeypatch.setenv("MANTIS_MODEL_MID", "y")
    monkeypatch.setenv("MANTIS_MODEL_DEEP", "z")
    cfg = load_config(tmp_path)
    assert all(cfg.models[t] for t in REQUIRED_TIERS)


def test_explicit_config_path_overrides_target(tmp_path, monkeypatch):
    for var in ("MANTIS_CONFIG", "MANTIS_MODEL_FAST", "MANTIS_MODEL_MID",
                "MANTIS_MODEL_DEEP"):
        monkeypatch.delenv(var, raising=False)
    other = tmp_path / "other.yaml"
    _write(other, """
models:
  fast: a
  mid:  b
  deep: c
""")
    # Target dir has no .mantis.yaml; explicit wins.
    cfg = load_config(tmp_path, explicit=str(other))
    assert cfg.models["fast"] == "a"


def test_non_string_model_value_raises(tmp_path, monkeypatch):
    for var in ("MANTIS_MODEL_FAST", "MANTIS_MODEL_MID", "MANTIS_MODEL_DEEP"):
        monkeypatch.delenv(var, raising=False)
    _write(tmp_path / ".mantis.yaml", """
models:
  fast: [bad, list]
  mid:  b
  deep: c
""")
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path)
    assert "must be a string" in str(ei.value)


def test_missing_explicit_path_raises(tmp_path, monkeypatch):
    monkeypatch.delenv("MANTIS_CONFIG", raising=False)
    with pytest.raises(ConfigError) as ei:
        load_config(tmp_path, explicit=str(tmp_path / "nope.yaml"))
    assert "config not found" in str(ei.value)
