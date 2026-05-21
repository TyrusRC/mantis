"""Config loading for the standalone CLI.

Precedence: env vars > explicit --config > <target>/.mantis.yaml > error.

No model names are hardcoded. The user must map every tier (fast/mid/deep)
to a model string the configured provider understands.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


class ConfigError(Exception):
    pass


REQUIRED_TIERS = ("fast", "mid", "deep")


@dataclass
class Config:
    models: dict[str, str] = field(default_factory=dict)
    provider: Optional[str] = None
    api_base: Optional[str] = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    sast_bin: Optional[str] = None
    max_findings: int = 200
    max_deep_calls: int = 50
    triage_mode: str = "single"   # single | dual
    source_path: Optional[Path] = None

    def validate(self) -> None:
        missing = [t for t in REQUIRED_TIERS if not self.models.get(t)]
        if missing:
            raise ConfigError(
                "missing model mapping for tier(s): "
                + ", ".join(missing)
                + f" (set in .mantis.yaml or via MANTIS_MODEL_{missing[0].upper()})"
            )


def _resolve_path(target: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"config not found: {path}")
        return path
    env_cfg = os.environ.get("MANTIS_CONFIG")
    if env_cfg:
        path = Path(env_cfg)
        if not path.is_file():
            raise ConfigError(f"MANTIS_CONFIG points at non-existent file: {path}")
        return path
    candidate = target / ".mantis.yaml"
    return candidate if candidate.is_file() else None


def load_config(
    target: Path,
    explicit: Optional[str] = None,
    *,
    skip_provider_validation: bool = False,
) -> Config:
    path = _resolve_path(target, explicit)
    cfg = Config(source_path=path)

    if path is not None:
        with path.open() as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: top-level must be a mapping")
        cfg.provider = data.get("provider")
        models = data.get("models") or {}
        if not isinstance(models, dict):
            raise ConfigError(f"{path}: 'models' must be a mapping of tier -> model string")
        for tier, val in models.items():
            if not isinstance(val, str):
                raise ConfigError(
                    f"{path}: models.{tier} must be a string; got {type(val).__name__}"
                )
            cfg.models[tier] = val
        cfg.api_base = data.get("api_base")
        headers = data.get("extra_headers") or {}
        if not isinstance(headers, dict):
            raise ConfigError(f"{path}: 'extra_headers' must be a mapping")
        cfg.extra_headers = headers
        cfg.sast_bin = data.get("sast_bin")
        budget = data.get("budget") or {}
        cfg.max_findings = int(budget.get("max_findings", cfg.max_findings))
        cfg.max_deep_calls = int(budget.get("max_deep_calls", cfg.max_deep_calls))
        triage = data.get("triage") or {}
        if isinstance(triage, dict) and triage.get("mode") in ("single", "dual"):
            cfg.triage_mode = triage["mode"]

    env_overrides = {
        "MANTIS_PROVIDER":    ("provider", lambda v: setattr(cfg, "provider", v)),
        "MANTIS_API_BASE":    ("api_base", lambda v: setattr(cfg, "api_base", v)),
        "MANTIS_SAST_BIN":    ("sast_bin", lambda v: setattr(cfg, "sast_bin", v)),
        "MANTIS_MODEL_FAST":  ("models.fast", lambda v: cfg.models.__setitem__("fast", v)),
        "MANTIS_MODEL_MID":   ("models.mid",  lambda v: cfg.models.__setitem__("mid", v)),
        "MANTIS_MODEL_DEEP":  ("models.deep", lambda v: cfg.models.__setitem__("deep", v)),
        "MANTIS_TRIAGE_MODE": ("triage_mode",
                               lambda v: setattr(cfg, "triage_mode", v) if v in ("single", "dual") else None),
    }
    for env_var, (_field, apply) in env_overrides.items():
        v = os.environ.get(env_var)
        if v:
            apply(v)

    if not skip_provider_validation:
        cfg.validate()
    return cfg
