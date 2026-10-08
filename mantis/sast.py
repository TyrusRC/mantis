"""SAST binary resolution.

Precedence: $AUDIT_SAST_BIN > config.sast_bin > opengrep.

OpenGrep is the one and only SAST scanner. (Rules are written in the Semgrep YAML
schema, which OpenGrep consumes unchanged — that is a rule-format name, not a
dependency on the semgrep binary.)
"""
from __future__ import annotations

import os
import shutil
from typing import Optional


class SastError(Exception):
    pass


DEFAULT = "opengrep"
CANDIDATES = (DEFAULT,)  # OpenGrep only; semgrep support removed


def resolve_sast_binary(preference: Optional[str]) -> str:
    env = os.environ.get("AUDIT_SAST_BIN")
    if env:
        if shutil.which(env):
            return env
        raise SastError(f"AUDIT_SAST_BIN={env!r} but not on PATH")

    pref = (preference or "auto").lower()
    if pref in ("auto", DEFAULT):  # "auto" is an alias for the default
        if shutil.which(DEFAULT):
            return DEFAULT
        raise SastError(
            "OpenGrep not on PATH; install it: `pipx install opengrep`"
        )
    raise SastError(f"unknown sast_bin: {pref!r} (OpenGrep is the only supported scanner)")
