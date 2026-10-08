"""SAST binary resolution.

Precedence: $AUDIT_SAST_BIN > config.sast_bin > opengrep.

OpenGrep is the engine. Semgrep is used only when explicitly requested
(`sast_bin: semgrep` or $AUDIT_SAST_BIN=semgrep); it is never chosen implicitly.
"""
from __future__ import annotations

import os
import shutil
from typing import Optional


class SastError(Exception):
    pass


DEFAULT = "opengrep"
CANDIDATES = (DEFAULT, "semgrep")  # accepted explicit values; semgrep is opt-in


def resolve_sast_binary(preference: Optional[str]) -> str:
    env = os.environ.get("AUDIT_SAST_BIN")
    if env:
        if shutil.which(env):
            return env
        raise SastError(f"AUDIT_SAST_BIN={env!r} but not on PATH")

    pref = (preference or "auto").lower()
    if pref == "auto":  # "auto" is kept as an alias for the default
        if shutil.which(DEFAULT):
            return DEFAULT
        raise SastError(
            "no SAST binary on PATH; install OpenGrep: `pipx install opengrep` "
            "(Semgrep is used only if you set sast_bin: semgrep)"
        )
    if pref in CANDIDATES:
        if shutil.which(pref):
            return pref
        raise SastError(f"{pref!r} not on PATH; install it or unset sast_bin to use opengrep")
    raise SastError(f"unknown sast_bin: {pref!r} (expected: opengrep, or semgrep as explicit opt-in)")
