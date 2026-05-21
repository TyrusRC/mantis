"""SAST binary resolution.

Precedence: $AUDIT_SAST_BIN > config.sast_bin > opengrep > semgrep.
"""
from __future__ import annotations

import os
import shutil
from typing import Optional


class SastError(Exception):
    pass


CANDIDATES = ("opengrep", "semgrep")


def resolve_sast_binary(preference: Optional[str]) -> str:
    env = os.environ.get("AUDIT_SAST_BIN")
    if env:
        if shutil.which(env):
            return env
        raise SastError(f"AUDIT_SAST_BIN={env!r} but not on PATH")

    pref = (preference or "auto").lower()
    if pref == "auto":
        for c in CANDIDATES:
            if shutil.which(c):
                return c
        raise SastError(
            "no SAST binary on PATH; install one: "
            "`pipx install opengrep` (recommended) or `pipx install semgrep`"
        )
    if pref in CANDIDATES:
        if shutil.which(pref):
            return pref
        raise SastError(f"{pref!r} not on PATH; install it or set sast_bin: auto")
    raise SastError(f"unknown sast_bin: {pref!r} (expected: auto, opengrep, semgrep)")
