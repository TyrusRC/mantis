"""mantis — hybrid SAST + LLM toolkit for local code-security audits."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("mantis-sast")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"
