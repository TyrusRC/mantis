"""mantis — hybrid SAST + LLM toolkit for local code-security audits."""
from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("mantis-sast")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

__all__ = ["audit", "__version__"]


def __getattr__(name: str):
    # Lazy so `import mantis` (and the CLI's `from mantis import __version__`)
    # stays cheap; the pipeline only loads when `audit` is actually accessed.
    if name == "audit":
        from mantis.api import audit

        return audit
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
