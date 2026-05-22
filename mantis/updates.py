"""PyPI version-check + self-update for mantis.

Two responsibilities:

1. `check_for_update()` — non-blocking, 24h-cached query of pypi.org for the
   latest published mantis-sast version. If a newer one exists, returns a
   short message; otherwise returns None. Honors $MANTIS_NO_UPDATE_CHECK=1
   and skips entirely when stdout is not a TTY.

2. `cmd_update()` — `mantis update` subcommand. Detects how mantis is
   installed (pipx, pip --user, plain pip, editable) and shells out to the
   appropriate upgrade command. Refuses on editable installs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

PYPI_URL = "https://pypi.org/pypi/mantis-sast/json"
CACHE_TTL_SECONDS = 24 * 60 * 60
HTTP_TIMEOUT_SECONDS = 2.0


def _cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mantis" / "pypi-version.json"


def _parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in re.split(r"[.+-]", v):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) or (0,)


def _fetch_latest_from_pypi() -> Optional[str]:
    try:
        req = Request(PYPI_URL, headers={"User-Agent": "mantis-update-check"})
        with urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("info", {}).get("version")
    except (URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None


def _read_cache() -> Optional[dict]:
    p = _cache_path()
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(latest: str) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"latest": latest, "ts": int(time.time())}),
                     encoding="utf-8")
    except OSError:
        pass


def check_for_update(current: str, *, force: bool = False) -> Optional[str]:
    """Return a one-line update message if a newer release exists, else None.

    Opt-out via MANTIS_NO_UPDATE_CHECK=1. Always returns None on dev builds
    (versions ending in '+dev'). Cached for 24h.
    """
    if not force:
        if os.environ.get("MANTIS_NO_UPDATE_CHECK") == "1":
            return None
        if current.endswith("+dev") or current == "0.0.0":
            return None

    latest: Optional[str] = None
    cache = _read_cache()
    if cache and not force:
        if (int(time.time()) - int(cache.get("ts", 0))) < CACHE_TTL_SECONDS:
            latest = cache.get("latest")

    if latest is None:
        latest = _fetch_latest_from_pypi()
        if latest:
            _write_cache(latest)

    if not latest:
        return None
    if _parse_version(latest) > _parse_version(current):
        return f"mantis {latest} is available (you have {current}). run: mantis update"
    return None


def _session_marker_path() -> Path:
    """A per-terminal-session marker file. Two invocations sharing a parent
    process (the user's shell) on the same day will see the same path."""
    ppid = os.getppid()
    day = time.strftime("%Y%m%d")
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return Path(base) / f"mantis-update-shown-{ppid}-{day}"


def maybe_print_update_notice(current: str) -> None:
    """Best-effort startup nudge. Silent on non-TTY, on errors, when opted
    out, or once already shown in this shell session today."""
    try:
        if not sys.stderr.isatty():
            return
        marker = _session_marker_path()
        if marker.exists():
            return
        msg = check_for_update(current)
        if msg:
            print(msg, file=sys.stderr)
            try:
                marker.touch()
            except OSError:
                pass
    except Exception:
        pass


def _detect_install_kind() -> str:
    """Return one of: editable, pipx, pip, unknown."""
    try:
        import mantis  # noqa: F401
        from mantis import __file__ as mantis_file
    except ImportError:
        return "unknown"

    src = Path(mantis_file).resolve()

    # Editable install: package lives inside a checked-out source tree
    # (parent has pyproject.toml).
    pkg_parent = src.parent.parent
    if (pkg_parent / "pyproject.toml").is_file():
        return "editable"

    # pipx puts its venvs under ~/.local/pipx/venvs/<pkg>/
    if "/pipx/venvs/" in str(src) or "\\pipx\\venvs\\" in str(src):
        return "pipx"

    return "pip"


def cmd_update(args) -> int:
    from mantis import __version__

    kind = _detect_install_kind()
    print(f"installed via: {kind}")
    print(f"current version: {__version__}")

    if kind == "editable":
        print("editable install detected — pull from git and reinstall manually:",
              file=sys.stderr)
        print("  git -C <repo> pull && pip install -e <repo>", file=sys.stderr)
        return 2

    if getattr(args, "check", False):
        msg = check_for_update(__version__, force=True)
        if msg:
            print(msg)
        else:
            print("up to date.")
        return 0

    if kind == "pipx":
        if not shutil.which("pipx"):
            print("pipx not on PATH; install it or run with `pip install -U mantis-sast`",
                  file=sys.stderr)
            return 2
        cmd = ["pipx", "upgrade", "mantis-sast"]
    elif kind == "pip":
        cmd = [sys.executable, "-m", "pip", "install", "-U", "mantis-sast"]
    else:
        print("could not detect install method; run: pip install -U mantis-sast",
              file=sys.stderr)
        return 2

    print(f"running: {' '.join(cmd)}")
    try:
        return subprocess.call(cmd)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"upgrade failed: {e}", file=sys.stderr)
        return 1
