"""Diagnostics for `mantis doctor`.

Runs a fixed checklist of probes and reports PASS/WARN/FAIL. Exits 0 if
no probe failed.

Subsumes the legacy `mantis check` (config + scanner + agents) and the
shell-based probes that used to live in doctor.sh (python/git/keys).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from mantis import __version__


GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
RESET = "\033[0m"


def _isatty() -> bool:
    return sys.stdout.isatty()


def _color(code: str, text: str) -> str:
    return f"{code}{text}{RESET}" if _isatty() else text


@dataclass
class ProbeResult:
    status: str  # "pass" | "warn" | "fail" | "info"
    message: str


def _say(section: str) -> None:
    print()
    print(_color(CYAN, f"== {section} =="))


def _emit(r: ProbeResult) -> int:
    tag_map = {
        "pass": _color(GREEN, " PASS"),
        "warn": _color(YELLOW, " WARN"),
        "fail": _color(RED, " FAIL"),
        "info": _color(BLUE, " INFO"),
    }
    print(f"{tag_map[r.status]}  {r.message}")
    return 1 if r.status == "fail" else 0


def _probe_python() -> ProbeResult:
    v = sys.version_info
    if v >= (3, 10):
        return ProbeResult("pass", f"python {v.major}.{v.minor}.{v.micro}")
    return ProbeResult("fail", f"python {v.major}.{v.minor} (need 3.10+)")


def _probe_binary(name: str, *, required: bool = True,
                  version_arg: str = "--version") -> ProbeResult:
    path = shutil.which(name)
    if not path:
        return ProbeResult("fail" if required else "warn", f"{name} not on PATH")
    try:
        out = subprocess.run([path, version_arg], capture_output=True,
                             text=True, timeout=5).stdout.strip().splitlines()
        ver = out[0] if out else "(no version output)"
    except (OSError, subprocess.SubprocessError):
        ver = "(version probe failed)"
    return ProbeResult("pass", f"{name} {ver}  [{path}]")


def _probe_scanner() -> ProbeResult:
    """OpenGrep preferred, semgrep accepted."""
    for binary in ("opengrep", "semgrep"):
        path = shutil.which(binary)
        if path:
            try:
                out = subprocess.run([path, "--version"], capture_output=True,
                                     text=True, timeout=5).stdout.strip().splitlines()
                ver = out[0] if out else ""
            except (OSError, subprocess.SubprocessError):
                ver = ""
            suffix = "" if binary == "opengrep" else "  (opengrep is recommended)"
            return ProbeResult("pass", f"{binary} {ver}{suffix}")
    return ProbeResult("fail", "no SAST binary found; install opengrep or semgrep")


def _probe_repo_root() -> tuple[ProbeResult, Path | None]:
    from mantis.cli import REPO_ROOT
    expected = ("agents", "rules", "checklists", "scripts", "commands")
    missing = [d for d in expected if not (REPO_ROOT / d).is_dir()]
    if missing:
        return (ProbeResult("fail",
                            f"REPO_ROOT={REPO_ROOT} missing: {', '.join(missing)}"),
                None)
    return (ProbeResult("pass", f"resources at {REPO_ROOT}"), REPO_ROOT)


def _probe_manifest(root: Path) -> ProbeResult:
    m = root / "rules" / "_manifest.yaml"
    if not m.is_file():
        return ProbeResult(
            "warn",
            "rules/_manifest.yaml missing — run: python3 -m mantis.resources.scripts.build_manifest",
        )
    n = "?"
    try:
        for line in m.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("total_rules:"):
                n = s.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return ProbeResult("pass", f"manifest present ({n} rules indexed)")


def _probe_agents(root: Path) -> ProbeResult:
    from mantis.agents import discover_agents, AgentParseError
    try:
        agents = discover_agents(root / "agents")
    except AgentParseError as e:
        return ProbeResult("fail", f"agent parse error: {e}")
    if not agents:
        return ProbeResult("fail", "no agents discovered")
    return ProbeResult("pass", f"{len(agents)} agent(s): {', '.join(a.name for a in agents)}")


def _probe_provider_keys() -> ProbeResult:
    keys = ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
            "OPENAI_API_KEY", "OPENROUTER_API_KEY")
    set_keys = [k for k in keys if os.environ.get(k)]
    if not set_keys:
        return ProbeResult(
            "warn",
            f"no provider keys in env ({', '.join(keys)}); standalone audits will fail at triage",
        )
    return ProbeResult("pass", f"{len(set_keys)} provider key(s) set: {', '.join(set_keys)}")


def _probe_config(target: Path, explicit: str | None) -> ProbeResult:
    from mantis.config import load_config, ConfigError
    try:
        cfg = load_config(target, explicit=explicit, skip_provider_validation=True)
    except ConfigError as e:
        return ProbeResult("warn", f"no usable config ({e}); run: mantis init")
    src = cfg.source_path or "(env only)"
    tiers = ", ".join(f"{t}={cfg.models.get(t) or '?'}" for t in ("fast", "mid", "deep"))
    return ProbeResult("pass", f"config: {src}  provider={cfg.provider or '?'}  {tiers}")


def cmd_doctor(args) -> int:
    print(_color(CYAN, f"mantis doctor — v{__version__}"))
    target = Path(getattr(args, "path", ".") or ".").resolve()
    explicit = getattr(args, "config", None)
    fail = 0

    _say("environment")
    fail |= _emit(_probe_python())
    fail |= _emit(_probe_binary("pipx", required=False))
    fail |= _emit(_probe_binary("git", required=False))

    _say("SAST scanner")
    fail |= _emit(_probe_scanner())

    _say("resource discovery")
    root_r, root = _probe_repo_root()
    fail |= _emit(root_r)
    if root:
        fail |= _emit(_probe_manifest(root))
        fail |= _emit(_probe_agents(root))

    _say("LLM provider keys")
    fail |= _emit(_probe_provider_keys())

    _say("config")
    fail |= _emit(_probe_config(target, explicit))

    print()
    if fail == 0:
        print(_color(GREEN, "All critical checks passed."))
        return 0
    print(_color(RED, "One or more critical checks failed — see above."))
    return 1
