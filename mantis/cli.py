"""mantis CLI entrypoint."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from mantis import __version__


def _resolve_repo_root() -> Path:
    """Locate the directory containing agents/, rules/, scripts/, checklists/.

    Precedence:
      1. $MANTIS_HOME if it points to a directory with agents/
      2. Two levels up from this file (works in editable / source installs)
      3. ~/.local/share/mantis / /usr/local/share/mantis / /usr/share/mantis
      4. Give up and return the parent-of-parent (helpful error later)
    """
    candidates: list[Path] = []
    env = os.environ.get("MANTIS_HOME")
    if env:
        candidates.append(Path(env))
    candidates.append(Path(__file__).resolve().parent.parent)
    for share in ("~/.local/share/mantis", "/usr/local/share/mantis", "/usr/share/mantis"):
        candidates.append(Path(share).expanduser())
    for c in candidates:
        if (c / "agents").is_dir() and (c / "rules").is_dir():
            return c
    return candidates[1]


REPO_ROOT = _resolve_repo_root()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mantis",
        description="Hybrid SAST + LLM code-security audit (local-only).",
    )
    p.add_argument("--version", action="version", version=f"mantis {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Run a security audit on a target directory.")
    audit.add_argument("path", nargs="?", default=".", help="Path to audit (default: .)")
    audit.add_argument(
        "--mode",
        default=None,
        choices=["quick", "deep", "bugbounty", "cve", "mobile", "web", "llm", "taint"],
    )
    audit.add_argument("--fix", action="store_true")
    audit.add_argument("--lite", action="store_true")
    audit.add_argument("--focus", default=None)
    audit.add_argument(
        "--config",
        default=None,
        help="Path to .mantis.yaml (default: <target>/.mantis.yaml or $MANTIS_CONFIG)",
    )
    audit.add_argument(
        "--experimental-toast",
        action="store_true",
        help="Enable the experimental Tree-of-AST hunter on confirmed slices (bugbounty mode only).",
    )
    audit.add_argument(
        "--skip-llm",
        action="store_true",
        help="Run only the SAST + inventory stages; skip triage/deep/fix and write a raw report. "
             "Useful for sanity-checking rule packs without provider quota.",
    )

    check = sub.add_parser(
        "check",
        help="Validate config + environment without running an audit.",
    )
    check.add_argument("path", nargs="?", default=".", help="Target dir for config discovery")
    check.add_argument("--config", default=None)

    return p


def cmd_check(args) -> int:
    from mantis.config import load_config, ConfigError
    from mantis.sast import resolve_sast_binary, SastError
    from mantis.agents import discover_agents, AgentParseError

    target = Path(args.path).resolve()
    try:
        cfg = load_config(target, explicit=args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    try:
        sast = resolve_sast_binary(cfg.sast_bin)
    except SastError as e:
        print(f"sast error: {e}", file=sys.stderr)
        return 2

    try:
        agents = discover_agents(REPO_ROOT / "agents")
    except AgentParseError as e:
        print(f"agent error: {e}", file=sys.stderr)
        return 2

    cfg_src = cfg.source_path or "(none — using env vars only)"
    print(f"mantis {__version__}")
    print(f"config: {cfg_src}")
    print(f"sast binary: {sast}")
    print(f"provider: {cfg.provider or '(unspecified)'}")
    print(f"tier mapping:")
    for tier in ("fast", "mid", "deep"):
        print(f"  {tier:<4} -> {cfg.models.get(tier)}")
    print(f"budget: max_findings={cfg.max_findings}  max_deep_calls={cfg.max_deep_calls}")
    print(f"agents discovered: {len(agents)}")
    for a in agents:
        print(f"  {a.name:<22} tier={a.tier:<4} model={a.model}")
    return 0


def cmd_audit(args) -> int:
    from mantis.agents import discover_agents, AgentParseError
    from mantis.config import load_config, ConfigError
    from mantis.runner import Pipeline
    from mantis.sast import resolve_sast_binary, SastError

    target = Path(args.path).resolve()
    if not target.is_dir():
        print(f"target not found: {target}", file=sys.stderr)
        return 2

    skip_llm = getattr(args, "skip_llm", False)
    try:
        cfg = load_config(target, explicit=args.config, skip_provider_validation=skip_llm)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    try:
        sast = resolve_sast_binary(cfg.sast_bin)
    except SastError as e:
        print(f"sast error: {e}", file=sys.stderr)
        return 2

    try:
        agents = discover_agents(REPO_ROOT / "agents")
    except AgentParseError as e:
        print(f"agent error: {e}", file=sys.stderr)
        return 2

    pipe = Pipeline(
        target=target,
        config=cfg,
        sast_bin=sast,
        agents=agents,
        mode=args.mode,
        fix=args.fix,
        lite=args.lite,
        focus=args.focus,
        experimental_toast=getattr(args, "experimental_toast", False),
        skip_llm=skip_llm,
    )
    return pipe.run()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return cmd_check(args)
    if args.command == "audit":
        return cmd_audit(args)
    parser.error(f"unknown command: {args.command}")
    return 2
