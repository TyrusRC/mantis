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
      2. The bundled package resources at mantis/resources/ (PyPI installs and
         editable installs from a source checkout both land here).
      3. Parent-of-parent of this file (legacy dev layout that still keeps
         top-level agents/ rules/).
      4. ~/.local/share/mantis / /usr/local/share/mantis / /usr/share/mantis
      5. Give up and return the package-resources path (helpful error later).
    """
    candidates: list[Path] = []
    env = os.environ.get("MANTIS_HOME")
    if env:
        candidates.append(Path(env))
    pkg_resources = Path(__file__).resolve().parent / "resources"
    candidates.append(pkg_resources)
    candidates.append(Path(__file__).resolve().parent.parent)
    for share in ("~/.local/share/mantis", "/usr/local/share/mantis", "/usr/share/mantis"):
        candidates.append(Path(share).expanduser())
    for c in candidates:
        if (c / "agents").is_dir() and (c / "rules").is_dir():
            return c
    return pkg_resources


REPO_ROOT = _resolve_repo_root()

AUDIT_MODES = ("quick", "deep", "bugbounty", "cve", "mobile", "web", "desktop", "llm", "taint")


def _resolve_audit_positionals(raw: list[str], explicit_mode: str | None,
                               focus: str | None) -> tuple[str, str | None, str | None]:
    """Disambiguate positional args after `mantis audit`.

    Accepts up to two positionals in either order: a path, a mode keyword,
    or a `focus:<area>` token. Returns (path, mode, focus).
    """
    path = "."
    mode = explicit_mode
    seen_path = False
    for tok in raw:
        if tok.startswith("focus:") and not focus:
            focus = tok.split(":", 1)[1] or None
        elif tok in AUDIT_MODES and not mode:
            mode = tok
        elif not seen_path:
            path = tok
            seen_path = True
        else:
            raise SystemExit(f"unexpected positional argument: {tok!r}")
    return path, mode, focus


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mantis",
        description="Hybrid SAST + LLM code-security audit (local-only).",
    )
    p.add_argument("--version", action="version", version=f"mantis {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    audit = sub.add_parser(
        "audit",
        help="Run a security audit on a target directory.",
        usage="mantis audit [path] [mode] [focus:<area>] [options]",
    )
    audit.add_argument(
        "pos", nargs="*",
        help=f"Optional [path] and/or [mode] in either order. "
             f"Modes: {', '.join(AUDIT_MODES)}. Also accepts focus:<area>.",
    )
    audit.add_argument(
        "--mode",
        default=None,
        choices=list(AUDIT_MODES),
        help="Deprecated alias for the positional mode keyword.",
    )
    audit.add_argument("--fix", action="store_true")
    audit.add_argument("--lite", action="store_true")
    audit.add_argument(
        "--focus",
        default=None,
        help="Restrict deep review to a domain (auth, crypto, injection, ...).",
    )
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
    audit.add_argument(
        "--since",
        default=None,
        help="Scan only files changed since a git ref. "
             "Examples: --since main, --since HEAD~1, --since uncommitted, --since staged.",
    )
    audit.add_argument(
        "--format",
        default="md",
        choices=["md", "json", "sarif", "all"],
        help="Additional report formats to write alongside the markdown report "
             "(default: md only). `all` writes md + json + sarif.",
    )
    audit.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass the per-file SAST result cache. Useful when debugging rules.",
    )

    doctor = sub.add_parser(
        "doctor",
        help="Probe install, scanner, agents, provider keys, and config.",
    )
    doctor.add_argument("path", nargs="?", default=".", help="Target dir for config discovery")
    doctor.add_argument("--config", default=None)

    # Back-compat: `mantis check` was the prior name.
    check = sub.add_parser("check", help="Deprecated alias for `mantis doctor`.")
    check.add_argument("path", nargs="?", default=".")
    check.add_argument("--config", default=None)

    history = sub.add_parser("history", help="List past audit runs for a target.")
    history.add_argument("path", nargs="?", default=".")

    show = sub.add_parser("show", help="Print a past audit report.")
    show.add_argument("ref", nargs="?", default="latest",
                      help="Run id, prefix, 'latest', or '-N' (Nth most recent).")
    show.add_argument("--path", default=".", help="Target dir (default: .)")

    diff = sub.add_parser("diff", help="Diff two audit reports.")
    diff.add_argument("a", nargs="?", default="-1",
                      help="Older ref (default: previous run, -1).")
    diff.add_argument("b", nargs="?", default="latest",
                      help="Newer ref (default: latest).")
    diff.add_argument("--path", default=".", help="Target dir (default: .)")

    init = sub.add_parser(
        "init",
        help="Scaffold .mantis.yaml + .env.example in the target directory.",
    )
    init.add_argument("path", nargs="?", default=".", help="Target dir (default: .)")
    init.add_argument("--force", action="store_true", help="Overwrite existing files.")

    update = sub.add_parser(
        "update",
        help="Check PyPI for a newer mantis release and upgrade in place.",
    )
    update.add_argument(
        "--check",
        action="store_true",
        help="Only check (don't upgrade). Bypasses the 24h cache.",
    )

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

    raw_pos = list(getattr(args, "pos", []) or [])
    path, mode, focus = _resolve_audit_positionals(raw_pos, args.mode, args.focus)

    target = Path(path).resolve()
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
        mode=mode,
        fix=args.fix,
        lite=args.lite,
        focus=focus,
        experimental_toast=getattr(args, "experimental_toast", False),
        skip_llm=skip_llm,
        since=getattr(args, "since", None),
        output_format=getattr(args, "format", "md"),
        no_cache=getattr(args, "no_cache", False),
    )
    return pipe.run()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "update":
        from mantis.updates import maybe_print_update_notice
        maybe_print_update_notice(__version__)
    if args.command in ("doctor", "check"):
        if args.command == "check":
            print("note: `mantis check` is deprecated; use `mantis doctor`.", file=sys.stderr)
        from mantis.doctor import cmd_doctor
        return cmd_doctor(args)
    if args.command == "init":
        from mantis.init_wizard import cmd_init
        return cmd_init(args)
    if args.command in ("history", "show", "diff"):
        from mantis.history import cmd_history, cmd_show, cmd_diff
        return {"history": cmd_history, "show": cmd_show, "diff": cmd_diff}[args.command](args)
    if args.command == "audit":
        return cmd_audit(args)
    if args.command == "update":
        from mantis.updates import cmd_update
        return cmd_update(args)
    parser.error(f"unknown command: {args.command}")
    return 2
