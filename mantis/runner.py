"""Pipeline orchestrator.

Stages: 0 inventory · 1 SAST scan · 5 triage · 6 slice · 7 deep review ·
        8 fix (only with --fix) · 9 report.

Skipped per flag:
  --lite  -> skip 6, 7, 8
  --fix=false (default) -> skip 8
  mode=quick -> skip 6, 7, 8 (triage-only)
  mode=bugbounty -> force 6, 7; gate 7 on REACHABLE_FROM_ENTRYPOINT == yes
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mantis.agents import Agent
from mantis.config import Config
from mantis.deep import DeepResult, deep_review_many
from mantis.fix import FixResult, fix_all
from mantis.inventory import MODE_TO_PACKS, packs_for, take_inventory
from mantis.report import RunMeta, write_report
from mantis.scan import (
    Finding, ScanError, compose_pack_files, dedupe_findings,
    filter_valid_rule_files, run_scan,
)
from mantis.slice import Slice, extract_slice
from mantis.triage import TriageResult, triage_all


from mantis.cli import REPO_ROOT as REPO_ROOT  # type: ignore[import]

SCRIPTS_DIR = REPO_ROOT / "scripts"
RULES_DIR = REPO_ROOT / "rules"


def _is_writable(p: Path) -> bool:
    import os
    return os.access(p, os.W_OK)

_FOCUS_TAGS: dict[str, list[str]] = {
    "auth": ["auth", "m3-", "session", "jwt", "oauth"],
    "crypto": ["crypto", "cipher", "hash", "random", "m2-"],
    "injection": ["sql", "xss", "ssrf", "xxe", "inject", "command-injection"],
    "storage": ["storage", "m9-", "sharedpref", "nsuserdefaults", "keychain", "keystore"],
    "network": ["network", "http", "m4-", "tls", "cleartext"],
    "webview": ["webview", "evaluatejavascript", "javascriptenabled"],
    "secrets": ["secret", "credential", "apikey", "hardcoded"],
    "privacy": ["privacy", "pii", "m6-"],
    "ipc": ["ipc", "intent", "deeplink", "uri-handler"],
    "business-logic": ["business", "auth-bypass", "idor"],
    "prompt-injection": ["llm01", "prompt-injection", "llm05"],
}


@dataclass
class Pipeline:
    target: Path
    config: Config
    sast_bin: str
    agents: list[Agent]
    mode: Optional[str] = None
    fix: bool = False
    lite: bool = False
    focus: Optional[str] = None
    experimental_toast: bool = False
    skip_llm: bool = False

    def run(self) -> int:
        t0 = time.monotonic()
        notes: list[str] = []
        status = "complete"
        mode_label = self.mode or "auto"
        m = (self.mode or "").lower()

        print(f"[mantis] target  = {self.target}")
        print(f"[mantis] mode    = {mode_label}")
        print(f"[mantis] sast    = {self.sast_bin}")
        print(f"[mantis] provider= {self.config.provider or '(unspecified)'}")
        if self.lite:
            print("[mantis] --lite: stages 6/7/8 will be skipped")

        # Pre-flight: target writability (so we don't burn tokens then fail).
        if not _is_writable(self.target):
            print(f"[mantis] warning: {self.target} is not writable; "
                  "report will be written to a temp file on completion")
            notes.append("target dir not writable; report falls back to /tmp")

        # Stage 0: inventory
        print("[mantis] stage 0: inventory")
        inv = take_inventory(self.target)
        for r in inv.rationale:
            print(f"           - {r}")
        try:
            packs = packs_for(self.mode, inv)
        except ValueError as e:
            print(f"[mantis] error: {e}")
            return 2
        print(f"[mantis] packs   = {', '.join(packs)}")

        # Stage 1: SAST scan
        print("[mantis] stage 1: SAST scan")
        try:
            rule_files = compose_pack_files(packs, SCRIPTS_DIR)
            valid_rules, invalid_rules = filter_valid_rule_files(rule_files, self.sast_bin)
            if invalid_rules:
                print(f"[mantis] skipped {len(invalid_rules)} invalid rule file(s); "
                      f"{len(valid_rules)} valid")
                notes.append(
                    f"{len(invalid_rules)} rule file(s) failed scanner --validate and were skipped "
                    f"(see scanner stderr or run `opengrep --validate --config <file>` to diagnose)"
                )
            if not valid_rules:
                print("[mantis] no valid rule files in pack; aborting")
                return 2
            scan_out = run_scan(self.target, valid_rules, self.sast_bin)
        except ScanError as e:
            print(f"[mantis] scan failed: {e}")
            return 2
        raw_findings = dedupe_findings(scan_out.findings)
        if scan_out.errors:
            kept = scan_out.errors[:5]
            notes.append(
                f"scanner reported {len(scan_out.errors)} error(s); first {len(kept)}: "
                + "; ".join(kept)
            )
            status = "incomplete"
            for e in kept:
                print(f"[mantis] scanner: {e}")
        print(f"[mantis] raw findings: {len(raw_findings)}")

        if not raw_findings:
            self._write(packs, mode_label, time.monotonic() - t0,
                        notes or ["no findings"], status,
                        [], [], [], [], [], None, [], [])
            print("[mantis] done — no findings.")
            return 0

        filtered = self._apply_focus(raw_findings)
        if self.focus and len(filtered) != len(raw_findings):
            print(f"[mantis] focus={self.focus!r} kept {len(filtered)}/{len(raw_findings)} findings")

        if len(filtered) > self.config.max_findings and m != "deep":
            notes.append(
                f"raw findings exceeded max_findings ({len(filtered)} > "
                f"{self.config.max_findings}); only the first {self.config.max_findings} were triaged."
            )
            print(f"[mantis] capping to {self.config.max_findings} findings (mode=deep bypasses cap)")
            status = "incomplete"
            filtered = filtered[: self.config.max_findings]

        # Provider for any LLM-driven stage
        if self.skip_llm:
            provider, prov_err = None, "skip-llm requested"
            notes.append("LLM stages skipped (--skip-llm); raw SAST findings only")
        else:
            provider, prov_err = self._make_provider()
            if prov_err:
                notes.append(f"provider unavailable: {prov_err}")
                status = "incomplete"

        # Stage 5: triage
        triage_results: list[TriageResult] = []
        if provider:
            tmode = self.config.triage_mode or "single"
            print(f"[mantis] stage 5: triage ({len(filtered)} findings, {tmode}-chain)")
            triage_results = triage_all(filtered, self.agents, provider, self.target, mode=tmode)
        else:
            print("[mantis] stage 5: triage skipped (no provider)")
            triage_results = [
                TriageResult(finding=f, verdict="NEEDS-DEEP",
                             reason="triage skipped (no provider)", raw_response="")
                for f in filtered
            ]

        slice_input = self._select_for_slice(triage_results, m)
        slices: list[Slice] = []
        deep_results: list[DeepResult] = []
        fix_results: list[FixResult] = []
        fix_worktree: Optional[Path] = None

        skip_deep = self.lite or m == "quick"

        # Stage 6 + 7: slice and deep review
        if slice_input and not skip_deep:
            print(f"[mantis] stage 6: slice ({len(slice_input)} candidates)")
            slices = [extract_slice(r.finding, self.target) for r in slice_input]

            reachable = [s for s in slices if s.reachability != "no"]
            if m == "bugbounty":
                reachable = [s for s in slices if s.reachability == "yes"]
            print(f"[mantis] reachable slices: {len(reachable)}/{len(slices)}")

            if reachable and provider:
                budget = min(self.config.max_deep_calls, len(reachable))
                print(f"[mantis] stage 7: deep review ({budget} slices)")
                deep_results = deep_review_many(
                    reachable, self.agents, provider,
                    focus=self.focus, mode=m, max_calls=budget,
                )
                if len(reachable) > budget:
                    notes.append(
                        f"deep review budget cap ({budget}) below reachable slices ({len(reachable)})"
                    )
                    status = "incomplete"
            elif not provider:
                print("[mantis] stage 7: deep review skipped (no provider)")
        elif slice_input:
            print(f"[mantis] stages 6/7 skipped ({len(slice_input)} candidates left for review)")

        # Stage 7b (experimental): ToAST hunter — bugbounty mode only, behind flag.
        toast_results = []
        if self.experimental_toast and m == "bugbounty" and provider and deep_results:
            confirmed_pairs = self._pair_confirmed(slices, deep_results)
            if confirmed_pairs:
                print(f"[mantis] stage 7b (experimental): ToAST hunter on {len(confirmed_pairs)} slices")
                from mantis.toast import hunt_all
                toast_results = hunt_all(
                    [s for s, _ in confirmed_pairs],
                    self.agents,
                    provider,
                    max_calls=min(self.config.max_deep_calls // 3 or 1, len(confirmed_pairs)),
                )
                new_count = sum(len(t.new_findings) for t in toast_results)
                print(f"[mantis] ToAST: {new_count} new candidate finding(s) reached quorum")
        elif self.experimental_toast and m != "bugbounty":
            notes.append("--experimental-toast ignored: only runs in bugbounty mode")

        # Stage 8: fix
        if self.fix and deep_results:
            confirmed = self._pair_confirmed(slices, deep_results)
            if not confirmed:
                print("[mantis] stage 8: nothing confirmed; skipping fix")
            elif not provider:
                notes.append("fix stage skipped: no provider")
                status = "incomplete"
            else:
                print(f"[mantis] stage 8: fix ({len(confirmed)} confirmed)")
                fix_results, fix_worktree = fix_all(
                    confirmed, self.agents, provider, self.target, self.sast_bin, RULES_DIR,
                )
                applied = sum(1 for r in fix_results if r.status == "applied")
                print(f"[mantis] fix: {applied}/{len(fix_results)} applied")
        elif self.fix:
            notes.append("--fix requested but no confirmed deep findings to patch")

        duration = time.monotonic() - t0
        self._write(packs, mode_label, duration, notes, status,
                    raw_findings, filtered, triage_results, slices, deep_results,
                    fix_worktree, fix_results, toast_results)
        # Match the report's "Confirmed" column: triage verdict TRUE.
        # Deep-review verdicts further refine these but aren't a separate bucket
        # in the user-facing summary table.
        confirmed_n = sum(1 for r in triage_results if r.verdict == "TRUE")
        applied_n = sum(1 for r in fix_results if r.status == "applied")
        print(f"[mantis] done. confirmed={confirmed_n}  applied={applied_n}  "
              f"duration={duration:.1f}s")
        return 0

    # ------------ helpers ------------

    def _apply_focus(self, findings: list[Finding]) -> list[Finding]:
        if not self.focus:
            return findings
        tags = _FOCUS_TAGS.get(self.focus.lower())
        if not tags:
            return findings
        rx = re.compile("|".join(re.escape(t) for t in tags), re.IGNORECASE)
        return [f for f in findings if rx.search(f.rule_id)]

    def _make_provider(self):
        try:
            from mantis.providers import Provider, ProviderError
        except Exception as e:
            return None, f"provider import failed: {e}"
        try:
            return Provider(self.config), None
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def _select_for_slice(self, triage_results: list[TriageResult], mode_lower: str) -> list[TriageResult]:
        kept = [r for r in triage_results if r.verdict in ("TRUE", "NEEDS-DEEP")]
        if mode_lower == "bugbounty":
            return kept
        return kept

    def _pair_confirmed(self, slices: list[Slice], deep_results: list[DeepResult]):
        by_id = {s.finding.id: s for s in slices}
        out = []
        for d in deep_results:
            if d.verdict != "confirmed":
                continue
            s = by_id.get(d.finding_id)
            if s:
                out.append((s, d))
        return out

    def _write(self, packs, mode_label, duration, notes, status,
               raw_findings, filtered, triage_results, slices, deep_results,
               fix_worktree, fix_results, toast_results=None):
        toast_results = toast_results or []
        tokens_in = sum(r.tokens_in for r in triage_results) + sum(r.tokens_in for r in deep_results)
        tokens_out = sum(r.tokens_out for r in triage_results) + sum(r.tokens_out for r in deep_results)
        if fix_results:
            tokens_in += sum(r.tokens_in for r in fix_results)
            tokens_out += sum(r.tokens_out for r in fix_results)
        if toast_results:
            tokens_in += sum(getattr(r, "tokens_in", 0) for r in toast_results)
            tokens_out += sum(getattr(r, "tokens_out", 0) for r in toast_results)
        meta = RunMeta(
            target=self.target,
            mode=mode_label,
            packs=packs,
            sast_bin=self.sast_bin,
            provider=self.config.provider,
            duration_seconds=duration,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            status=status,
            notes=notes,
        )
        out_path = self.target / "security-audit-report.md"
        write_report(
            out_path, meta, raw_findings, triage_results,
            slices=slices, deep_results=deep_results,
            fix_results=fix_results, fix_worktree=fix_worktree,
            toast_results=toast_results,
        )
        print(f"[mantis] stage 9: wrote {out_path}")
