"""Native Haruspex adjudication client for mantis (SAST).

Haruspex is a small, local, calibrated decision model. mantis uses it as a FAIL-OPEN
triage annotator: it scores how likely an already-emitted finding is a real, reportable
vulnerability (0..1), to fight alert fatigue by letting the report rank true-positives
first. It is advisory only — a low score NEVER drops, re-severities, or hides a finding,
and it must never feed the slice/deep selection, the ``max_findings`` cap, or ``--fail-on``.
A missed finding is the cardinal harm, so the model can annotate, never gate.

Standalone: point ``MANTIS_HARUSPEX_URL`` at any Haruspex ``/v1/evaluate`` endpoint
(keyless on loopback). Unset or unreachable -> annotation is skipped and findings are
untouched.
"""

from __future__ import annotations

import json
import os
import urllib.request

_QUESTION = {
    "type": "boolean",
    "instructions": "Is this a real, reportable security finding?",
    "criteria": {"true": "a real, exploitable vulnerability", "false": "noise / not reportable alone"},
}


def base_url() -> str:
    """Configured Haruspex endpoint, or '' when the engine is not enabled."""
    return os.environ.get("MANTIS_HARUSPEX_URL", "").strip()


def adjudicate(state: str, url: str = "", timeout: int = 30) -> float | None:
    """Return P(real reportable finding) in [0,1] for the evidence in ``state``.

    Fail-open: returns ``None`` on a missing endpoint, transport error, or bad response —
    the caller MUST then leave the finding unchanged. The evidence belongs in ``state``
    (the format the model is trained on), not folded into the question.
    """
    endpoint = (url or base_url()).strip()
    if not endpoint or not state:
        return None
    # domain="web": mantis is a code/web SAST tool; a multi-adapter engine routes
    # to the web/SOC adapter, a single-adapter engine ignores the hint.
    body = json.dumps({"model": "haruspex", "domain": "web", "state": state,
                       "questions": {"q": _QUESTION}}).encode()
    req = urllib.request.Request(endpoint.rstrip("/") + "/v1/evaluate", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ans = json.loads(resp.read()).get("answers", {}).get("q", {})
        p = ans.get("probability")
        return float(p) if p is not None else None
    except Exception:  # noqa: BLE001 - fail-open: any failure means "no opinion"
        return None
