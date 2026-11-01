"""Provider-agnostic LLM client.

Routes by tier (fast / mid / deep). The model string per tier is taken
verbatim from config — no hardcoded model names. Uses litellm for
multi-provider routing (Anthropic, Google, OpenAI, OpenRouter, Ollama, ...).

Resilience:
- ``drop_params`` lets litellm drop parameters a model rejects (reasoning
  models refuse any temperature but 1). If a provider still rejects
  max_tokens as an unsupported parameter, retry once without it.
- Transient upstream errors (429/5xx, timeouts, connection errors) are retried
  with exponential backoff up to ``RETRY_ATTEMPTS`` times, honouring
  ``Retry-After``.
- A reply emptied by the length cap (thinking models spend the budget before
  answering) is retried once with a larger budget; any other empty reply
  raises, so callers record an error instead of a silent blank.
- Calls at temperature <= ``CACHE_MAX_TEMPERATURE`` are replayed from
  ``~/.cache/mantis/llm`` when ``cache_dir`` is set (the runner sets it unless
  ``--no-cache``); hits report 0 tokens. Sampling calls are never cached.
- Missing usage fields default to 0 — token caps may misreport for those
  providers, but the run does not fail.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from mantis.config import Config

# litellm otherwise fetches its model price map from GitHub at import time:
# an unapproved outbound call that also adds ~20s to every run.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")


class ProviderError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    tokens_in: int
    tokens_out: int
    model: str


_TOKEN_PARAMS = ("max_tokens", "max_completion_tokens", "max_output_tokens")
_REJECTED = ("unsupported", "unexpected keyword", "not supported", "unrecognized", "unknown")

_TRANSIENT_NEEDLES = (
    "service unavailable", "serviceunavailable",
    "rate limit", "ratelimit", "too many requests",
    "overloaded", "timeout", "timed out", "temporarily unavailable",
    "internal server error", "bad gateway", "gateway timeout",
)
_TRANSIENT_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}
_TRANSIENT_CLASSES = ("RateLimitError", "ServiceUnavailableError", "Timeout",
                      "APIConnectionError", "InternalServerError")

RETRY_ATTEMPTS = 6       # initial + 5 retries: ~1 min of backoff covers per-minute rate limits
RETRY_BASE_SLEEP = 2.0   # seconds; doubles each retry
RETRY_AFTER_CAP = 60.0
REQUEST_TIMEOUT = 300    # seconds per call; deep-tier thinking replies can be slow
LENGTH_RETRY_FACTOR = 4
LENGTH_RETRY_CAP = 8192


CACHE_MAX_TEMPERATURE = 0.2   # above this a call is a deliberate sample (ToAST): never replayed

# litellm infers the backend from the model prefix; unprefixed "gemini-*" goes to
# Vertex AI, not the Gemini API the `google` provider means.
_PROVIDER_PREFIX = {
    "google": ("gemini/", ("gemini/", "vertex_ai/", "vertex_ai_beta/")),
    "openrouter": ("openrouter/", ("openrouter/",)),
    "ollama": ("ollama/", ("ollama/", "ollama_chat/")),
}


def route_model(model: str, provider: Optional[str]) -> str:
    rule = _PROVIDER_PREFIX.get((provider or "").lower())
    if not rule or model.startswith(rule[1]):
        return model
    if provider.lower() == "google" and "/" in model:   # some other explicit backend
        return model
    return rule[0] + model


def _cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "mantis" / "llm"


def _is_param_mismatch(exc: BaseException) -> bool:
    """The provider rejected a token-cap parameter itself (not e.g. a context overflow)."""
    msg = str(exc).lower()
    return any(p in msg for p in _TOKEN_PARAMS) and any(r in msg for r in _REJECTED)


def _is_transient(exc: BaseException) -> bool:
    if getattr(exc, "status_code", None) in _TRANSIENT_STATUS:
        return True
    if any(c.__name__ in _TRANSIENT_CLASSES for c in type(exc).__mro__):
        return True
    msg = str(exc).lower()
    return any(n in msg for n in _TRANSIENT_NEEDLES)


def _retry_after(exc: BaseException) -> Optional[float]:
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    try:
        raw = headers.get("retry-after") or headers.get("Retry-After")
        return min(float(raw), RETRY_AFTER_CAP) if raw is not None else None
    except (TypeError, ValueError, AttributeError):
        return None


class Provider:
    def __init__(self, config: Config, cache_dir: Optional[Path] = None):
        self.config = config
        # Replays identical low-temperature calls across runs (re-audits of an
        # unchanged tree cost nothing). None = disabled.
        self.cache_dir = cache_dir
        try:
            import litellm  # noqa: F401
        except ImportError as e:
            raise ProviderError(
                "litellm required for standalone provider routing: pip install litellm"
            ) from e

    def complete(
        self,
        tier: str,
        system: Optional[str],
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        model = self.config.models.get(tier)
        if not model:
            raise ProviderError(f"no model configured for tier {tier!r}")
        model = route_model(model, self.config.provider)

        key = None
        if self.cache_dir is not None and temperature <= CACHE_MAX_TEMPERATURE:
            key = hashlib.sha256(json.dumps(
                [model, self.config.api_base, system, user, max_tokens, temperature]
            ).encode("utf-8")).hexdigest()
            hit = self._cache_get(key)
            if hit is not None:
                return LLMResponse(text=hit, tokens_in=0, tokens_out=0, model=model)

        out = self._complete_uncached(model, system, user, max_tokens, temperature)
        if key is not None:
            self._cache_put(key, out.text)
        return out

    def _cache_get(self, key: str) -> Optional[str]:
        try:
            return json.loads((self.cache_dir / f"{key}.json").read_text(encoding="utf-8"))["text"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _cache_put(self, key: str, text: str) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_dir / f"{key}.json.tmp"
            tmp.write_text(json.dumps({"text": text}), encoding="utf-8")
            tmp.replace(self.cache_dir / f"{key}.json")
        except OSError:
            pass   # a cache write failure must never fail the audit

    def _complete_uncached(self, model: str, system: Optional[str], user: str,
                           max_tokens: int, temperature: float) -> LLMResponse:
        import litellm

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": user})

        base_kwargs: dict = dict(
            model=model,
            messages=msgs,
            temperature=temperature,
            drop_params=True,
            timeout=REQUEST_TIMEOUT,
        )
        if self.config.api_base:
            base_kwargs["api_base"] = self.config.api_base
        if self.config.extra_headers:
            base_kwargs["extra_headers"] = self.config.extra_headers

        resp = self._complete_with_retry(litellm, base_kwargs, max_tokens)
        out, finish = _extract_response(resp, model)
        if out.text.strip():
            return out
        if finish in ("length", "max_tokens") and max_tokens < LENGTH_RETRY_CAP:
            bigger = min(max_tokens * LENGTH_RETRY_FACTOR, LENGTH_RETRY_CAP)
            resp = self._complete_with_retry(litellm, base_kwargs, bigger)
            out, finish = _extract_response(resp, model)
            if out.text.strip():
                return out
        raise ProviderError(f"empty response from {model} (finish_reason={finish})")

    def _complete_with_retry(self, litellm, base_kwargs: dict, max_tokens: int):
        """Run litellm.completion with retry-on-transient and param-mismatch fallback."""
        last_exc: BaseException | None = None
        use_max_tokens = True
        for attempt in range(RETRY_ATTEMPTS):
            try:
                kw = dict(base_kwargs)
                if use_max_tokens:
                    kw["max_tokens"] = max_tokens
                return litellm.completion(**kw)
            except Exception as e:
                last_exc = e
                if _is_param_mismatch(e) and use_max_tokens:
                    use_max_tokens = False
                    continue  # immediate retry, no sleep
                if _is_transient(e) and attempt < RETRY_ATTEMPTS - 1:
                    sleep = _retry_after(e)
                    if sleep is None:
                        sleep = RETRY_BASE_SLEEP * (2 ** attempt) + random.uniform(0, 0.5)
                    time.sleep(sleep)
                    continue
                raise
        # Should not reach here, but be defensive.
        assert last_exc is not None
        raise last_exc


def _extract_response(resp, model: str) -> tuple[LLMResponse, Optional[str]]:
    try:
        first = resp["choices"][0]
        choice = first["message"]
        text = choice.get("content") if hasattr(choice, "get") else choice["content"]
        text = text or ""
        finish = _field(first, "finish_reason")
    except (KeyError, IndexError, TypeError, AttributeError) as e:
        raise ProviderError(f"unexpected response shape from {model}: {e}") from e

    # litellm returns a ModelResponse object, not a plain dict. Both
    # `resp["usage"]` and `resp.usage` work via __getitem__/attribute access.
    usage = None
    try:
        usage = resp["usage"]
    except (KeyError, TypeError):
        usage = getattr(resp, "usage", None)
    tokens_in = _coerce_int(_field(usage, "prompt_tokens"))
    tokens_out = _coerce_int(_field(usage, "completion_tokens"))
    return LLMResponse(
        text=text if isinstance(text, str) else str(text),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        model=model,
    ), finish


def _field(obj, name):
    if obj is None:
        return None
    if hasattr(obj, "get"):
        try:
            v = obj.get(name)
            if v is not None:
                return v
        except (TypeError, AttributeError):
            pass
    return getattr(obj, name, None)


def _coerce_int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0
