"""Provider-agnostic LLM client.

Routes by tier (fast / mid / deep). The model string per tier is taken
verbatim from config — no hardcoded model names. Uses litellm for
multi-provider routing (Anthropic, Google, OpenAI, OpenRouter, Ollama, ...).

Resilience:
- Providers disagree on parameter names (max_tokens vs max_completion_tokens
  vs max_output_tokens). On a parameter-mismatch error, retry once without
  max_tokens.
- Transient upstream errors (503 ServiceUnavailable, 429 rate-limit, timeouts)
  are retried with exponential backoff up to ``RETRY_ATTEMPTS`` times.
- Missing usage fields default to 0 — token caps may misreport for those
  providers, but the run does not fail.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional

from mantis.config import Config


class ProviderError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    tokens_in: int
    tokens_out: int
    model: str


_PARAM_ERROR_NEEDLES = (
    "max_tokens", "max_completion_tokens", "max_output_tokens",
    "unsupported parameter", "unexpected keyword",
)

_TRANSIENT_NEEDLES = (
    "503", "service unavailable", "serviceunavailable",
    "429", "rate limit", "ratelimit", "too many requests",
    "overloaded", "timeout", "timed out", "temporarily unavailable",
    "internal server error", "500", "502", "bad gateway", "504",
)

RETRY_ATTEMPTS = 4   # initial + 3 retries
RETRY_BASE_SLEEP = 1.5  # seconds; doubles each retry


def _is_param_mismatch(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(n in msg for n in _PARAM_ERROR_NEEDLES)


def _is_transient(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(n in msg for n in _TRANSIENT_NEEDLES)


class Provider:
    def __init__(self, config: Config):
        self.config = config
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

        import litellm

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": user})

        base_kwargs: dict = dict(
            model=model,
            messages=msgs,
            temperature=temperature,
        )
        if self.config.api_base:
            base_kwargs["api_base"] = self.config.api_base
        if self.config.extra_headers:
            base_kwargs["extra_headers"] = self.config.extra_headers

        resp = self._complete_with_retry(litellm, base_kwargs, max_tokens)
        return _extract_response(resp, model)

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
                    sleep = RETRY_BASE_SLEEP * (2 ** attempt) + random.uniform(0, 0.5)
                    time.sleep(sleep)
                    continue
                raise
        # Should not reach here, but be defensive.
        assert last_exc is not None
        raise last_exc


def _extract_response(resp, model: str) -> LLMResponse:
    try:
        choice = resp["choices"][0]["message"]
        text = choice.get("content") if hasattr(choice, "get") else choice["content"]
        text = text or ""
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
    )


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
