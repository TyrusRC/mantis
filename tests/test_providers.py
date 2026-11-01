"""Tests for the provider abstraction. litellm is mocked end-to-end."""
from __future__ import annotations

import sys
import types

import pytest

from mantis.config import Config
from mantis.providers import (
    Provider,
    ProviderError,
    _is_param_mismatch,
    _is_transient,
)


def _cfg(**kw):
    base = dict(models={"fast": "x/fast", "mid": "x/mid", "deep": "x/deep"})
    base.update(kw)
    return Config(**base)


@pytest.fixture
def fake_litellm(monkeypatch):
    """Install a stub `litellm` module the Provider can import."""
    mod = types.ModuleType("litellm")
    state = {"calls": [], "responses": [], "raise_param_error_on_call": None}

    def completion(**kwargs):
        idx = len(state["calls"])
        state["calls"].append(kwargs)
        if state["raise_param_error_on_call"] == idx:
            raise TypeError("unexpected keyword argument 'max_tokens'")
        if state["responses"]:
            return state["responses"].pop(0)
        return {
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        }

    mod.completion = completion
    monkeypatch.setitem(sys.modules, "litellm", mod)
    return state


def test_complete_basic(fake_litellm):
    p = Provider(_cfg())
    out = p.complete("fast", "sys", "user msg", max_tokens=100, temperature=0.0)
    assert out.text == "ok"
    assert out.tokens_in == 5
    assert out.tokens_out == 7
    assert out.model == "x/fast"
    assert fake_litellm["calls"][0]["model"] == "x/fast"
    assert fake_litellm["calls"][0]["max_tokens"] == 100


def test_complete_unknown_tier_raises(fake_litellm):
    p = Provider(_cfg())
    with pytest.raises(ProviderError):
        p.complete("turbo", "sys", "u")


def test_complete_passes_api_base_and_headers(fake_litellm):
    cfg = _cfg(api_base="http://localhost:11434", extra_headers={"X": "y"})
    Provider(cfg).complete("mid", None, "u")
    call = fake_litellm["calls"][-1]
    assert call["api_base"] == "http://localhost:11434"
    assert call["extra_headers"] == {"X": "y"}


def test_complete_retries_without_max_tokens_on_param_error(fake_litellm):
    fake_litellm["raise_param_error_on_call"] = 0
    out = Provider(_cfg()).complete("fast", None, "u", max_tokens=100)
    assert out.text == "ok"
    # First call had max_tokens; second (retry) should not.
    assert "max_tokens" in fake_litellm["calls"][0]
    assert "max_tokens" not in fake_litellm["calls"][1]


def test_complete_re_raises_non_param_errors(fake_litellm):
    def boom(**kwargs):
        raise RuntimeError("network is on fire")
    sys.modules["litellm"].completion = boom
    with pytest.raises(RuntimeError):
        Provider(_cfg()).complete("fast", None, "u")


def test_extract_response_handles_missing_usage(fake_litellm):
    fake_litellm["responses"].append({
        "choices": [{"message": {"content": "hi"}}],
        # usage omitted entirely
    })
    out = Provider(_cfg()).complete("fast", None, "u")
    assert out.tokens_in == 0
    assert out.tokens_out == 0


def test_extract_response_handles_object_style_response(fake_litellm):
    """litellm returns ModelResponse / Usage objects, not plain dicts.

    Simulate the shape with a class that supports attribute access AND
    __getitem__ (matching litellm's actual API).
    """
    class Usage:
        def __init__(self, p, c):
            self.prompt_tokens = p
            self.completion_tokens = c
        def get(self, name, default=None):
            return getattr(self, name, default)

    class ModelResp:
        def __init__(self):
            self._d = {
                "choices": [{"message": {"content": "ok-from-obj"}}],
                "usage": Usage(17, 23),
            }
        def __getitem__(self, k): return self._d[k]
        def get(self, k, default=None): return self._d.get(k, default)
        @property
        def usage(self): return self._d["usage"]

    fake_litellm["responses"].append(ModelResp())
    out = Provider(_cfg()).complete("fast", None, "u")
    assert out.text == "ok-from-obj"
    assert out.tokens_in == 17
    assert out.tokens_out == 23


def test_extract_response_handles_partial_usage(fake_litellm):
    fake_litellm["responses"].append({
        "choices": [{"message": {"content": "hi"}}],
        "usage": {"prompt_tokens": None, "completion_tokens": "12"},
    })
    out = Provider(_cfg()).complete("fast", None, "u")
    assert out.tokens_in == 0
    assert out.tokens_out == 12


def test_extract_response_rejects_garbage_shape(fake_litellm):
    fake_litellm["responses"].append({"nope": True})
    with pytest.raises(ProviderError):
        Provider(_cfg()).complete("fast", None, "u")


def test_is_param_mismatch_matches_known_patterns():
    assert _is_param_mismatch(TypeError("unexpected keyword argument 'max_tokens'"))
    assert _is_param_mismatch(Exception("unsupported parameter max_output_tokens"))
    assert not _is_param_mismatch(RuntimeError("rate limit exceeded"))


def test_is_transient_matches_known_patterns():
    assert _is_transient(Exception("503 ServiceUnavailableError"))
    assert _is_transient(Exception("429 Too Many Requests"))
    assert _is_transient(Exception("connection timed out"))
    assert _is_transient(Exception("model is overloaded"))
    assert not _is_transient(ValueError("bad input"))


def test_complete_retries_on_transient_503(fake_litellm, monkeypatch):
    monkeypatch.setattr("mantis.providers.RETRY_BASE_SLEEP", 0.0)
    state = {"n": 0}

    def boom(**kwargs):
        state["n"] += 1
        if state["n"] < 3:
            raise RuntimeError("503 ServiceUnavailableError: model overloaded")
        return {
            "choices": [{"message": {"content": "recovered"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 2},
        }

    sys.modules["litellm"].completion = boom
    out = Provider(_cfg()).complete("fast", None, "u")
    assert out.text == "recovered"
    assert state["n"] == 3  # two failures + one success


def test_complete_gives_up_after_max_retries(fake_litellm, monkeypatch):
    monkeypatch.setattr("mantis.providers.RETRY_BASE_SLEEP", 0.0)

    def boom(**kwargs):
        raise RuntimeError("503 ServiceUnavailableError")

    sys.modules["litellm"].completion = boom
    with pytest.raises(RuntimeError, match="503"):
        Provider(_cfg()).complete("fast", None, "u")


# ---- request shape + resilience ----

def test_drops_unsupported_params_and_sets_timeout(fake_litellm):
    Provider(_cfg()).complete("fast", None, "u")
    call = fake_litellm["calls"][-1]
    assert call["drop_params"] is True      # reasoning models reject temperature
    assert call["timeout"] > 0


def test_litellm_cost_map_is_local(fake_litellm):
    import os
    Provider(_cfg())
    assert os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP") == "True"


def test_context_overflow_mentioning_max_tokens_is_not_retried_uncapped(fake_litellm):
    def boom(**kw):
        fake_litellm["calls"].append(kw)
        raise RuntimeError("prompt + max_tokens exceeds the model context window")
    sys.modules["litellm"].completion = boom
    with pytest.raises(RuntimeError):
        Provider(_cfg()).complete("fast", None, "u", max_tokens=100)
    assert all("max_tokens" in c for c in fake_litellm["calls"])


def test_rate_limit_honours_retry_after(fake_litellm, monkeypatch):
    slept = []
    monkeypatch.setattr("mantis.providers.time.sleep", slept.append)

    class RateLimited(Exception):
        status_code = 429
        response = types.SimpleNamespace(headers={"retry-after": "7"})

    n = {"i": 0}
    def flaky(**kw):
        n["i"] += 1
        if n["i"] == 1:
            raise RateLimited("slow down")
        return {"choices": [{"message": {"content": "ok"}}], "usage": {}}
    sys.modules["litellm"].completion = flaky
    assert Provider(_cfg()).complete("fast", None, "u").text == "ok"
    assert slept == [7.0]


def test_empty_reply_cut_by_length_retries_with_bigger_budget(fake_litellm):
    fake_litellm["responses"].append({
        "choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {}})
    fake_litellm["responses"].append({
        "choices": [{"message": {"content": "x | TRUE | ok"}}], "usage": {}})
    out = Provider(_cfg()).complete("fast", None, "u", max_tokens=200)
    assert out.text == "x | TRUE | ok"
    assert fake_litellm["calls"][1]["max_tokens"] > 200


def test_empty_reply_without_length_cut_raises(fake_litellm):
    fake_litellm["responses"].append({
        "choices": [{"message": {"content": ""}, "finish_reason": "content_filter"}], "usage": {}})
    with pytest.raises(ProviderError, match="content_filter"):
        Provider(_cfg()).complete("fast", None, "u")


def test_model_routed_by_configured_provider(fake_litellm):
    # Unprefixed "gemini-*" goes to Vertex in litellm; with provider=google the
    # user means the Gemini API (GEMINI_API_KEY).
    from mantis.providers import route_model
    assert route_model("gemini-2.5-flash", "google") == "gemini/gemini-2.5-flash"
    assert route_model("vertex_ai/gemini-2.5-flash", "google") == "vertex_ai/gemini-2.5-flash"
    assert route_model("anthropic/claude-x", "openrouter") == "openrouter/anthropic/claude-x"
    assert route_model("openrouter/anthropic/claude-x", "openrouter") == "openrouter/anthropic/claude-x"
    assert route_model("qwen2.5-coder:7b", "ollama") == "ollama/qwen2.5-coder:7b"
    assert route_model("ollama_chat/qwen", "ollama") == "ollama_chat/qwen"
    assert route_model("claude-x", "anthropic") == "claude-x"
    assert route_model("gemini-2.5-flash", None) == "gemini-2.5-flash"
    p = Provider(_cfg(provider="google", models={"fast": "gemini-2.5-flash"}))
    p.complete("fast", "s", "u")
    assert fake_litellm["calls"][-1]["model"] == "gemini/gemini-2.5-flash"


def test_response_cache_replays_deterministic_calls_only(fake_litellm, tmp_path):
    p = Provider(_cfg())
    p.cache_dir = tmp_path
    a = p.complete("fast", "s", "u", temperature=0.0)
    b = p.complete("fast", "s", "u", temperature=0.0)
    assert len(fake_litellm["calls"]) == 1
    assert b.text == a.text and b.tokens_in == 0 and b.tokens_out == 0
    p.complete("fast", "s", "other", temperature=0.0)
    assert len(fake_litellm["calls"]) == 2
    # Sampling ensembles (ToAST) need distinct draws: never cached.
    p.complete("fast", "s", "u", temperature=0.6)
    p.complete("fast", "s", "u", temperature=0.6)
    assert len(fake_litellm["calls"]) == 4
