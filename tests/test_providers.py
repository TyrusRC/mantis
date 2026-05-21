"""Tests for the provider abstraction. litellm is mocked end-to-end."""
from __future__ import annotations

import sys
import types

import pytest

from mantis.config import Config
from mantis.providers import (
    LLMResponse,
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
