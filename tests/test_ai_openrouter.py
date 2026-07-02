"""Tests for the OpenRouter LLM path: JSON parsing + provider selection (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from types import SimpleNamespace  # noqa: E402

from aegis.ai.understanding import _parse_understanding_json  # noqa: E402
from aegis.core.config import Settings  # noqa: E402

# Underlying property functions, tested in isolation (avoids .env/env interference).
_provider = Settings.llm_provider.fget
_enabled = Settings.llm_enabled.fget

_VALID = (
    '{"summary":"s","what_it_is":"w","intent":"i","behavior_workflow":[],'
    '"capabilities":["c"],"attack_techniques":[{"technique_id":"T1071.001",'
    '"name":"Web Protocols","why":"c2"}],"risk_assessment":"r","confidence":"high",'
    '"limitations":[],"recommended_actions":["block"]}'
)


def test_parse_plain_json():
    u = _parse_understanding_json(_VALID)
    assert u is not None and u.summary == "s"
    assert u.attack_techniques[0].technique_id == "T1071.001"


def test_parse_strips_code_fences_and_prose():
    fenced = "Here is the analysis:\n```json\n" + _VALID + "\n```\nHope that helps."
    u = _parse_understanding_json(fenced)
    assert u is not None and u.confidence.value == "high"


def test_parse_rejects_garbage():
    assert _parse_understanding_json("not json at all") is None
    assert _parse_understanding_json("") is None
    assert _parse_understanding_json('{"summary": "missing required fields"}') is None


def test_provider_selection():
    assert _provider(SimpleNamespace(anthropic_api_key="k", openrouter_api_key="")) == "anthropic"
    assert _provider(SimpleNamespace(anthropic_api_key="", openrouter_api_key="k")) == "openrouter"
    assert _provider(SimpleNamespace(anthropic_api_key="", openrouter_api_key="")) is None
    # Anthropic wins when both are set.
    assert _provider(SimpleNamespace(anthropic_api_key="a", openrouter_api_key="o")) == "anthropic"
    assert _enabled(SimpleNamespace(anthropic_api_key="", openrouter_api_key="k")) is True
