"""Tests for the AI understanding layer (Claude). The model call is mocked — no
network, no API key required."""

from __future__ import annotations

import json

from aegis.ai import understanding as U
from aegis.ai.understanding import AnalysisUnderstanding


def _clear_settings():
    import aegis.core.config as cfg

    cfg.get_settings.cache_clear()


REPORT = {
    "file_type": "apk",
    "size": 25531,
    "hashes": {"sha256": "abc"},
    "entropy": {"overall": 6.5, "packing_likelihood": "medium"},
    "indicators": [
        {"id": "net.hardcoded_ip_c2", "severity": "high", "title": "C2",
         "inference": "C2", "evidence": ["http://1.2.3.4/x"]},
    ],
    "iocs": [{"type": "url", "value": "http://1.2.3.4/x", "confidence": 0.8, "source": "strings"}],
    "apk": {"package": "com.x", "permissions": ["android.permission.SEND_SMS"]},
    "pe": None, "elf": None,
}


class TestConfigGate:
    def test_not_configured_without_key(self, monkeypatch):
        # Empty env vars override any .env values (both providers must be unset).
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        monkeypatch.setenv("OPENROUTER_API_KEY", "")
        _clear_settings()
        try:
            assert U.is_configured() is False
            result = U.generate_understanding(REPORT)
            assert result.available is False
            assert "ANTHROPIC_API_KEY" in result.reason
        finally:
            _clear_settings()


class TestCompaction:
    def test_compact_report_bounds_and_drops_bulky(self):
        report = dict(REPORT)
        report["pe"] = {"machine": "x86", "sections": [{"name": ".text"}], "imports": [1, 2, 3]}
        out = json.loads(U._compact_report(report, None))
        assert out["static"]["file_type"] == "apk"
        assert "sections" not in out["static"]["pe"]   # bulky fields dropped
        assert "imports" not in out["static"]["pe"]
        assert out["static"]["pe"]["machine"] == "x86"

    def test_includes_dynamic_when_present(self):
        dyn = {"exit_reason": "finished", "network_peers": [{"host": "1.2.3.4"}],
               "indicators": [{"id": "dyn.runtime_c2", "severity": "high"}]}
        out = json.loads(U._compact_report(REPORT, dyn))
        assert out["dynamic"]["exit_reason"] == "finished"
        assert out["dynamic"]["network_peers"][0]["host"] == "1.2.3.4"


class _FakeResp:
    def __init__(self, parsed, stop_reason="end_turn"):
        self.parsed_output = parsed
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, resp):
        self._resp = resp
        self.last_kwargs = None

    def parse(self, **kwargs):
        self.last_kwargs = kwargs
        _FakeMessages.captured = kwargs
        return self._resp


def _install_fake_anthropic(monkeypatch, resp):
    import anthropic

    fake_messages = _FakeMessages(resp)

    class FakeClient:
        def __init__(self, **kw):
            self.messages = fake_messages

    monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
    return fake_messages


class TestGeneration:
    def test_successful_generation(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        _clear_settings()
        try:
            parsed = AnalysisUnderstanding(
                summary="Trojanized app", what_it_is="repackaged APK",
                intent="spyware", risk_assessment="high",
                capabilities=["SMS interception"], recommended_actions=["block C2 IP"],
            )
            fake = _install_fake_anthropic(monkeypatch, _FakeResp(parsed))
            result = U.generate_understanding(REPORT)
            assert result.available is True
            assert result.understanding.summary == "Trojanized app"
            assert result.review_required is True
            # uses the configured model + adaptive thinking + structured output
            assert fake.last_kwargs["model"] == "claude-opus-4-8"
            assert fake.last_kwargs["thinking"] == {"type": "adaptive"}
            assert fake.last_kwargs["output_format"] is AnalysisUnderstanding
        finally:
            _clear_settings()

    def test_refusal_is_handled(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        _clear_settings()
        try:
            _install_fake_anthropic(monkeypatch, _FakeResp(None, stop_reason="refusal"))
            result = U.generate_understanding(REPORT)
            assert result.available is False
            assert "declined" in result.reason
        finally:
            _clear_settings()

    def test_api_error_is_handled(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        _clear_settings()
        try:
            import anthropic

            class BoomMessages:
                def parse(self, **kwargs):
                    raise anthropic.APIError("boom", request=None, body=None)

            class FakeClient:
                def __init__(self, **kw):
                    self.messages = BoomMessages()

            monkeypatch.setattr(anthropic, "Anthropic", FakeClient)
            result = U.generate_understanding(REPORT)
            assert result.available is False
            assert "Claude API error" in result.reason
        finally:
            _clear_settings()
