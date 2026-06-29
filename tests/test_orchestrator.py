"""Tests for orchestrator backend registration and the isolation gate."""

from __future__ import annotations

import pytest

from aegis.orchestrator import isolation
from aegis.orchestrator.shell import CmdResult


def _canned(out: str):
    return lambda *a, **k: CmdResult(0, out, "")


class TestBackendRegistration:
    def test_all_backends_register(self):
        import aegis.orchestrator.avd  # noqa: F401
        import aegis.orchestrator.fake  # noqa: F401
        import aegis.orchestrator.genymotion  # noqa: F401
        from aegis.orchestrator.base import available_backends

        names = available_backends()
        assert {"avd", "fake", "genymotion"} <= set(names)


class TestIsolation:
    def test_reachable_when_ping_succeeds(self, monkeypatch):
        monkeypatch.setattr(isolation, "run", _canned("1 packets transmitted, 1 received, 0% packet loss"))
        assert isolation.device_can_reach_internet("emulator-5554") is True

    def test_not_reachable_when_ping_fails(self, monkeypatch):
        monkeypatch.setattr(isolation, "run", _canned("1 packets transmitted, 0 received, 100% packet loss"))
        assert isolation.device_can_reach_internet("emulator-5554") is False

    def test_assert_isolated_passes_when_offline(self, monkeypatch):
        monkeypatch.setattr(isolation, "run", _canned("100% packet loss"))
        assert isolation.assert_isolated("emulator-5554", require=True) is True

    def test_assert_isolated_aborts_when_online(self, monkeypatch):
        monkeypatch.setattr(isolation, "run", _canned("0% packet loss"))
        with pytest.raises(isolation.IsolationError):
            isolation.assert_isolated("emulator-5554", require=True)

    def test_override_allows_online(self, monkeypatch):
        # require=False must not raise even if the device is reachable (explicit opt-out).
        monkeypatch.setattr(isolation, "run", _canned("0% packet loss"))
        assert isolation.assert_isolated("emulator-5554", require=False) is False
