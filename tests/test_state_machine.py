"""Tests for the analysis state machine and environment router."""

from __future__ import annotations

import pytest

from aegis.core.enums import AnalysisState as S
from aegis.core.enums import TargetOS
from aegis.core.state import (
    AnalysisStateMachine,
    InvalidTransition,
    can_transition,
    is_terminal,
)
from aegis.orchestrator.router import UnroutableSample, is_routable, route_environment
from aegis.static.models import FileType


class TestStateMachine:
    def test_happy_path(self):
        sm = AnalysisStateMachine("a1", S.CREATED)
        path = [S.QUEUED, S.PROVISIONING, S.RUNNING, S.COLLECTING,
                S.PROCESSING, S.REPORTING, S.COMPLETED]
        for nxt in path:
            t = sm.transition(nxt, reason="step", actor="worker")
            assert t.to_state == nxt
            assert t.analysis_id == "a1"
        assert sm.is_terminal

    def test_illegal_transition_raises(self):
        sm = AnalysisStateMachine("a2", S.CREATED)
        with pytest.raises(InvalidTransition):
            sm.transition(S.RUNNING)  # can't skip straight to running

    def test_every_transition_emits_audit(self):
        sm = AnalysisStateMachine("a3", S.CREATED)
        t = sm.transition(S.QUEUED, reason="enqueued", actor="api")
        d = t.as_dict()
        assert d["from_state"] == "created"
        assert d["to_state"] == "queued"
        assert d["reason"] == "enqueued"
        assert d["actor"] == "api"
        assert "at" in d

    def test_terminal_states_have_no_exits(self):
        assert is_terminal(S.COMPLETED)
        assert is_terminal(S.TERMINATED_POLICY)
        sm = AnalysisStateMachine("a4", S.COMPLETED)
        with pytest.raises(InvalidTransition):
            sm.transition(S.QUEUED)

    def test_retry_capped_by_policy(self):
        sm = AnalysisStateMachine("a5", S.FAILED_RUNTIME, retries=0, max_retries=2)
        # Two retries allowed back to queued.
        sm.transition(S.QUEUED, reason="retry-1")
        sm.transition(S.PROVISIONING)
        sm.transition(S.FAILED_PROVISIONING)
        sm.transition(S.QUEUED, reason="retry-2")
        assert sm.retries == 2
        # Third retry must be refused.
        sm.transition(S.PROVISIONING)
        sm.transition(S.FAILED_PROVISIONING)
        with pytest.raises(InvalidTransition):
            sm.transition(S.QUEUED, reason="retry-3")

    def test_failed_state_can_terminate(self):
        sm = AnalysisStateMachine("a6", S.FAILED_RUNTIME)
        t = sm.transition(S.TERMINATED_POLICY, reason="give up")
        assert t.to_state == S.TERMINATED_POLICY

    def test_can_transition_helper(self):
        assert can_transition(S.RUNNING, S.COLLECTING)
        assert not can_transition(S.RUNNING, S.COMPLETED)


class TestRouter:
    def test_routes(self):
        assert route_environment(FileType.PE) == TargetOS.WINDOWS
        assert route_environment(FileType.ELF) == TargetOS.LINUX
        assert route_environment(FileType.APK) == TargetOS.ANDROID
        assert route_environment(FileType.DEX) == TargetOS.ANDROID

    def test_unroutable(self):
        assert not is_routable(FileType.UNKNOWN)
        with pytest.raises(UnroutableSample):
            route_environment(FileType.UNKNOWN)
        with pytest.raises(UnroutableSample):
            route_environment(FileType.ZIP)
