"""Analysis state machine.

Enforces that only legal transitions occur (SR-1 / TR-STM-01), produces an audit
event for every transition (SR-2 / TR-STM-02), and caps retries from failure states
by policy (TR-STM-03). The machine is intentionally pure/in-memory: persistence of
the resulting :class:`StateTransition` records is the caller's job (the API/worker
writes them to the audit log + analyses table), which keeps this unit trivially
testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.core.enums import AnalysisState

S = AnalysisState

# Legal forward transitions. Failure states allow a single hop back toward the work
# that failed (retry); the caller gates how many times via ``max_retries``.
_ALLOWED: dict[AnalysisState, frozenset[AnalysisState]] = {
    S.CREATED: frozenset({S.QUEUED, S.TERMINATED_POLICY}),
    # PROCESSING is the static-only fast path (no detonation): queued → processing.
    S.QUEUED: frozenset({S.PROVISIONING, S.PROCESSING, S.TERMINATED_POLICY}),
    S.PROVISIONING: frozenset({S.RUNNING, S.FAILED_PROVISIONING, S.TERMINATED_POLICY}),
    S.RUNNING: frozenset({S.COLLECTING, S.FAILED_RUNTIME, S.TERMINATED_POLICY}),
    S.COLLECTING: frozenset({S.PROCESSING, S.FAILED_RUNTIME, S.TERMINATED_POLICY}),
    S.PROCESSING: frozenset({S.REPORTING, S.FAILED_PROCESSING, S.TERMINATED_POLICY}),
    S.REPORTING: frozenset({S.COMPLETED, S.FAILED_PROCESSING}),
    S.COMPLETED: frozenset(),
    # Retry edges (policy-capped by the caller).
    S.FAILED_PROVISIONING: frozenset({S.QUEUED, S.TERMINATED_POLICY}),
    S.FAILED_RUNTIME: frozenset({S.QUEUED, S.TERMINATED_POLICY}),
    S.FAILED_PROCESSING: frozenset({S.PROCESSING, S.TERMINATED_POLICY}),
    S.TERMINATED_POLICY: frozenset(),
}

TERMINAL_STATES: frozenset[AnalysisState] = frozenset({S.COMPLETED, S.TERMINATED_POLICY})
FAILURE_STATES: frozenset[AnalysisState] = frozenset(
    {S.FAILED_PROVISIONING, S.FAILED_RUNTIME, S.FAILED_PROCESSING, S.TERMINATED_POLICY}
)
RETRIABLE_STATES: frozenset[AnalysisState] = frozenset(
    {S.FAILED_PROVISIONING, S.FAILED_RUNTIME, S.FAILED_PROCESSING}
)


class InvalidTransition(Exception):
    """Raised when an illegal state transition is attempted (TR-STM-01)."""

    def __init__(self, src: AnalysisState, dst: AnalysisState):
        super().__init__(f"illegal transition {src.value} → {dst.value}")
        self.src = src
        self.dst = dst


@dataclass(frozen=True, slots=True)
class StateTransition:
    """Audit record emitted on every state change (SR-2)."""

    analysis_id: str
    from_state: AnalysisState
    to_state: AnalysisState
    reason: str
    actor: str  # "system", a worker name, or a user id
    at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "reason": self.reason,
            "actor": self.actor,
            "at": self.at.isoformat(),
        }


def can_transition(src: AnalysisState, dst: AnalysisState) -> bool:
    return dst in _ALLOWED.get(src, frozenset())


def allowed_next(src: AnalysisState) -> frozenset[AnalysisState]:
    return _ALLOWED.get(src, frozenset())


def is_terminal(state: AnalysisState) -> bool:
    return state in TERMINAL_STATES


class AnalysisStateMachine:
    """Tracks one analysis's state and produces audit transitions.

    Construct with the analysis id and current state, call :meth:`transition` to move
    it. Every successful call returns a :class:`StateTransition` for the caller to
    persist. Retries from failure states are capped by ``max_retries``.
    """

    def __init__(
        self,
        analysis_id: str,
        state: AnalysisState = AnalysisState.CREATED,
        *,
        retries: int = 0,
        max_retries: int = 2,
    ):
        self.analysis_id = analysis_id
        self.state = state
        self.retries = retries
        self.max_retries = max_retries

    def transition(
        self, dst: AnalysisState, *, reason: str = "", actor: str = "system"
    ) -> StateTransition:
        if not can_transition(self.state, dst):
            raise InvalidTransition(self.state, dst)

        # A move *out of* a retriable failure state back into the pipeline counts as
        # a retry and is policy-capped (TR-STM-03).
        if self.state in RETRIABLE_STATES and dst not in FAILURE_STATES:
            if self.retries >= self.max_retries:
                raise InvalidTransition(self.state, dst)
            self.retries += 1

        prev = self.state
        self.state = dst
        return StateTransition(
            analysis_id=self.analysis_id,
            from_state=prev,
            to_state=dst,
            reason=reason,
            actor=actor,
        )

    @property
    def is_terminal(self) -> bool:
        return is_terminal(self.state)

    @property
    def can_retry(self) -> bool:
        return self.state in RETRIABLE_STATES and self.retries < self.max_retries
