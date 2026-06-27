"""Abstract sandbox orchestrator contract.

A concrete backend (KVM/libvirt VMs + Android emulator/AOSP) subclasses
:class:`SandboxOrchestrator` and registers itself via :func:`register_backend`. The
worker drives an analysis through ``provision → stage → execute → collect → teardown``
and the ABC pins the invariants the TRD requires:

* bounded execution (:class:`ExecutionBudget` — max runtime, CPU/mem caps, kill-switch)
* mandatory teardown + rollback verification after every run (TR-DYN-03)
* orphaned-session reaping (TR-DYN-02)
* lifecycle event emission left to the caller via the state machine (TR-DYN-01)

Nothing here talks to a hypervisor; this is the seam the real detonation zone plugs
into.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aegis.core.enums import AnalysisProfile, TargetOS


@dataclass(frozen=True, slots=True)
class ExecutionBudget:
    """Hard limits for one detonation run (TRD §5.3 execution budget / kill-switch)."""

    max_runtime_seconds: int = 300
    cpu_cores: int = 2
    memory_mb: int = 4096
    network_policy: str = "sinkhole"  # sinkhole | deny | simulated
    kill_on_budget_exceeded: bool = True


@dataclass(frozen=True, slots=True)
class EnvironmentSpec:
    """The detonation environment selected for a sample."""

    target_os: TargetOS
    profile: AnalysisProfile
    image: str                       # golden image / snapshot id
    arch: str = "x86_64"
    android_api_level: int | None = None
    labels: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class SandboxSession:
    """A provisioned, isolated detonation instance."""

    session_id: str
    analysis_id: str
    spec: EnvironmentSpec
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    snapshot_id: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DetonationResult:
    """Outcome of an execution run. ``raw_refs`` are immutable pointers into the
    artifact store (pcaps, event logs) for the collector to normalise (TR-TEL-02)."""

    session_id: str
    analysis_id: str
    completed: bool
    runtime_seconds: float
    exit_reason: str                 # finished | timeout | killed | crashed
    raw_refs: list[str] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RollbackResult:
    """Result of post-run teardown; ``verified`` must be logged (TR-DYN-03)."""

    session_id: str
    rolled_back: bool
    verified: bool
    detail: str = ""


class SandboxOrchestrator(ABC):
    """Interface every detonation backend implements."""

    #: Which target OSes this backend can detonate.
    supported_os: frozenset[TargetOS] = frozenset()

    @abstractmethod
    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        """Provision an isolated instance from a clean snapshot."""

    @abstractmethod
    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:
        """Transfer the sample into the instance via the one-way staging path."""

    @abstractmethod
    def execute(self, session: SandboxSession, budget: ExecutionBudget) -> DetonationResult:
        """Run the sample under the given budget, enforcing the kill-switch."""

    @abstractmethod
    def collect(self, session: SandboxSession) -> DetonationResult:
        """Export raw telemetry/artifacts out of the isolated zone."""

    @abstractmethod
    def teardown(self, session: SandboxSession) -> RollbackResult:
        """Destroy the instance and verify snapshot rollback (mandatory)."""

    @abstractmethod
    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        """Watchdog: destroy sessions exceeding their budget; return reaped ids."""

    def can_handle(self, target_os: TargetOS) -> bool:
        return target_os in self.supported_os


# ── Backend registry ─────────────────────────────────────────────────────────
# Lets the deployment choose a backend by name (env/config) without the control
# plane importing a specific hypervisor module.

_BACKENDS: dict[str, type[SandboxOrchestrator]] = {}


def register_backend(name: str, cls: type[SandboxOrchestrator]) -> None:
    _BACKENDS[name] = cls


def get_backend(name: str) -> type[SandboxOrchestrator]:
    try:
        return _BACKENDS[name]
    except KeyError as exc:
        available = ", ".join(sorted(_BACKENDS)) or "(none registered)"
        raise KeyError(f"no sandbox backend '{name}'; registered: {available}") from exc


def available_backends() -> list[str]:
    return sorted(_BACKENDS)
