"""Windows (PE) detonation backend — honest scaffold.

Real PE detonation requires an isolated Windows guest with an in-guest agent (procmon /
ETW / API monitor) — infrastructure that must be provisioned deliberately, and that we
must never approximate with fabricated telemetry. So this backend integrates with an
external, user-provided Windows sandbox VM (configured via ``WINDOWS_VM_NAME`` and
``WINDOWS_AGENT_URL``) and, when none is configured, **refuses to run** rather than
emitting fake results. That keeps the "no simulated telemetry for real verdicts" rule
intact: an unconfigured Windows detonation fails cleanly and the analysis degrades to
static-only, instead of silently inventing behaviour.

The lifecycle seam (provision → stage → execute → collect → teardown) is implemented so a
concrete Hyper-V / Windows Sandbox agent can be dropped in without touching the pipeline.
"""

from __future__ import annotations

import uuid

from aegis.core.enums import TargetOS
from aegis.orchestrator.base import (
    DetonationResult,
    EnvironmentSpec,
    ExecutionBudget,
    RollbackResult,
    SandboxOrchestrator,
    SandboxSession,
    register_backend,
)


class WindowsBackendUnavailable(RuntimeError):
    """Raised when no isolated Windows detonation guest/agent is configured."""


class WindowsOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.WINDOWS})

    def __init__(self, settings=None, store=None):
        self.settings = settings
        self.store = store
        self.vm_name = getattr(settings, "windows_vm_name", None)
        self.agent_url = getattr(settings, "windows_agent_url", None)

    @staticmethod
    def preflight() -> dict[str, bool]:
        return {"windows_vm_configured": False, "windows_agent_configured": False}

    def _configured(self) -> bool:
        return bool(self.vm_name and self.agent_url)

    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        if not self._configured():
            raise WindowsBackendUnavailable(
                "Windows PE detonation is not configured. Provision an isolated Windows "
                "guest (Hyper-V / Windows Sandbox) with an in-guest telemetry agent and set "
                "WINDOWS_VM_NAME + WINDOWS_AGENT_URL. Refusing to emit fabricated telemetry."
            )
        # A concrete agent integration would revert the guest to a clean snapshot here.
        return SandboxSession(
            session_id=f"win-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id, spec=spec, snapshot_id=self.vm_name,
            extra={"device_name": self.vm_name or "windows"},
        )

    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:  # pragma: no cover
        raise WindowsBackendUnavailable("no in-guest agent configured to stage the sample")

    def execute(self, session: SandboxSession, budget: ExecutionBudget) -> DetonationResult:  # pragma: no cover
        raise WindowsBackendUnavailable("no in-guest agent configured to execute the sample")

    def collect(self, session: SandboxSession) -> DetonationResult:  # pragma: no cover
        raise WindowsBackendUnavailable("no in-guest agent configured to collect telemetry")

    def teardown(self, session: SandboxSession) -> RollbackResult:  # pragma: no cover
        return RollbackResult(session_id=session.session_id, rolled_back=True, verified=False,
                              detail="no Windows guest to revert")

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        return []


register_backend("windows", WindowsOrchestrator)
