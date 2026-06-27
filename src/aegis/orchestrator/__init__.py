"""Dynamic detonation orchestration.

This package defines the *contract* the dynamic sandbox must satisfy — environment
routing, snapshot provisioning, bounded execution, telemetry collection and
guaranteed teardown/rollback — without binding to a hypervisor. A real KVM/libvirt +
Android-emulator backend implements :class:`SandboxOrchestrator`; the control plane
and worker depend only on the abstract interface, so the engine and pipeline work
today and the detonation backend drops in later.
"""

from aegis.orchestrator.base import (
    DetonationResult,
    EnvironmentSpec,
    ExecutionBudget,
    RollbackResult,
    SandboxOrchestrator,
    SandboxSession,
    get_backend,
    register_backend,
)
from aegis.orchestrator.router import route_environment

__all__ = [
    "DetonationResult",
    "EnvironmentSpec",
    "ExecutionBudget",
    "RollbackResult",
    "SandboxOrchestrator",
    "SandboxSession",
    "register_backend",
    "get_backend",
    "route_environment",
]
