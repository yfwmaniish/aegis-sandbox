"""Dynamic analysis: normalized runtime telemetry, detectors and the dynamic report.

This package is intentionally infra-agnostic — it consumes raw telemetry (logcat,
Frida JSON, dumpsys, pcap) and produces canonical :class:`NormalizedEvent` streams and
findings. The actual detonation (booting an Android VM, installing, running, tearing
down) lives behind the :mod:`aegis.orchestrator` backend, so everything here is
testable without a hypervisor.
"""

from aegis.dynamic.models import (
    DYNAMIC_SCHEMA_VERSION,
    DynamicReport,
    EventCategory,
    NormalizedEvent,
)

__all__ = [
    "DYNAMIC_SCHEMA_VERSION",
    "DynamicReport",
    "EventCategory",
    "NormalizedEvent",
]
