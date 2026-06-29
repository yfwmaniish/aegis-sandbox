"""Canonical dynamic-analysis schema.

``NormalizedEvent`` is the unified runtime event envelope from TRD §6.2 — every
collector (logcat, Frida, dumpsys, pcap) maps into it, and every downstream consumer
(detectors, timeline, report) reads only this. ``DynamicReport`` aggregates a run:
the event stream plus behaviour roll-ups (permissions actually used, network peers,
dropped files, loaded DEX) and the run's lifecycle outcome.

Each normalized event keeps a ``raw_ref`` pointer back to immutable raw evidence
(TR-TEL-02), so every dynamic finding is traceable to the bytes that produced it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from aegis.static.models import SuspiciousIndicator

DYNAMIC_SCHEMA_VERSION = "1.0"


def _net_host(value: str) -> str:
    """Extract a host from a network event value (URL or bare host[:port])."""
    if value.startswith(("http://", "https://")):
        return urlparse(value).hostname or value
    return value.split("/")[0].split(":")[0]


class EventCategory(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    IPC = "ipc"
    UI = "ui"
    ACCESSIBILITY = "accessibility"
    SMS = "sms"
    NOTIFICATION = "notification"
    PERMISSION = "permission"
    CRYPTO = "crypto"
    EXEC = "exec"
    DEX_LOAD = "dex_load"
    TELEPHONY = "telephony"
    LOCATION = "location"
    MEDIA = "media"
    LOG = "log"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EventSubject(BaseModel):
    process: str | None = None
    pid: int | None = None
    path: str | None = None


class EventObject(BaseModel):
    type: str | None = None   # file|domain|ip|package|component|resource|number|...
    value: str | None = None


class NormalizedEvent(BaseModel):
    """One runtime observation, normalized across collectors (TRD §6.2 envelope)."""

    schema_version: str = DYNAMIC_SCHEMA_VERSION
    timestamp: datetime = Field(default_factory=_utcnow)
    platform: str = "android"
    category: EventCategory
    action: str
    subject: EventSubject = Field(default_factory=EventSubject)
    object: EventObject = Field(default_factory=EventObject)
    raw_ref: str | None = None          # opaque://collector/source/id
    collector: str = "unknown"
    collector_version: str = "1.0"
    detail: dict = Field(default_factory=dict)


class NetworkPeer(BaseModel):
    host: str
    port: int | None = None
    protocol: str | None = None         # tcp|udp|tls|http
    bytes_out: int = 0
    bytes_in: int = 0


class DynamicEnvironment(BaseModel):
    backend: str = "unknown"            # genymotion|fake|...
    device: str | None = None
    android_version: str | None = None
    image: str | None = None
    network_policy: str = "sinkhole"


class DynamicReport(BaseModel):
    schema_version: str = DYNAMIC_SCHEMA_VERSION
    created_at: datetime = Field(default_factory=_utcnow)

    package: str | None = None
    profile: str = "standard"
    environment: DynamicEnvironment = Field(default_factory=DynamicEnvironment)

    started_at: datetime | None = None
    ended_at: datetime | None = None
    runtime_seconds: float = 0.0
    exit_reason: str = "unknown"        # finished|timeout|killed|crashed|install_failed

    # Behaviour roll-ups.
    requested_permissions: list[str] = Field(default_factory=list)
    granted_permissions: list[str] = Field(default_factory=list)
    used_permissions: list[str] = Field(default_factory=list)
    network_peers: list[NetworkPeer] = Field(default_factory=list)
    dropped_files: list[str] = Field(default_factory=list)
    loaded_dex: list[str] = Field(default_factory=list)
    started_components: list[str] = Field(default_factory=list)
    category_counts: dict[str, int] = Field(default_factory=dict)

    # Event sample (full stream is persisted/indexed separately to bound size).
    event_count: int = 0
    events: list[NormalizedEvent] = Field(default_factory=list)
    raw_refs: list[str] = Field(default_factory=list)

    indicators: list[SuspiciousIndicator] = Field(default_factory=list)
    collector_errors: dict[str, str] = Field(default_factory=dict)

    def summarize(self) -> None:
        """Recompute roll-ups from the event stream."""
        counts: dict[str, int] = {}
        peers: dict[tuple[str, int | None], NetworkPeer] = {}
        used: set[str] = set()
        dropped: set[str] = set()
        dex: set[str] = set()
        comps: set[str] = set()
        for e in self.events:
            counts[e.category.value] = counts.get(e.category.value, 0) + 1
            if e.category == EventCategory.NETWORK and e.object.value:
                host = _net_host(e.object.value)
                port = e.detail.get("port")
                peers.setdefault((host, port), NetworkPeer(
                    host=host, port=port, protocol=e.detail.get("protocol"),
                ))
            elif e.category == EventCategory.PERMISSION and e.action == "used" and e.object.value:
                used.add(e.object.value)
            elif e.category == EventCategory.FILE and e.object.value:
                # Our file hook instruments writes; treat any file event as a drop.
                dropped.add(e.object.value)
            elif e.category == EventCategory.DEX_LOAD and e.object.value:
                dex.add(e.object.value)
            elif e.category == EventCategory.PROCESS and e.action == "start_component" and e.object.value:
                comps.add(e.object.value)
        self.category_counts = counts
        self.event_count = len(self.events)
        if peers:
            self.network_peers = list(peers.values())
        if used:
            self.used_permissions = sorted(used)
        if dropped:
            self.dropped_files = sorted(dropped)
        if dex:
            self.loaded_dex = sorted(dex)
        if comps:
            self.started_components = sorted(comps)
