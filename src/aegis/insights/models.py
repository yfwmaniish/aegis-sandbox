"""Serializable visualization models derived from an analysis.

These are deterministic roll-ups computed from the static (+ optional dynamic) report —
no LLM required. The UI renders them as a capability radar, a permission heatmap, a
MITRE ATT&CK matrix, and a behaviour/network graph. Everything here is evidence-linked:
each capability axis and ATT&CK technique carries the indicator ids / facts that drove it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

VIZ_SCHEMA_VERSION = "1.0"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class CapabilityAxis(BaseModel):
    key: str
    label: str
    score: int = Field(ge=0, le=100)
    evidence: list[str] = Field(default_factory=list)


class PermissionEntry(BaseModel):
    permission: str
    dangerous: bool = False
    used_at_runtime: bool = False


class PermissionCategory(BaseModel):
    key: str
    label: str
    risk: str = "none"  # none|low|medium|high|critical
    count: int = 0
    permissions: list[PermissionEntry] = Field(default_factory=list)


class AttackTechnique(BaseModel):
    tactic: str
    technique_id: str
    technique: str
    severity: str = "medium"
    source_indicators: list[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str  # sample|capability|host|ioc
    weight: float = 1.0
    detail: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str | None = None
    kind: str = "relates"


class BehaviorGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class Visualizations(BaseModel):
    schema_version: str = VIZ_SCHEMA_VERSION
    generated_at: datetime = Field(default_factory=_utcnow)
    file_type: str = "unknown"
    package: str | None = None
    has_dynamic: bool = False

    capability_radar: list[CapabilityAxis] = Field(default_factory=list)
    permission_heatmap: list[PermissionCategory] = Field(default_factory=list)
    attack_matrix: list[AttackTechnique] = Field(default_factory=list)
    behavior_graph: BehaviorGraph = Field(default_factory=BehaviorGraph)
    top_drivers: list[str] = Field(default_factory=list)
