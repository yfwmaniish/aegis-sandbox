"""Generate an analyst-grade understanding of an analysis using Claude.

The structured output (:class:`AnalysisUnderstanding`) is produced via
``client.messages.parse`` with a Pydantic schema, on ``claude-opus-4-8`` with adaptive
thinking. Everything is best-effort: missing key, API error, or a safety refusal all
return an :class:`UnderstandingResult` with ``available=False`` and a reason, never an
exception that would break the request.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field

from aegis.core.config import get_settings

# Bump when the prompt/schema changes (stored with each generation, TR-REP-03).
PROMPT_VERSION = "1.0"

_SYSTEM = (
    "You are a senior malware analyst assisting authorized, defensive malware analysis. "
    "You are given the deterministic static (and, when present, dynamic) findings from an "
    "automated sandbox. Produce a precise, evidence-grounded understanding for another "
    "analyst.\n\n"
    "Rules:\n"
    "- Defensive only. Never provide operational attack instructions, exploit code, or "
    "step-by-step abuse guidance. Describe behaviour to enable detection and response.\n"
    "- Ground every claim in the provided evidence. Distinguish observed facts from "
    "inference. If evidence is thin, say so and lower your confidence.\n"
    "- Do not invent IOCs, permissions, or capabilities that aren't in the input.\n"
    "- Map behaviours to MITRE ATT&CK only where the evidence supports it.\n"
    "- Be concise and concrete; this is read by an expert, not an executive."
)


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class WorkflowStep(BaseModel):
    phase: str = Field(description="Short phase label, e.g. 'Install', 'C2', 'Exfiltration'")
    action: str = Field(description="What the app does in this step")
    evidence: str = Field(description="The finding/IOC/API this is grounded in")


class AttackTechnique(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK id, e.g. T1636.004")
    name: str
    why: str = Field(description="Why this technique applies, grounded in evidence")


class AnalysisUnderstanding(BaseModel):
    """Structured, human-review-required understanding of a sample."""

    summary: str = Field(description="2-4 sentence executive summary")
    what_it_is: str = Field(description="What this file/app actually is")
    intent: str = Field(description="Hypothesized purpose/intent of the sample")
    behavior_workflow: list[WorkflowStep] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    risk_assessment: str = Field(description="Why this risk level; what's the impact")
    confidence: Confidence = Confidence.MEDIUM
    limitations: list[str] = Field(default_factory=list, description="Gaps / what's unverified")
    recommended_actions: list[str] = Field(default_factory=list, description="Defensive steps")


@dataclass(slots=True)
class UnderstandingResult:
    available: bool
    understanding: AnalysisUnderstanding | None = None
    model: str | None = None
    prompt_version: str = PROMPT_VERSION
    reason: str | None = None  # populated when available is False
    review_required: bool = True


def is_configured() -> bool:
    return get_settings().llm_enabled


def _compact_report(report: dict, dynamic: dict | None) -> str:
    """Trim the full report blobs to the high-signal fields the model needs, bounded."""
    static_view = {
        "file_type": report.get("file_type"),
        "size": report.get("size"),
        "hashes": report.get("hashes"),
        "entropy": report.get("entropy"),
        "indicators": [
            {k: i.get(k) for k in ("id", "severity", "title", "inference", "evidence")}
            for i in report.get("indicators", [])[:40]
        ],
        "iocs": report.get("iocs", [])[:60],
        "apk": report.get("apk"),
        "pe": _drop_bulky(report.get("pe")),
        "elf": _drop_bulky(report.get("elf")),
    }
    payload: dict = {"static": static_view}
    if dynamic:
        payload["dynamic"] = {
            "exit_reason": dynamic.get("exit_reason"),
            "granted_permissions": dynamic.get("granted_permissions"),
            "network_peers": dynamic.get("network_peers"),
            "dropped_files": dynamic.get("dropped_files"),
            "loaded_dex": dynamic.get("loaded_dex"),
            "category_counts": dynamic.get("category_counts"),
            "indicators": [
                {k: i.get(k) for k in ("id", "severity", "title", "inference", "evidence")}
                for i in dynamic.get("indicators", [])[:40]
            ],
        }
    return json.dumps(payload, default=str)[:60_000]


def _drop_bulky(block: dict | None) -> dict | None:
    """Drop verbose per-section/import lists that bloat the prompt without adding signal."""
    if not block:
        return block
    keep = {k: v for k, v in block.items() if k not in {"sections", "imports", "imported_symbols"}}
    return keep


def generate_understanding(report: dict, dynamic: dict | None = None) -> UnderstandingResult:
    """Call Claude to produce a structured understanding of the analysis."""
    settings = get_settings()
    if not settings.llm_enabled:
        return UnderstandingResult(
            available=False,
            reason="LLM not configured — set ANTHROPIC_API_KEY to enable AI understanding.",
        )

    try:
        import anthropic  # lazy: optional dependency
    except ImportError:
        return UnderstandingResult(available=False, reason="anthropic SDK not installed")

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    user_prompt = (
        "Analyze the following sandbox findings and return your structured understanding.\n\n"
        f"FINDINGS (JSON):\n{_compact_report(report, dynamic)}"
    )

    try:
        resp = client.messages.parse(
            model=settings.llm_model,
            max_tokens=settings.llm_max_tokens,
            thinking={"type": "adaptive"},
            system=_SYSTEM,
            messages=[{"role": "user", "content": user_prompt}],
            output_format=AnalysisUnderstanding,
        )
    except anthropic.APIError as exc:
        return UnderstandingResult(available=False, model=settings.llm_model,
                                   reason=f"Claude API error: {exc}")

    if resp.stop_reason == "refusal":
        return UnderstandingResult(available=False, model=settings.llm_model,
                                   reason="model declined to analyze this sample")
    parsed = resp.parsed_output
    if parsed is None:
        return UnderstandingResult(available=False, model=settings.llm_model,
                                   reason="model returned no parseable output")

    return UnderstandingResult(
        available=True, understanding=parsed, model=settings.llm_model,
        prompt_version=PROMPT_VERSION, review_required=True,
    )
