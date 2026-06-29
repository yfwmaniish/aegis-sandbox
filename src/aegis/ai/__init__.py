"""AI-assisted analysis understanding (Claude).

Turns the deterministic static + dynamic findings into an analyst-grade narrative:
what the sample is, what it does, a step-by-step behaviour workflow, MITRE ATT&CK
mapping, risk assessment, confidence, limitations and defensive recommendations.

Defensive framing only (Program Doc §3: no operational abuse instructions). Output is
flagged human-review-required and stored with model + prompt-template version
(TR-REP-03). The Claude dependency is imported lazily and the feature degrades to a
clear "not configured" result when ``ANTHROPIC_API_KEY`` is unset.
"""

from aegis.ai.understanding import (
    PROMPT_VERSION,
    AnalysisUnderstanding,
    UnderstandingResult,
    generate_understanding,
    is_configured,
)

__all__ = [
    "PROMPT_VERSION",
    "AnalysisUnderstanding",
    "UnderstandingResult",
    "generate_understanding",
    "is_configured",
]
