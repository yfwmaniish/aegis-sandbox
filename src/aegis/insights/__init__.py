"""Deterministic visualization/insight layer for an analysis (no LLM required)."""

from __future__ import annotations

from aegis.insights.build import build_visualizations
from aegis.insights.models import Visualizations

__all__ = ["Visualizations", "build_visualizations"]
