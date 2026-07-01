"""Corpus catch-rate scoreboard: batch analysis roll-up (FR: aggregate metrics)."""

from __future__ import annotations

from aegis.corpus.models import Scoreboard, ScanRow
from aegis.corpus.scan import scan_folder, scan_path
from aegis.corpus.scoreboard import build_scoreboard, row_from_report

__all__ = [
    "ScanRow",
    "Scoreboard",
    "build_scoreboard",
    "row_from_report",
    "scan_folder",
    "scan_path",
]
