"""Thin subprocess helpers for driving external CLIs (gmtool, adb, frida).

Centralises timeout handling and a stable result type so the Genymotion backend stays
readable. Never raises on non-zero exit — callers inspect :class:`CmdResult`.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CmdResult:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def have(tool: str) -> bool:
    """Is ``tool`` on PATH?"""
    return shutil.which(tool) is not None


def run(args: list[str], *, timeout: float = 120.0, input_text: str | None = None) -> CmdResult:
    """Run ``args`` with a timeout; capture stdout/stderr as text. Timeout/!found are
    surfaced as a non-zero :class:`CmdResult`, not exceptions."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            # adb/logcat/dumpsys emit UTF-8 (and occasional raw bytes); without this
            # Windows decodes as cp1252 and a single bad byte crashes the reader thread.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            input=input_text,
            check=False,
        )
        return CmdResult(proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return CmdResult(124, exc.stdout or "", f"timeout after {timeout}s")
    except FileNotFoundError as exc:
        return CmdResult(127, "", str(exc))
