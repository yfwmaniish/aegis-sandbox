"""Environment routing rules (TRD §5.3).

Maps a detected file type to the detonation OS:
``PE → Windows, ELF → Linux, APK → Android``. Kept separate from the orchestrator
backend so routing policy can be tested and evolved independently of any hypervisor.
"""

from __future__ import annotations

from aegis.core.enums import TargetOS
from aegis.static.models import FileType

_ROUTE: dict[FileType, TargetOS] = {
    FileType.PE: TargetOS.WINDOWS,
    FileType.ELF: TargetOS.LINUX,
    FileType.APK: TargetOS.ANDROID,
    FileType.DEX: TargetOS.ANDROID,
    FileType.MACHO: TargetOS.LINUX,  # closest available; macOS detonation out of scope
}


class UnroutableSample(Exception):
    """Raised when no detonation environment matches a sample's file type."""


def route_environment(file_type: FileType) -> TargetOS:
    """Return the detonation :class:`TargetOS` for ``file_type``.

    Raises :class:`UnroutableSample` for types with no dynamic environment (e.g.
    plain ZIP / UNKNOWN) — those are static-only."""
    try:
        return _ROUTE[file_type]
    except KeyError as exc:
        raise UnroutableSample(f"no detonation environment for file type {file_type.value}") from exc


def is_routable(file_type: FileType) -> bool:
    return file_type in _ROUTE
