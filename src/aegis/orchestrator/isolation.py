"""Network-isolation enforcement for detonation devices.

The platform must never let a live sample phone home or spread (NFR-1 / TRD §4.2).
This module provides two host-agnostic primitives driven over ``adb``:

* :func:`enforce_offline` — best-effort: turn off the device's radios / enable airplane
  mode so the guest has no egress (adb keeps working on the emulator's separate channel).
* :func:`device_can_reach_internet` — actively probe outbound reachability.

The orchestrator calls both in ``provision``: enforce, then verify, and **abort the run**
if the device can still reach the internet (when ``DYNAMIC_REQUIRE_ISOLATION`` is set).
This makes "did I configure isolation correctly?" a non-issue — the engine checks.
"""

from __future__ import annotations

from aegis.orchestrator.shell import run


class IsolationError(RuntimeError):
    """Raised when a device cannot be confirmed isolated from the internet."""


def enforce_offline(serial: str | None) -> None:
    """Best-effort: cut the device's network egress while keeping adb alive."""
    base = ["adb"] + (["-s", serial] if serial else [])
    # Order matters little; all are best-effort and idempotent.
    run([*base, "shell", "svc", "data", "disable"], timeout=15)
    run([*base, "shell", "svc", "wifi", "disable"], timeout=15)
    run([*base, "shell", "settings", "put", "global", "airplane_mode_on", "1"], timeout=15)
    run([*base, "shell", "su", "-c",
         "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true"], timeout=15)


def _ping_reachable(out: str) -> bool:
    """Interpret ``ping`` output. Checks failure markers first — note '0% packet loss'
    is a substring of '100% packet loss', so order matters."""
    out = out.lower()
    if any(m in out for m in ("100% packet loss", "0 received", "0 packets received",
                              "unreachable", "bad address", "unknown host")):
        return False
    return any(m in out for m in ("0% packet loss", "1 received", "1 packets received"))


def device_can_reach_internet(serial: str | None) -> bool:
    """Probe outbound reachability from the device. True = NOT isolated (danger)."""
    base = ["adb"] + (["-s", serial] if serial else [])
    for host in ("8.8.8.8", "1.1.1.1"):
        res = run([*base, "shell", "ping", "-c", "1", "-W", "2", host], timeout=20)
        if _ping_reachable(res.stdout + res.stderr):
            return True
    return False


def assert_isolated(serial: str | None, *, require: bool) -> bool:
    """Enforce offline mode and verify it. Returns True if isolated.

    If ``require`` and the device can still reach the internet, raises
    :class:`IsolationError` so the caller aborts before staging the sample."""
    enforce_offline(serial)
    reachable = device_can_reach_internet(serial)
    if reachable and require:
        raise IsolationError(
            "device still has internet egress after enforcing airplane mode — refusing to "
            "detonate. Put the VM/emulator on an isolated network (or set "
            "DYNAMIC_REQUIRE_ISOLATION=false to override, NOT recommended for live malware)."
        )
    return not reachable
