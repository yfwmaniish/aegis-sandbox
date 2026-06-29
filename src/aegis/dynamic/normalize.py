"""Telemetry normalizers: raw collector output -> :class:`NormalizedEvent`.

Three sources for the Genymotion/Android backend:
* **Frida JSON** — our instrumentation script (``agent/hooks.js``) emits one JSON object
  per intercepted API call; this is the richest, most reliable signal.
* **logcat** — system log (threadtime format); we lift a few high-value lines
  (component starts, crashes, our own tagged markers).
* **dumpsys package** — the app's requested/granted runtime permissions.

All parsers are pure functions over text, so they're tested with fixtures and never
need a device.
"""

from __future__ import annotations

import contextlib
import json
import re
from datetime import UTC, datetime

from aegis.dynamic.models import EventCategory, EventObject, EventSubject, NormalizedEvent

_COLLECTOR_VERSION = "1.0"

# Frida event "t" -> (category, object type).
_FRIDA_MAP: dict[str, tuple[EventCategory, str]] = {
    "sms": (EventCategory.SMS, "number"),
    "network": (EventCategory.NETWORK, "ip"),
    "http": (EventCategory.NETWORK, "url"),
    "location": (EventCategory.LOCATION, "resource"),
    "exec": (EventCategory.EXEC, "command"),
    "file": (EventCategory.FILE, "file"),
    "crypto": (EventCategory.CRYPTO, "resource"),
    "dex": (EventCategory.DEX_LOAD, "file"),
    "telephony": (EventCategory.TELEPHONY, "resource"),
    "media": (EventCategory.MEDIA, "resource"),
    "camera": (EventCategory.MEDIA, "resource"),
    "accessibility": (EventCategory.ACCESSIBILITY, "component"),
    "ipc": (EventCategory.IPC, "component"),
    "notification": (EventCategory.NOTIFICATION, "resource"),
}

# Where to find the object value in a frida event, in priority order.
_VALUE_KEYS = ("url", "host", "dest", "number", "path", "cmd", "command", "value",
               "target", "provider", "algo", "component")


def _ts_from_ms(ms) -> datetime:
    try:
        return datetime.fromtimestamp(float(ms) / 1000.0, tz=UTC)
    except (TypeError, ValueError, OSError):
        return datetime.now(tz=UTC)


def parse_frida_events(jsonl: str, raw_ref: str = "opaque://frida") -> list[NormalizedEvent]:
    """Parse newline-delimited JSON emitted by the Frida hook script."""
    events: list[NormalizedEvent] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = str(obj.get("t", "")).lower()
        category, obj_type = _FRIDA_MAP.get(t, (EventCategory.LOG, "resource"))
        value = next((str(obj[k]) for k in _VALUE_KEYS if obj.get(k) is not None), None)
        detail = {k: v for k, v in obj.items()
                  if k not in {"t", "ts", "pid", "thread", "process", "api"} and v is not None}
        if obj.get("port") is not None:
            with contextlib.suppress(TypeError, ValueError):
                detail["port"] = int(obj["port"])
        events.append(NormalizedEvent(
            timestamp=_ts_from_ms(obj.get("ts")) if obj.get("ts") else datetime.now(tz=UTC),
            category=category,
            action=str(obj.get("api") or obj.get("action") or t or "event"),
            subject=EventSubject(process=obj.get("process"), pid=obj.get("pid")),
            object=EventObject(type=obj_type, value=value),
            raw_ref=raw_ref,
            collector="frida",
            collector_version=_COLLECTOR_VERSION,
            detail=detail,
        ))
    return events


# logcat threadtime: "MM-DD HH:MM:SS.mmm  PID  TID L TAG: message"
_LOGCAT_RE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+):\s?(?P<msg>.*)$"
)
# Lines worth lifting into the timeline.
_LOGCAT_INTEREST = [
    (re.compile(r"Start proc (\S+)"), EventCategory.PROCESS, "start_process"),
    (re.compile(r"START u\d+ \{.*?cmp=(\S+?)[ }]"), EventCategory.PROCESS, "start_component"),
    (re.compile(r"Displayed (\S+)"), EventCategory.UI, "displayed"),
    (re.compile(r"(FATAL EXCEPTION|ANR in) (\S+)"), EventCategory.PROCESS, "crash"),
]


def parse_logcat(text: str, raw_ref: str = "opaque://logcat") -> list[NormalizedEvent]:
    """Lift high-value lines from a logcat dump into normalized events."""
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        m = _LOGCAT_RE.match(line.strip())
        if not m:
            continue
        msg, tag, pid = m["msg"], m["tag"].strip(), int(m["pid"])
        for pat, category, action in _LOGCAT_INTEREST:
            hit = pat.search(msg)
            if hit:
                value = hit.groups()[-1]
                events.append(NormalizedEvent(
                    category=category,
                    action=action,
                    subject=EventSubject(process=tag, pid=pid),
                    object=EventObject(type="component", value=value),
                    raw_ref=raw_ref,
                    collector="logcat",
                    collector_version=_COLLECTOR_VERSION,
                    detail={"tag": tag, "level": m["level"]},
                ))
                break
    return events


# dumpsys package output: "requested permissions:" block and "runtime permissions:" grants.
_REQUESTED_RE = re.compile(r"^\s*(android\.permission\.[A-Z_]+|[\w.]+\.permission\.[A-Z_]+)\s*$")
_GRANTED_RE = re.compile(r"^\s*([\w.]+\.permission\.[A-Z_]+|android\.permission\.[A-Z_]+):\s*granted=true")


def parse_dumpsys_permissions(text: str) -> tuple[list[str], list[str]]:
    """Return (requested, granted) permission lists from ``dumpsys package <pkg>``."""
    requested: list[str] = []
    granted: list[str] = []
    in_requested = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("requested permissions:"):
            in_requested = True
            continue
        if in_requested:
            m = _REQUESTED_RE.match(line)
            if m:
                requested.append(m.group(1))
                continue
            if stripped and not line.startswith(" " * 4):
                in_requested = False
        g = _GRANTED_RE.search(line)
        if g:
            granted.append(g.group(1))
    return sorted(set(requested)), sorted(set(granted))
