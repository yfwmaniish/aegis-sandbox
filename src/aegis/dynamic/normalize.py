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


# ── strace (Linux/ELF detonation) ────────────────────────────────────────────
# Emitted with `strace -f -ttt` (epoch timestamps, per-pid). One line per syscall:
#   [pid  1234] 1712345678.123456 openat(AT_FDCWD, "/tmp/x", O_WRONLY|O_CREAT, 0644) = 4
#   1234 1712345678.200 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 EINPROGRESS
_STRACE_RE = re.compile(
    r"^(?:\[pid\s+(?P<p1>\d+)\]\s+|(?P<p2>\d+)\s+)?"
    r"(?P<ts>\d+\.\d+)\s+"
    r"(?P<call>\w+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)"
)
_STR_INET = re.compile(r'inet_addr\("([^"]+)"\)')
_STR_INET6 = re.compile(r'inet_pton\(AF_INET6,\s*"([^"]+)"')
_STR_PORT = re.compile(r"(?:sin6?_port=)?htons\((\d+)\)")
_STR_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_STR_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")


def _strace_ts(epoch: str) -> datetime:
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except (TypeError, ValueError, OSError):
        return datetime.now(tz=UTC)


def parse_strace(text: str, raw_ref: str = "opaque://strace") -> list[NormalizedEvent]:
    """Parse ``strace -f -ttt`` output into normalized events (process/file/network).

    Focuses on the behaviour-revealing syscalls: execve (command execution), connect
    (network egress), file writes/renames/unlinks/chmod (drops), and clone/fork
    (process spawn). Failed reads and local (AF_UNIX/netlink) sockets are dropped."""
    events: list[NormalizedEvent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "<unfinished" in line or "resumed>" in line or line.startswith(("+++", "---")):
            continue
        m = _STRACE_RE.match(line)
        if not m:
            continue
        pid = int(m["p1"] or m["p2"]) if (m["p1"] or m["p2"]) else None
        call, args, ret = m["call"], m["args"], m["ret"]
        ts = _strace_ts(m["ts"])
        ev = _strace_event(call, args, ret, pid, ts, raw_ref)
        if ev is not None:
            events.append(ev)
    return events


def _strace_event(call, args, ret, pid, ts, raw_ref) -> NormalizedEvent | None:
    def mk(category, action, obj_type, value, detail=None):
        return NormalizedEvent(
            timestamp=ts, platform="linux", category=category, action=action,
            subject=EventSubject(pid=pid), object=EventObject(type=obj_type, value=value),
            raw_ref=raw_ref, collector="strace", collector_version=_COLLECTOR_VERSION,
            detail=detail or {},
        )

    if call in ("execve", "execveat"):
        q = _STR_QUOTED.findall(args)
        if not q:
            return None
        path = q[0]
        argv = " ".join(a for a in q[1:6])
        return mk(EventCategory.EXEC, "execve", "command", (path + (" " + argv if argv else "")).strip()[:300])

    if call in ("connect", "sendto", "sendmsg"):
        ip = None
        mi = _STR_INET.search(args) or _STR_INET6.search(args)
        if mi:
            ip = mi.group(1)
        if not ip or ip in ("0.0.0.0", "127.0.0.1", "::1"):
            return None  # unresolved / loopback / AF_UNIX → not egress
        mp = _STR_PORT.search(args)
        detail = {"port": int(mp.group(1))} if mp else {}
        return mk(EventCategory.NETWORK, call, "ip", ip, detail)

    if call in ("open", "openat"):
        if not any(f in args for f in _STR_WRITE_FLAGS):
            return None  # read-only opens are noise
        try:
            if int(ret) < 0:
                return None
        except ValueError:
            pass
        q = _STR_QUOTED.findall(args)
        path = q[-1] if call == "openat" and len(q) > 1 else (q[0] if q else None)
        return mk(EventCategory.FILE, "open_write", "file", path) if path else None

    if call in ("rename", "renameat", "renameat2"):
        q = _STR_QUOTED.findall(args)
        return mk(EventCategory.FILE, "rename", "file", q[-1]) if q else None
    if call in ("unlink", "unlinkat"):
        q = _STR_QUOTED.findall(args)
        return mk(EventCategory.FILE, "delete", "file", q[-1]) if q else None
    if call in ("chmod", "fchmodat"):
        q = _STR_QUOTED.findall(args)
        return mk(EventCategory.FILE, "chmod", "file", q[-1]) if q else None
    if call in ("clone", "clone3", "fork", "vfork"):
        return mk(EventCategory.PROCESS, "spawn", "process", ret)
    return None


# ── sinkhole (live network-capture detonation) ───────────────────────────────
# The sinkhole container logs one line per observed attempt (see the sinkhole script):
#   DNS <query-name>
#   HTTP <METHOD> <host> <path>
_SINK_DNS = re.compile(r"^DNS\s+(?P<name>\S+)")
_SINK_HTTP = re.compile(r"^HTTP\s+(?P<method>\S+)\s+(?P<host>\S+)\s+(?P<path>\S+)")


def parse_sinkhole(text: str, raw_ref: str = "opaque://sinkhole") -> list[NormalizedEvent]:
    """Parse the sinkhole's capture log into normalized NETWORK events — the endpoints the
    sample *attempted* to reach (all resolved/served locally; nothing left the machine)."""
    events: list[NormalizedEvent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        d = _SINK_DNS.match(line)
        if d:
            name = d["name"].rstrip(".")
            events.append(NormalizedEvent(
                platform="linux", category=EventCategory.NETWORK, action="dns_query",
                object=EventObject(type="domain", value=name), raw_ref=raw_ref,
                collector="sinkhole", collector_version=_COLLECTOR_VERSION,
            ))
            continue
        h = _SINK_HTTP.match(line)
        if h:
            url = f"http://{h['host']}{h['path']}"
            events.append(NormalizedEvent(
                platform="linux", category=EventCategory.NETWORK, action="http_request",
                object=EventObject(type="url", value=url), raw_ref=raw_ref,
                collector="sinkhole", collector_version=_COLLECTOR_VERSION,
                detail={"method": h["method"], "host": h["host"]},
            ))
    return events
