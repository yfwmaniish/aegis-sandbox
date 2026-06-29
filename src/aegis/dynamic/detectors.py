"""Dynamic detectors — runtime behaviour (normalized events) -> findings.

These are the dynamic counterparts to the static heuristics: what the app *did* when
run, not just what it *could* do. They consume a summarized :class:`DynamicReport` and
emit the same evidence-first :class:`SuspiciousIndicator` objects the static engine
produces, so findings from both phases land in one schema.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from aegis.dynamic.models import DynamicReport, EventCategory, NormalizedEvent
from aegis.static.models import Severity, SuspiciousIndicator


def _is_public_ip(host: str) -> bool:
    try:
        return not ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def _host_of(event: NormalizedEvent) -> str | None:
    val = event.object.value
    if not val:
        return None
    if val.startswith(("http://", "https://")):
        return urlparse(val).hostname
    # "host/ip:port" or raw host
    return val.split("/")[0].split(":")[0].strip()


def detect(report: DynamicReport) -> list[SuspiciousIndicator]:
    """Run all dynamic detectors over a (summarized) report."""
    out: list[SuspiciousIndicator] = []
    ev = report.events

    # 1) Runtime C2 — outbound network to a public IP / raw-IP URL while detonating.
    net = [e for e in ev if e.category == EventCategory.NETWORK]
    c2 = sorted({
        e.object.value for e in net
        if e.object.value and ((_host_of(e) and _is_public_ip(_host_of(e))) or
                               (e.object.type == "url" and _host_of(e) and _is_public_ip(_host_of(e))))
    })
    if c2:
        out.append(SuspiciousIndicator(
            id="dyn.runtime_c2", title="Outbound connection to external host at runtime",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=c2[:10],
            inference="The app actively contacted an external endpoint during detonation — "
                      "likely C2 / exfiltration.",
            evidence=c2[:10],
        ))

    # 2) SMS sent at runtime (OTP/premium-SMS abuse).
    sms = [e for e in ev if e.category == EventCategory.SMS]
    if sms:
        dests = sorted({e.object.value for e in sms if e.object.value})
        out.append(SuspiciousIndicator(
            id="dyn.sms_sent", title="SMS sent at runtime",
            severity=Severity.HIGH, confidence=0.8,
            observed_facts=[f"{len(sms)} send(s)"] + dests[:8],
            inference="Sending SMS during analysis indicates OTP relay or premium-SMS fraud.",
            evidence=dests[:8] or ["SmsManager.sendTextMessage"],
        ))

    # 3) Dynamic code loading observed (stager executed).
    dex = [e for e in ev if e.category == EventCategory.DEX_LOAD]
    if dex:
        paths = sorted({e.object.value for e in dex if e.object.value})
        out.append(SuspiciousIndicator(
            id="dyn.dynamic_code_load", title="Loaded code at runtime",
            severity=Severity.HIGH, confidence=0.75,
            observed_facts=paths[:8] or ["DexClassLoader"],
            inference="Runtime class loading is the defining behaviour of a dropper/stager.",
            evidence=paths[:8] or ["DexClassLoader"],
        ))

    # 3b) Dropper correlation: a file was written and then loaded as code.
    dropped = set(report.dropped_files)
    loaded = set(report.loaded_dex)
    overlap = sorted(dropped & loaded) or sorted(
        p for p in loaded if any(p in d or d in p for d in dropped)
    )
    if overlap:
        out.append(SuspiciousIndicator(
            id="dyn.dropper_chain", title="Dropped-then-loaded payload (dropper chain)",
            severity=Severity.CRITICAL, confidence=0.8,
            observed_facts=overlap[:8],
            inference="A file written at runtime was subsequently loaded as code — a "
                      "complete multi-stage dropper execution.",
            evidence=overlap[:8],
        ))

    # 4) Native command execution.
    execs = [e for e in ev if e.category == EventCategory.EXEC]
    if execs:
        cmds = sorted({e.object.value for e in execs if e.object.value})
        sev = Severity.HIGH if any(c and ("su" in c.split() or "mount" in c) for c in cmds) else Severity.MEDIUM
        out.append(SuspiciousIndicator(
            id="dyn.command_exec", title="Executed shell command(s) at runtime",
            severity=sev, confidence=0.7,
            observed_facts=cmds[:8] or ["Runtime.exec"],
            inference="Spawning shell commands at runtime (esp. su/mount) is rare in benign apps.",
            evidence=cmds[:8] or ["Runtime.exec"],
        ))

    # 5) Device/SIM identifier harvesting.
    tele = [e for e in ev if e.category == EventCategory.TELEPHONY]
    if tele:
        apis = sorted({e.action for e in tele})
        out.append(SuspiciousIndicator(
            id="dyn.identifier_harvest", title="Harvested device/SIM identifiers",
            severity=Severity.MEDIUM, confidence=0.65,
            observed_facts=apis,
            inference="Reading IMEI/IMSI/SIM serial is used to fingerprint/track victims.",
            evidence=apis,
        ))

    # 6) Surveillance: location + mic/camera.
    loc = [e for e in ev if e.category == EventCategory.LOCATION]
    media = [e for e in ev if e.category == EventCategory.MEDIA]
    if loc:
        out.append(SuspiciousIndicator(
            id="dyn.location_access", title="Accessed device location at runtime",
            severity=Severity.MEDIUM, confidence=0.6,
            observed_facts=[e.action for e in loc][:5],
            inference="Active location access during detonation indicates tracking.",
            evidence=[e.action for e in loc][:5],
        ))
    if media:
        out.append(SuspiciousIndicator(
            id="dyn.media_capture", title="Started microphone/camera capture",
            severity=Severity.HIGH, confidence=0.65,
            observed_facts=[e.action for e in media][:5],
            inference="Recording audio/video at runtime is a hallmark of spyware.",
            evidence=[e.action for e in media][:5],
        ))

    # 7) Accessibility automation used at runtime.
    acc = [e for e in ev if e.category == EventCategory.ACCESSIBILITY]
    if acc:
        out.append(SuspiciousIndicator(
            id="dyn.accessibility_active", title="Accessibility service active at runtime",
            severity=Severity.HIGH, confidence=0.7,
            observed_facts=[e.action for e in acc][:5],
            inference="Live accessibility events enable screen reading / UI automation abuse.",
            evidence=[e.action for e in acc][:5],
        ))

    return out
