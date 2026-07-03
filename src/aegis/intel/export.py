"""Export an analysis as STIX 2.1 or a MISP event.

Turns the deterministic findings — network/file IOCs, the sample hash, the mapped MITRE
ATT&CK techniques and the generated YARA rule — into two interchange formats so results
can flow into real threat-intel platforms:

* **STIX 2.1** bundle: a ``malware`` SDO for the sample, ``indicator`` SDOs (STIX
  patterns) for each IOC + the file hash + the YARA rule, ``attack-pattern`` SDOs for the
  techniques, and ``relationship`` SROs tying them together.
* **MISP event**: attributes (ip/domain/url/hash/yara) with sensible categories plus
  ATT&CK galaxy-style tags and a threat level derived from the risk score.

Object ids are deterministic (uuid5 over stable content) so re-exports diff cleanly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from aegis.insights.build import _IGNORED_HOSTS, _host_of
from aegis.insights.mapping import ATTACK_MAP
from aegis.intel.rules import generate_rules

_NS = uuid.UUID("a2e15c9e-0000-4ae0-9000-ae0150000001")  # stable namespace for det. ids
_NET_IOC_TYPES = {"ipv4", "ip", "ipv6", "domain", "url", "hostname", "telegram", "telegram_channel"}
_MITRE_URL = "https://attack.mitre.org/techniques/"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _clean(value: str) -> str:
    """Cut at first NUL and strip control chars (IOC values carry extraction junk)."""
    value = str(value).split("\x00")[0].strip()
    return "".join(ch for ch in value if ch >= " " and ch != "\x7f")


def _det_id(prefix: str, *parts: str) -> str:
    return f"{prefix}--{uuid.uuid5(_NS, prefix + '|' + '|'.join(parts))}"


# ── shared IOC extraction ────────────────────────────────────────────────────


def _iocs(report: dict) -> list[tuple[str, str]]:
    """Return de-duplicated (kind, value) IOCs, kind in {ipv4,ipv6,domain,url,email}."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for ioc in report.get("iocs") or []:
        t = str(ioc.get("type", "")).lower()
        raw = ioc.get("value")
        if not raw:
            continue
        val = _clean(str(raw))
        if not val:
            continue
        if t == "url":
            host = _host_of(val)
            if host in _IGNORED_HOSTS:
                continue
            kind = "url"
        elif t in ("ipv4", "ip"):
            kind = "ipv4"
        elif t == "ipv6":
            kind = "ipv6"
        elif t in ("domain", "hostname"):
            if val.lower() in _IGNORED_HOSTS:
                continue
            kind = "domain"
        elif t == "email":
            kind = "email"
        else:
            continue
        key = f"{kind}:{val.lower()}"
        if key in seen or len(val) > 500:
            continue
        seen.add(key)
        out.append((kind, val))
    return out


def _techniques(report: dict) -> list[tuple[str, str, str]]:
    """De-duplicated (tactic, technique_id, technique_name) from the indicators."""
    seen: dict[str, tuple[str, str, str]] = {}
    for ind in report.get("indicators") or []:
        for tactic, tid, name in ATTACK_MAP.get(ind.get("id", ""), []):
            seen.setdefault(tid, (tactic, tid, name))
    return list(seen.values())


# ── STIX 2.1 ─────────────────────────────────────────────────────────────────

_STIX_PATTERN = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
}
_STIX_INDICATOR_TYPE = {
    "ipv4": "malicious-activity", "ipv6": "malicious-activity",
    "domain": "malicious-activity", "url": "malicious-activity",
    "email": "malicious-activity",
}


def _stix_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def to_stix_bundle(report: dict, *, sha256: str, filename: str | None,
                   risk: float | None) -> dict:
    now = _now_iso()
    objects: list[dict] = []

    mal_name = (report.get("apk") or {}).get("package") or filename or ("sample " + sha256[:12])
    malware_id = _det_id("malware", sha256)
    objects.append({
        "type": "malware", "spec_version": "2.1", "id": malware_id,
        "created": now, "modified": now, "name": mal_name, "is_family": False,
        "malware_types": ["unknown"],
        "description": f"MalwareTotal analysis (risk {(risk or 0):.0f}/100). "
                       "Auto-generated; review before use.",
    })

    def indicator(name, pattern, itype, key) -> str:
        iid = _det_id("indicator", key)
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": iid,
            "created": now, "modified": now, "name": name,
            "indicator_types": [itype], "pattern": pattern,
            "pattern_type": "stix", "pattern_version": "2.1", "valid_from": now,
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1",
            "id": _det_id("relationship", "ind", key),
            "created": now, "modified": now, "relationship_type": "indicates",
            "source_ref": iid, "target_ref": malware_id,
        })
        return iid

    # File hash indicator for the sample itself.
    indicator(f"SHA-256 {sha256[:16]}",
              f"[file:hashes.'SHA-256' = '{sha256}']", "malicious-activity",
              "sha256:" + sha256)

    # Network / email IOCs.
    for kind, val in _iocs(report):
        pattern = _STIX_PATTERN[kind].format(v=_stix_escape(val))
        indicator(f"{kind} {val}"[:120], pattern, _STIX_INDICATOR_TYPE[kind], f"{kind}:{val.lower()}")

    # YARA rule as a STIX indicator (pattern_type: yara).
    rules = generate_rules(report, sha256=sha256, risk=risk)
    yid = _det_id("indicator", "yara:" + sha256)
    objects.append({
        "type": "indicator", "spec_version": "2.1", "id": yid,
        "created": now, "modified": now, "name": rules.yara.name,
        "indicator_types": ["malicious-activity"], "pattern": rules.yara.text,
        "pattern_type": "yara", "valid_from": now,
    })
    objects.append({
        "type": "relationship", "spec_version": "2.1", "id": _det_id("relationship", "yara", sha256),
        "created": now, "modified": now, "relationship_type": "indicates",
        "source_ref": yid, "target_ref": malware_id,
    })

    # ATT&CK techniques as attack-pattern SDOs; malware `uses` them.
    for _tactic, tid, name in _techniques(report):
        ap_id = _det_id("attack-pattern", tid)
        objects.append({
            "type": "attack-pattern", "spec_version": "2.1", "id": ap_id,
            "created": now, "modified": now, "name": name,
            "external_references": [{
                "source_name": "mitre-attack", "external_id": tid,
                "url": _MITRE_URL + tid.replace(".", "/"),
            }],
        })
        objects.append({
            "type": "relationship", "spec_version": "2.1", "id": _det_id("relationship", "uses", tid, sha256),
            "created": now, "modified": now, "relationship_type": "uses",
            "source_ref": malware_id, "target_ref": ap_id,
        })

    return {"type": "bundle", "id": _det_id("bundle", sha256, now), "objects": objects}


# ── MISP event ───────────────────────────────────────────────────────────────

_MISP_ATTR = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
}


def _threat_level(risk: float | None) -> int:
    r = risk or 0  # MISP: 1=High, 2=Medium, 3=Low, 4=Undefined
    if r >= 50:
        return 1
    if r >= 25:
        return 2
    if r > 0:
        return 3
    return 4


def to_misp_event(report: dict, *, sha256: str, filename: str | None,
                  risk: float | None) -> dict:
    name = (report.get("apk") or {}).get("package") or filename or sha256[:12]
    attrs: list[dict] = [{
        "type": "sha256", "category": "Payload delivery", "value": sha256,
        "to_ids": True, "comment": "Analyzed sample",
    }]
    if filename:
        attrs.append({"type": "filename", "category": "Payload delivery",
                      "value": filename, "to_ids": False})
    for kind, val in _iocs(report):
        mtype, category = _MISP_ATTR[kind]
        attrs.append({"type": mtype, "category": category, "value": val, "to_ids": True})

    rules = generate_rules(report, sha256=sha256, risk=risk)
    attrs.append({"type": "yara", "category": "Payload delivery",
                  "value": rules.yara.text, "to_ids": True, "comment": "MalwareTotal-generated"})

    tags = [{"name": f'aegis:risk="{(risk or 0):.0f}"'}]
    for _tactic, tid, tname in _techniques(report):
        tags.append({"name": f'misp-galaxy:mitre-attack-pattern="{tname} - {tid}"'})

    return {"Event": {
        "info": f"MalwareTotal: {name}",
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "threat_level_id": _threat_level(risk),
        "analysis": 2,          # completed
        "distribution": 0,      # your org only
        "uuid": str(uuid.uuid5(_NS, "misp:" + sha256)),
        "published": False,
        "Attribute": attrs,
        "Tag": tags,
    }}
