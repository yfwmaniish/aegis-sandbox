"""Deterministic detection-rule generation from a static report (FR-12).

Turns the evidence in an analysis into two portable, hand-off-ready artifacts:
- a **YARA** rule keyed on the sample's strong string atoms (C2 endpoints, tokens,
  package/API names) plus imphash for PE,
- a **Sigma** rule that fires on the sample's network endpoints (DNS/IP) or, absent
  those, on the file hash — tagged with the MITRE techniques we mapped.

No LLM and no third-party YAML dependency: the Sigma YAML is emitted deterministically.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from aegis.insights.build import _IGNORED_HOSTS, _host_of
from aegis.insights.mapping import ATTACK_MAP
from aegis.intel.models import RuleBundle, SigmaRule, YaraRule

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ID_SANITIZE = re.compile(r"[^A-Za-z0-9_]")
_NET_IOC_TYPES = {"ipv4", "ip", "ipv6", "domain", "url", "hostname", "telegram", "telegram_channel"}


def _clean_atom(s: str) -> str:
    """Strip NULs/control chars, cut at first NUL, trim; return '' if unusable."""
    s = str(s).split("\x00")[0].strip()
    s = "".join(ch for ch in s if ch >= " " and ch != "\x7f")
    return s


def _yara_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _rule_name(report: dict, sha256: str) -> str:
    apk = report.get("apk") or {}
    base = apk.get("package") or (report.get("file_type", "sample") + "_" + sha256[:10])
    ident = _ID_SANITIZE.sub("_", base).strip("_")
    if ident and ident[0].isdigit():
        ident = "s_" + ident
    return "MalwareTotal_" + (ident or ("sample_" + sha256[:10]))


def _collect_string_atoms(report: dict) -> list[tuple[str, str]]:
    """Return de-duplicated (label, value) atoms worth pinning a YARA rule on."""
    atoms: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label: str, value: str) -> None:
        v = _clean_atom(value)
        if len(v) < 5 or len(v) > 120 or v.lower() in seen:
            return
        seen.add(v.lower())
        atoms.append((label, v))

    # Network + notable IOCs first — highest signal.
    for ioc in report.get("iocs") or []:
        t = str(ioc.get("type", "")).lower()
        val = ioc.get("value")
        if not val:
            continue
        if t in {"telegram", "telegram_channel"} or "telegram" in str(val).lower():
            add("telegram", str(val))
        elif t in _NET_IOC_TYPES:
            # Skip structural/namespace hosts (e.g. schemas.android.com) — they'd match
            # every file of that type and make a useless YARA atom.
            host = _host_of(str(val))
            if host and host in _IGNORED_HOSTS:
                continue
            add(t, str(val))
        elif t in {"email", "bitcoin", "onion", "registry"}:
            add(t, str(val))

    apk = report.get("apk") or {}
    if apk.get("package"):
        add("package", apk["package"])
    for api in (apk.get("suspicious_apis") or [])[:6]:
        add("api", api)

    # Interesting strings the string scanner already surfaced (categorised).
    interesting = ((report.get("strings") or {}).get("interesting")) or {}
    for cat, vals in interesting.items():
        for v in (vals or [])[:4]:
            add(cat, v)

    return atoms[:24]


def generate_yara(report: dict, sha256: str, risk: float | None) -> YaraRule:
    name = _rule_name(report, sha256)
    atoms = _collect_string_atoms(report)
    file_type = report.get("file_type", "unknown")
    date = datetime.now(UTC).strftime("%Y-%m-%d")

    lines = [f"rule {name}", "{", "    meta:",
             '        author = "MalwareTotal (auto-generated)"',
             f'        date = "{date}"',
             f'        sha256 = "{sha256}"',
             f'        file_type = "{file_type}"']
    if risk is not None:
        lines.append(f'        risk_score = "{risk:.1f}"')
    lines.append('        description = "Auto-derived from static findings; review before deployment"')

    lines.append("    strings:")
    if atoms:
        for i, (label, val) in enumerate(atoms):
            lines.append(f'        $s{i} = "{_yara_escape(val)}" ascii wide  // {label}')
    else:
        lines.append(f'        $sha = "{sha256}" ascii nocase')

    imphash = (report.get("hashes") or {}).get("imphash")
    cond_parts: list[str] = []
    if atoms:
        k = max(1, min(3, len(atoms)))
        cond_parts.append(f"{k} of ($s*)")
    else:
        cond_parts.append("$sha")
    if file_type == "pe" and imphash:
        lines.insert(0, 'import "pe"')
        lines.append("")
        cond_parts.append(f'pe.imphash() == "{imphash}"')

    lines.append("    condition:")
    lines.append("        " + " or ".join(cond_parts))
    lines.append("}")
    return YaraRule(name=name, text="\n".join(lines), string_count=len(atoms))


def _attack_tags(report: dict) -> list[str]:
    tags: set[str] = set()
    for ind in report.get("indicators") or []:
        for tactic, tech_id, _ in ATTACK_MAP.get(ind.get("id", ""), []):
            tags.add("attack." + tactic.lower().replace(" ", "_"))
            tags.add("attack." + tech_id.lower())
    return sorted(tags)


def _split_endpoints(report: dict) -> tuple[list[str], list[str]]:
    domains: set[str] = set()
    ips: set[str] = set()
    for ioc in report.get("iocs") or []:
        if str(ioc.get("type", "")).lower() not in _NET_IOC_TYPES or not ioc.get("value"):
            continue
        host = _host_of(str(ioc["value"]))
        if not host or host in _IGNORED_HOSTS:
            continue
        (ips if _IPV4.match(host) else domains).add(host)
    return sorted(domains), sorted(ips)


def _yaml_list(values: list[str], indent: str) -> str:
    return "\n".join(f"{indent}- '{v}'" for v in values)


def generate_sigma(report: dict, sha256: str, tags: list[str]) -> SigmaRule:
    domains, ips = _split_endpoints(report)
    rid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "aegis:" + sha256))
    date = datetime.now(UTC).strftime("%Y/%m/%d")
    pkg = (report.get("apk") or {}).get("package") or sha256[:12]
    tag_block = ("\ntags:\n" + "\n".join(f"    - {t}" for t in tags)) if tags else ""

    if domains or ips:
        title = f"MalwareTotal - {pkg} network C2 indicators"
        det = ["detection:"]
        sel_names = []
        if domains:
            det += ["    selection_domain:", "        QueryName:", _yaml_list(domains, "            ")]
            sel_names.append("selection_domain")
        if ips:
            det += ["    selection_ip:", "        DestinationIp:", _yaml_list(ips, "            ")]
            sel_names.append("selection_ip")
        det.append("    condition: " + " or ".join(sel_names))
        logsource = "category: dns_query / firewall"
        body = (
            f"title: {title}\n"
            f"id: {rid}\n"
            "status: experimental\n"
            f"description: Auto-generated by MalwareTotal from static analysis of {sha256}\n"
            "author: MalwareTotal (auto-generated)\n"
            f"date: {date}\n"
            "logsource:\n"
            "    category: dns_query\n"
            + "\n".join(det) + "\n"
            "level: high"
            + tag_block + "\n"
        )
    else:
        title = f"MalwareTotal - {pkg} file hash"
        logsource = "category: process_creation"
        body = (
            f"title: {title}\n"
            f"id: {rid}\n"
            "status: experimental\n"
            f"description: Auto-generated by MalwareTotal; detects execution of sample {sha256}\n"
            "author: MalwareTotal (auto-generated)\n"
            f"date: {date}\n"
            "logsource:\n"
            "    category: process_creation\n"
            "detection:\n"
            "    selection:\n"
            f"        Hashes|contains: 'SHA256={sha256}'\n"
            "    condition: selection\n"
            "level: high"
            + tag_block + "\n"
        )
    return SigmaRule(title=title, logsource=logsource, yaml=body)


def generate_rules(report: dict, *, sha256: str, risk: float | None = None) -> RuleBundle:
    tags = _attack_tags(report)
    yara = generate_yara(report, sha256, risk)
    sigma = generate_sigma(report, sha256, tags)
    notes = [
        "Rules are auto-generated heuristics — review and tune before production use.",
        "YARA matches string atoms extracted from the sample; Sigma targets its network "
        "endpoints (or file hash when no endpoints were observed).",
    ]
    return RuleBundle(
        sample_sha256=sha256, file_type=report.get("file_type", "unknown"),
        yara=yara, sigma=sigma, attack_tags=tags, notes=notes,
    )
