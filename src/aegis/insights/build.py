"""Compute the visualization bundle from a stored analysis.

``build_visualizations`` takes the persisted static report dict and (optionally) the
dynamic report dict — exactly the JSON blobs the API already stores — and derives the
capability radar, permission heatmap, ATT&CK matrix and behaviour graph. Pure and
deterministic: same reports in, same visuals out, no network or LLM.
"""

from __future__ import annotations

from urllib.parse import urlparse

from aegis.insights.mapping import (
    ATTACK_MAP,
    DANGEROUS_PERMISSIONS,
    PERMISSION_CATEGORIES,
    TACTIC_ORDER,
)
from aegis.insights.models import (
    AttackTechnique,
    BehaviorGraph,
    CapabilityAxis,
    GraphEdge,
    GraphNode,
    PermissionCategory,
    PermissionEntry,
    Visualizations,
)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_NET_IOC_TYPES = {"ipv4", "ip", "ipv6", "domain", "url", "hostname", "telegram", "telegram_channel"}


def _norm_perm(p: str) -> str:
    """`android.permission.SEND_SMS` -> `SEND_SMS`; leave custom perms as their tail."""
    return p.rsplit(".", 1)[-1].strip().upper() if p else ""


def _score(components: list[tuple[bool, int, str]]) -> tuple[int, list[str]]:
    """Sum weights of present components (clamped to 100); return score + evidence labels."""
    total = 0
    evidence: list[str] = []
    for present, weight, label in components:
        if present:
            total += weight
            evidence.append(label)
    return min(total, 100), evidence


class _Signals:
    """Normalized feature set pulled once from both reports."""

    def __init__(self, static: dict, dynamic: dict | None) -> None:
        self.file_type = static.get("file_type", "unknown")
        apk = static.get("apk") or {}
        self.package = apk.get("package")
        self.perms_raw: list[str] = list(apk.get("permissions") or [])
        self.perms: set[str] = {_norm_perm(p) for p in self.perms_raw}
        self.dangerous_raw: list[str] = list(apk.get("dangerous_permissions") or [])
        self.suspicious_apis: list[str] = list(apk.get("suspicious_apis") or [])
        self.native_libs: bool = bool(apk.get("uses_native_libs"))
        self.entropy_packing = (static.get("entropy") or {}).get("packing_likelihood", "low")

        # Indicator ids + a severity per id (max across static/dynamic occurrences).
        self.ind_sev: dict[str, str] = {}
        for ind in list(static.get("indicators") or []):
            self._add_ind(ind)
        self.iocs: list[dict] = list(static.get("iocs") or [])

        self.has_dynamic = dynamic is not None
        self.dyn_categories: set[str] = set()
        self.net_peers: list[dict] = []
        self.used_perms: set[str] = set()
        self.loaded_dex: list[str] = []
        self.dropped_files: list[str] = []
        if dynamic:
            for ind in list(dynamic.get("indicators") or []):
                self._add_ind(ind)
            self.dyn_categories = set((dynamic.get("category_counts") or {}).keys())
            self.net_peers = list(dynamic.get("network_peers") or [])
            self.used_perms = {_norm_perm(p) for p in (dynamic.get("used_permissions") or [])}
            self.loaded_dex = list(dynamic.get("loaded_dex") or [])
            self.dropped_files = list(dynamic.get("dropped_files") or [])

    def _add_ind(self, ind: dict) -> None:
        iid = ind.get("id")
        if not iid:
            return
        sev = ind.get("severity", "medium")
        prev = self.ind_sev.get(iid)
        if prev is None or _SEVERITY_ORDER.get(sev, 1) > _SEVERITY_ORDER.get(prev, 1):
            self.ind_sev[iid] = sev

    def has(self, *ids: str) -> bool:
        return any(i in self.ind_sev for i in ids)

    def perm_cat_present(self, key: str) -> bool:
        return any(c.key == key and c.count > 0 for c in self._perm_cats)

    # Filled by build() so capability rules can reference heatmap categories.
    _perm_cats: list[PermissionCategory] = []


# ── Permission heatmap ───────────────────────────────────────────────────────


def _permission_heatmap(sig: _Signals) -> list[PermissionCategory]:
    dangerous_norm = {_norm_perm(p) for p in sig.dangerous_raw} | DANGEROUS_PERMISSIONS
    cats: list[PermissionCategory] = []
    seen: set[str] = set()
    for spec in PERMISSION_CATEGORIES:
        entries: list[PermissionEntry] = []
        for raw in sig.perms_raw:
            name = _norm_perm(raw)
            if name in seen:
                continue
            if name in spec["match"]:
                seen.add(name)
                entries.append(PermissionEntry(
                    permission=name,
                    dangerous=name in dangerous_norm,
                    used_at_runtime=name in sig.used_perms,
                ))
        risk = spec["risk"] if entries else "none"
        cats.append(PermissionCategory(
            key=spec["key"], label=spec["label"], risk=risk,
            count=len(entries), permissions=sorted(entries, key=lambda e: e.permission),
        ))
    return cats


# ── Capability radar ─────────────────────────────────────────────────────────


def _capability_radar(sig: _Signals) -> list[CapabilityAxis]:
    dyn_net = bool(sig.net_peers) or "network" in sig.dyn_categories
    axes_def = [
        ("sms_telephony", "SMS & Telephony", [
            (sig.has("apk.sms_capability"), 45, "SMS-capable manifest"),
            (sig.has("dyn.sms_sent"), 55, "sent SMS at runtime"),
            (sig.perm_cat_present("sms"), 25, "SMS permissions"),
            (sig.perm_cat_present("telephony"), 15, "telephony permissions"),
        ]),
        ("network_c2", "Network / C2", [
            (sig.has("net.hardcoded_ip_c2", "dyn.runtime_c2", "dyn.c2_beacon"), 55, "hard-coded C2 endpoint"),
            (sig.has("net.telegram_channel"), 40, "Telegram C2 channel"),
            (sig.has("net.hardcoded_ip"), 20, "hard-coded IP"),
            (dyn_net, 35, "live network traffic"),
            (sig.perm_cat_present("network"), 10, "network permissions"),
        ]),
        ("surveillance", "Surveillance & Collection", [
            (sig.has("dyn.location_access"), 40, "read location at runtime"),
            (sig.has("dyn.media_capture"), 40, "camera/mic capture"),
            (sig.has("dyn.identifier_harvest"), 30, "harvested device identifiers"),
            (sig.perm_cat_present("location"), 20, "location permissions"),
            (sig.perm_cat_present("camera_mic"), 20, "camera/mic permissions"),
            (sig.perm_cat_present("contacts"), 15, "contacts/accounts permissions"),
        ]),
        ("persistence_control", "Persistence & Device Control", [
            (sig.has("apk.overlay_plus_accessibility"), 50, "overlay + accessibility"),
            (sig.has("apk.device_admin"), 45, "device-admin request"),
            (sig.has("apk.accessibility_service", "dyn.accessibility_active"), 40, "accessibility service"),
            (sig.perm_cat_present("persistence"), 20, "boot/persistence permissions"),
            (sig.perm_cat_present("overlay"), 20, "overlay permission"),
        ]),
        ("evasion_obfuscation", "Evasion & Obfuscation", [
            (sig.entropy_packing == "high", 35, "high-entropy/packed"),
            (sig.entropy_packing == "medium", 20, "possibly packed"),
            (sig.has("pe.packer_section", "pe.high_entropy_code", "elf.high_entropy_code"), 35, "packer artifacts"),
            (sig.has("apk.dynamic_code_loading", "dyn.dynamic_code_load"), 30, "runtime code loading"),
            (sig.has("script.obfuscated", "script.encoded_command"), 35, "obfuscated script"),
            (sig.has("office.remote_template", "pdf.embedded_file", "macho.encrypted"), 25, "evasive delivery"),
            (sig.has("apk.debug_signed"), 15, "debug-signed"),
            (sig.has("apk.network_without_internet_permission"), 20, "hidden network capability"),
        ]),
        ("code_execution", "Dynamic Code & Execution", [
            (sig.has("dyn.command_exec"), 50, "executed shell command"),
            (sig.has("dyn.dynamic_code_load", "apk.dynamic_code_loading"), 45, "loaded code at runtime"),
            (sig.has("dyn.dropper_chain"), 50, "dropper chain"),
            (sig.has("apk.request_install_packages"), 40, "installs packages"),
            (sig.has("office.auto_exec_macro", "office.suspicious_macro", "office.dde"), 50, "maldoc macro execution"),
            (sig.has("script.download_exec", "script.suspicious_api"), 50, "script execution"),
            (sig.has("pdf.launch_action", "pdf.javascript"), 40, "PDF active content"),
            (sig.perm_cat_present("packages"), 25, "install/manage-app permissions"),
            (bool(sig.loaded_dex), 25, "DEX loaded at runtime"),
        ]),
        ("privilege_escalation", "Privilege Escalation", [
            (sig.has("apk.overlay_plus_accessibility"), 50, "overlay + accessibility"),
            (sig.has("apk.device_admin"), 40, "device-admin"),
            (sig.has("apk.accessibility_service", "dyn.accessibility_active"), 35, "accessibility abuse"),
            (sig.has("dyn.command_exec"), 40, "shell execution"),
            (sig.native_libs, 20, "bundled native libraries"),
        ]),
        ("data_exfiltration", "Data Exfiltration", [
            (sig.has("net.telegram_channel"), 45, "Telegram exfil channel"),
            (sig.has("dyn.identifier_harvest"), 30, "identifier harvest"),
            (sig.has("apk.sms_capability", "dyn.sms_sent"), 25, "SMS exfil path"),
            (bool(sig.dropped_files), 20, "wrote files at runtime"),
            (sig.has("net.hardcoded_ip_c2", "dyn.runtime_c2") and
             (sig.perm_cat_present("sms") or sig.perm_cat_present("location")
              or sig.perm_cat_present("contacts")), 30, "collection + network egress"),
        ]),
    ]
    out: list[CapabilityAxis] = []
    for key, label, comps in axes_def:
        score, evidence = _score(comps)
        out.append(CapabilityAxis(key=key, label=label, score=score, evidence=evidence))
    return out


# ── ATT&CK matrix ────────────────────────────────────────────────────────────


def _attack_matrix(sig: _Signals) -> list[AttackTechnique]:
    by_tech: dict[str, AttackTechnique] = {}
    for iid, sev in sig.ind_sev.items():
        for tactic, tech_id, tech_name in ATTACK_MAP.get(iid, []):
            existing = by_tech.get(tech_id)
            if existing is None:
                by_tech[tech_id] = AttackTechnique(
                    tactic=tactic, technique_id=tech_id, technique=tech_name,
                    severity=sev, source_indicators=[iid],
                )
            else:
                existing.source_indicators.append(iid)
                if _SEVERITY_ORDER.get(sev, 1) > _SEVERITY_ORDER.get(existing.severity, 1):
                    existing.severity = sev

    def sort_key(t: AttackTechnique) -> tuple[int, str]:
        tac = TACTIC_ORDER.index(t.tactic) if t.tactic in TACTIC_ORDER else len(TACTIC_ORDER)
        return (tac, t.technique_id)

    techs = sorted(by_tech.values(), key=sort_key)
    for t in techs:
        t.source_indicators = sorted(set(t.source_indicators))
    return techs


# ── Behaviour / network graph ────────────────────────────────────────────────


# Manifest/namespace hosts that are structural noise, not C2/exfil endpoints.
_IGNORED_HOSTS = {
    "schemas.android.com", "www.w3.org", "ns.adobe.com", "xmlpull.org",
    "www.apache.org", "java.sun.com", "localhost",
}


def _host_of(value: str) -> str:
    """Extract a clean host. IOC values often carry embedded NULs / concatenated junk
    from cross-DEX string extraction, so cut at the first NUL/whitespace first."""
    value = (value or "").split("\x00")[0].strip()
    if not value:
        return ""
    value = value.split()[0]
    if value.startswith(("http://", "https://")):
        host = urlparse(value).hostname or value
    else:
        host = value.split("/")[0].split(":")[0]
    return (host or "").strip().strip(".,;\"'").lower()


def _behavior_graph(sig: _Signals, radar: list[CapabilityAxis]) -> BehaviorGraph:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    root_label = sig.package or (sig.file_type.upper() + " sample")
    nodes.append(GraphNode(id="sample", label=root_label, kind="sample", weight=3.0,
                           detail=sig.file_type))

    active = [a for a in radar if a.score >= 20]
    active.sort(key=lambda a: a.score, reverse=True)
    cap_ids: dict[str, str] = {}
    for axis in active:
        nid = f"cap:{axis.key}"
        cap_ids[axis.key] = nid
        nodes.append(GraphNode(id=nid, label=axis.label, kind="capability",
                               weight=1.0 + axis.score / 50.0,
                               detail="; ".join(axis.evidence[:3]) or None))
        edges.append(GraphEdge(source="sample", target=nid, kind="capability",
                               label=f"{axis.score}"))

    # Network endpoints from static IOCs + live peers (deduped, bounded).
    hosts: dict[str, str] = {}  # host -> detail/source
    for ioc in sig.iocs:
        if str(ioc.get("type", "")).lower() in _NET_IOC_TYPES and ioc.get("value"):
            h = _host_of(str(ioc["value"]))
            if h and h not in _IGNORED_HOSTS:
                hosts.setdefault(h, "static IOC")
    for peer in sig.net_peers:
        h = _host_of(str(peer.get("host") or ""))
        if h and h not in _IGNORED_HOSTS:
            hosts[h] = "live peer"

    net_cap = cap_ids.get("network_c2")
    for i, (host, src) in enumerate(list(hosts.items())[:12]):
        nid = f"net:{host}"
        nodes.append(GraphNode(id=nid, label=host, kind="host", weight=1.2, detail=src))
        anchor = net_cap or "sample"
        edges.append(GraphEdge(source=anchor, target=nid, kind="network",
                               label="live" if src == "live peer" else None))

    return BehaviorGraph(nodes=nodes, edges=edges)


# ── Top-level ────────────────────────────────────────────────────────────────


def build_visualizations(static: dict, dynamic: dict | None = None) -> Visualizations:
    """Derive the full visualization bundle from stored report dicts."""
    sig = _Signals(static, dynamic)
    heatmap = _permission_heatmap(sig)
    sig._perm_cats = heatmap  # let capability rules see category presence
    radar = _capability_radar(sig)
    attack = _attack_matrix(sig)
    graph = _behavior_graph(sig, radar)

    drivers = [f"{a.label} ({a.score})" for a in sorted(radar, key=lambda a: a.score,
               reverse=True) if a.score >= 40][:4]

    return Visualizations(
        file_type=sig.file_type,
        package=sig.package,
        has_dynamic=sig.has_dynamic,
        capability_radar=radar,
        permission_heatmap=heatmap,
        attack_matrix=attack,
        behavior_graph=graph,
        top_drivers=drivers,
    )
