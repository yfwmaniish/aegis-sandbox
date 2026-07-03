"""Self-contained HTML analyst report.

Renders one standalone, print-to-PDF-friendly HTML document for an analysis: verdict,
file metadata, findings, IOCs, the capability radar / permission heatmap / MITRE ATT&CK
matrix / behaviour graph (as inline SVG + HTML, no JavaScript required), the dynamic
run summary, the Claude narrative (if present), generated YARA/Sigma rules, and similar
samples. Everything is inlined so the file can be handed off or archived on its own.
"""

from __future__ import annotations

import html
import math
from datetime import UTC, datetime

from aegis.insights.models import Visualizations
from aegis.intel.models import RuleBundle, SimilarResult

_AXIS_SHORT = {
    "sms_telephony": "SMS", "network_c2": "Network/C2", "surveillance": "Surveillance",
    "persistence_control": "Persistence", "evasion_obfuscation": "Evasion",
    "code_execution": "Exec", "privilege_escalation": "PrivEsc", "data_exfiltration": "Exfil",
}
_RISKCOL = {"none": "#c9d1d9", "low": "#3b82f6", "medium": "#d69e2e",
            "high": "#dd6b20", "critical": "#e53e3e"}
_SEVCOL = {"low": "#3b82f6", "medium": "#d69e2e", "high": "#dd6b20", "critical": "#e53e3e"}


def _e(s: object) -> str:
    return html.escape(str(s if s is not None else ""))


def _verdict(risk: float | None) -> tuple[str, str]:
    r = risk or 0
    if r >= 70:
        return "CRITICAL", "#e53e3e"
    if r >= 50:
        return "HIGH", "#dd6b20"
    if r >= 25:
        return "MEDIUM", "#d69e2e"
    if r > 0:
        return "LOW", "#3b82f6"
    return "CLEAN", "#38a169"


# ── SVG blocks ───────────────────────────────────────────────────────────────


def _radar_svg(axes: list) -> str:
    W, H, cx, cy, R = 360, 300, 180, 154, 96
    n = len(axes)
    if not n:
        return ""

    def pt(i: int, frac: float) -> tuple[float, float]:
        a = -math.pi / 2 + i * 2 * math.pi / n
        return cx + R * frac * math.cos(a), cy + R * frac * math.sin(a)

    rings = ""
    for f in (0.25, 0.5, 0.75, 1.0):
        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in (pt(i, f) for i in range(n)))
        rings += f'<polygon points="{poly}" fill="none" stroke="#e2e8f0" stroke-width="1"/>'
    spokes = labels = ""
    for i, ax in enumerate(axes):
        ex, ey = pt(i, 1)
        spokes += f'<line x1="{cx}" y1="{cy}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="#e2e8f0"/>'
        lx, ly = pt(i, 1.17)
        anchor = "middle" if abs(lx - cx) < 12 else ("start" if lx > cx else "end")
        short = _AXIS_SHORT.get(ax.key, ax.key)
        labels += (f'<text x="{lx:.1f}" y="{ly:.1f}" fill="#4a5568" font-size="10" '
                   f'text-anchor="{anchor}" dominant-baseline="middle">{_e(short)}</text>')
        if ax.score:
            labels += (f'<text x="{lx:.1f}" y="{ly + 11:.1f}" fill="#1a202c" font-size="9" '
                       f'font-weight="700" text-anchor="{anchor}" dominant-baseline="middle">{ax.score}</text>')
    data = " ".join(f"{x:.1f},{y:.1f}" for x, y in (pt(i, axes[i].score / 100) for i in range(n)))
    dots = "".join(f'<circle cx="{pt(i, axes[i].score/100)[0]:.1f}" '
                   f'cy="{pt(i, axes[i].score/100)[1]:.1f}" r="2.6" fill="#3b4cb8"/>' for i in range(n))
    return (f'<svg viewBox="0 0 {W} {H}" width="100%">'
            f'{rings}{spokes}'
            f'<polygon points="{data}" fill="#3b4cb8" fill-opacity="0.25" stroke="#3b4cb8" stroke-width="1.6"/>'
            f'{dots}{labels}</svg>')


def _heatmap_html(cats: list, file_type: str) -> str:
    if not any(c.count for c in cats):
        note = " (manifest may be obfuscated/unpacked)" if file_type == "apk" else ""
        return f'<p class="muted">No permissions parsed from the manifest{note}.</p>'
    tiles = ""
    for c in cats:
        on = c.count > 0
        col = _RISKCOL.get(c.risk, _RISKCOL["none"])
        perms = ", ".join(p.permission + (" •" if p.used_at_runtime else "")
                          for p in c.permissions)
        style = (f"background:{col};border-color:{col};color:#fff" if on and c.risk != "low"
                 else (f"background:{col};border-color:{col};color:#fff" if on else ""))
        tiles += (f'<div class="tile" style="{style}"><div class="t">{_e(c.label)}</div>'
                  f'<div class="n">{c.count}</div><div class="p">{_e(perms) if on else "—"}</div></div>')
    return f'<div class="heat">{tiles}</div>'


def _attack_html(techs: list) -> str:
    if not techs:
        return '<p class="muted">No ATT&CK techniques mapped from the findings.</p>'
    by_tac: dict[str, list] = {}
    for t in techs:
        by_tac.setdefault(t.tactic, []).append(t)
    cols = ""
    for tac, lst in by_tac.items():
        cards = ""
        for t in lst:
            col = _SEVCOL.get(t.severity, _SEVCOL["medium"])
            cards += (f'<div class="tech" style="border-left-color:{col}">'
                      f'<div class="tid">{_e(t.technique_id)}</div>'
                      f'<div class="tnm">{_e(t.technique)}</div></div>')
        cols += f'<div class="acol"><div class="tac">{_e(tac)}</div>{cards}</div>'
    return f'<div class="attack">{cols}</div>'


def _graph_svg(graph) -> str:
    nodes = graph.nodes
    edges = graph.edges
    if len(nodes) <= 1:
        return '<p class="muted">No behavioural relationships to graph.</p>'
    W, H, cx, cy = 720, 340, 360, 170
    caps = [n for n in nodes if n.kind == "capability"]
    hosts = [n for n in nodes if n.kind == "host"]
    pos: dict[str, tuple[float, float]] = {"sample": (cx, cy)}
    for i, nd in enumerate(caps):
        a = -math.pi / 2 + i * 2 * math.pi / max(len(caps), 1)
        pos[nd.id] = (cx + 100 * math.cos(a), cy + 82 * math.sin(a))
    for i, nd in enumerate(hosts):
        a = -math.pi / 2 + (i + 0.5) * 2 * math.pi / max(len(hosts), 1)
        pos[nd.id] = (cx + 250 * math.cos(a), cy + 135 * math.sin(a))
    esvg = ""
    for e in edges:
        p, q = pos.get(e.source), pos.get(e.target)
        if not p or not q:
            continue
        live = e.label == "live"
        stroke = "#e53e3e" if live else "#cbd5e0"
        width = 1.6 if live else 1
        dash = ' stroke-dasharray="4 3"' if live else ""
        esvg += (f'<line x1="{p[0]:.1f}" y1="{p[1]:.1f}" x2="{q[0]:.1f}" y2="{q[1]:.1f}" '
                 f'stroke="{stroke}" stroke-width="{width}"{dash}/>')
    nsvg = ""
    for nd in nodes:
        p = pos.get(nd.id)
        if not p:
            continue
        if nd.kind == "sample":
            r, fill, label = 13, "#3b4cb8", nd.label[:24]
        elif nd.kind == "capability":
            r, fill, label = 6 + min(6, (nd.weight or 1) * 2), "#dd6b20", nd.label[:16]
        else:
            r, fill = 6, ("#e53e3e" if nd.detail == "live peer" else "#3b82f6")
            label = nd.label[:22]
        below = p[1] >= cy
        ty = p[1] + r + 11 if below else p[1] - r - 5
        nsvg += (f'<g><circle cx="{p[0]:.1f}" cy="{p[1]:.1f}" r="{r:.1f}" fill="{fill}" '
                 f'stroke="#fff" stroke-width="1.5"/>'
                 f'<text x="{p[0]:.1f}" y="{ty:.1f}" fill="#1a202c" font-size="10" '
                 f'text-anchor="middle">{_e(label)}</text></g>')
    return f'<svg viewBox="0 0 {W} {H}" width="100%">{esvg}{nsvg}</svg>'


# ── Section builders ─────────────────────────────────────────────────────────


def _findings_html(static: dict) -> str:
    inds = static.get("indicators") or []
    if not inds:
        return '<p class="muted">No heuristic indicators raised.</p>'
    out = ""
    for i in sorted(inds, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    .get(x.get("severity", "low"), 4)):
        col = _SEVCOL.get(i.get("severity", "low"), "#718096")
        ev = " · ".join(_e(x) for x in (i.get("evidence") or [])[:8])
        inf = f'<div class="inf">{_e(i.get("inference"))}</div>' if i.get("inference") else ""
        ev_html = f'<div class="ev">{ev}</div>' if ev else ""
        out += (f'<div class="find" style="border-left-color:{col}">'
                f'<div><span class="sev" style="background:{col}">{_e(i.get("severity"))}</span> '
                f'<b>{_e(i.get("title"))}</b></div>{inf}{ev_html}</div>')
    return out


def _iocs_html(static: dict) -> str:
    iocs = static.get("iocs") or []
    if not iocs:
        return '<p class="muted">No IOCs extracted.</p>'
    rows = "".join(f'<tr><td>{_e(i.get("type"))}</td><td class="mono">{_e(i.get("value"))}</td>'
                   f'<td>{_e(i.get("confidence"))}</td><td class="muted">{_e(i.get("source"))}</td></tr>'
                   for i in iocs)
    return ('<table><thead><tr><th>Type</th><th>Value</th><th>Conf</th><th>Source</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


def _android_html(static: dict) -> str:
    a = static.get("apk")
    if not a:
        return ""
    perms = a.get("permissions") or []
    dang = set(a.get("dangerous_permissions") or [])
    pills = "".join(
        f'<span class="pill{" danger" if p in dang else ""}">{_e(p.replace("android.permission.", ""))}</span>'
        for p in perms) or '<span class="muted">none declared</span>'
    return (f'<h2>Android</h2><table class="kv"><tbody>'
            f'<tr><td>Package</td><td class="mono">{_e(a.get("package"))} '
            f'v{_e(a.get("version_name"))}/{_e(a.get("version_code"))}</td></tr>'
            f'<tr><td>SDK</td><td>min {_e(a.get("min_sdk"))} / target {_e(a.get("target_sdk"))}</td></tr>'
            f'<tr><td>Components</td><td>{a.get("activities",0)} act · {a.get("services",0)} svc · '
            f'{a.get("receivers",0)} rcv · {a.get("providers",0)} prov</td></tr>'
            f'<tr><td>Accessibility</td><td>{a.get("requests_accessibility")} · '
            f'device admin: {a.get("requests_device_admin")}</td></tr></tbody></table>'
            f'<p style="margin-top:8px"><b>Permissions ({len(perms)}):</b><br>{pills}</p>')


def _dynamic_html(dynamic: dict | None) -> str:
    if not dynamic:
        return ""
    env = dynamic.get("environment") or {}
    peers = dynamic.get("network_peers") or []
    peer_rows = "".join(f"<li class='mono'>{_e(p.get('host'))}"
                        f"{':' + str(p.get('port')) if p.get('port') else ''}</li>" for p in peers)
    cats = dynamic.get("category_counts") or {}
    cat_str = ", ".join(f"{k}: {v}" for k, v in sorted(cats.items())) or "—"
    return (f'<h2>Dynamic detonation</h2><table class="kv"><tbody>'
            f'<tr><td>Backend</td><td>{_e(env.get("backend"))} '
            f'({_e(env.get("network_policy"))})</td></tr>'
            f'<tr><td>Package</td><td class="mono">{_e(dynamic.get("package"))}</td></tr>'
            f'<tr><td>Runtime</td><td>{_e(dynamic.get("runtime_seconds"))}s · '
            f'exit: {_e(dynamic.get("exit_reason"))} · {dynamic.get("event_count",0)} events</td></tr>'
            f'<tr><td>Event categories</td><td>{_e(cat_str)}</td></tr></tbody></table>'
            f'{f"<p style=margin-top:8px><b>Network peers:</b></p><ul>{peer_rows}</ul>" if peer_rows else ""}')


def _understanding_html(u: dict | None) -> str:
    if not u:
        return ""
    body = u.get("understanding") or u
    parts = ['<h2>AI analyst narrative <span class="muted">(Claude — review required)</span></h2>']
    if body.get("summary"):
        parts.append(f'<p>{_e(body["summary"])}</p>')
    if body.get("classification"):
        parts.append(f'<p><b>Classification:</b> {_e(body["classification"])}</p>')
    steps = body.get("behavior_workflow") or body.get("workflow") or []
    if steps:
        parts.append("<ol>" + "".join(f"<li>{_e(s)}</li>" for s in steps) + "</ol>")
    actions = body.get("recommended_actions") or body.get("defensive_actions") or []
    if actions:
        parts.append("<p><b>Recommended actions:</b></p><ul>"
                     + "".join(f"<li>{_e(s)}</li>" for s in actions) + "</ul>")
    return "".join(parts)


def _rules_html(rules: RuleBundle) -> str:
    tags = "".join(f'<span class="tag2">{_e(t)}</span>' for t in rules.attack_tags)
    return (f'<h2>Detection rules <span class="tags">{tags}</span></h2>'
            f'<p class="muted">Auto-generated heuristics — review before deployment.</p>'
            f'<h3>YARA</h3><pre>{_e(rules.yara.text)}</pre>'
            f'<h3>Sigma</h3><pre>{_e(rules.sigma.yaml)}</pre>')


def _similar_html(similar: SimilarResult) -> str:
    if not similar.matches:
        return f'<h2>Similar samples</h2><p class="muted">{_e(similar.note or "None found.")}</p>'
    rows = ""
    for m in similar.matches:
        col = "#dd6b20" if m.score >= 60 else "#d69e2e"
        rows += (f'<div class="sim"><div class="ss" style="color:{col}">{m.score}</div>'
                 f'<div><b>{_e(m.filename or m.sample_sha256[:16])}</b> '
                 f'<span class="muted">· {_e(m.file_type)}'
                 f'{f" · risk {m.risk_score}" if m.risk_score is not None else ""}</span>'
                 f'<div class="muted">{_e(" · ".join(m.reasons))}</div></div></div>')
    return f'<h2>Similar samples <span class="muted">({similar.corpus_size} in corpus)</span></h2>{rows}'


# ── Top-level ────────────────────────────────────────────────────────────────

_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       color:#1a202c; background:#f7fafc; margin:0; padding:0; }
.page { max-width:960px; margin:0 auto; padding:28px 34px 60px; background:#fff; }
h1 { font-size:24px; margin:0 0 2px; }
h2 { font-size:17px; margin:26px 0 8px; padding-bottom:5px; border-bottom:2px solid #edf2f7; }
h3 { font-size:13px; margin:14px 0 5px; color:#4a5568; }
.muted { color:#718096; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size:12px; word-break:break-all; }
.top { display:flex; align-items:center; gap:18px; border:1px solid #e2e8f0; border-radius:10px;
       padding:16px 20px; margin-top:14px; }
.score { font-size:44px; font-weight:800; line-height:1; }
.badge { color:#fff; font-weight:700; padding:3px 12px; border-radius:6px; font-size:13px; }
.metar { color:#718096; font-size:13px; margin-top:4px; }
table { width:100%; border-collapse:collapse; font-size:13px; margin-top:4px; }
th,td { text-align:left; padding:5px 9px; border-bottom:1px solid #edf2f7; vertical-align:top; }
th { color:#718096; }
table.kv td:first-child { color:#718096; width:150px; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:18px; align-items:start; }
.card { border:1px solid #e2e8f0; border-radius:10px; padding:12px 14px; }
.card h3 { margin-top:0; }
.find { border-left:3px solid #718096; background:#f7fafc; border-radius:5px; padding:7px 10px; margin:6px 0; }
.find .sev { color:#fff; font-size:10px; text-transform:uppercase; padding:1px 6px; border-radius:4px; }
.find .inf { color:#4a5568; font-size:12px; margin-top:3px; }
.find .ev { color:#718096; font-size:11px; font-family:ui-monospace,monospace; margin-top:3px; }
.pill { display:inline-block; background:#edf2f7; border:1px solid #e2e8f0; border-radius:999px;
        padding:1px 8px; font-size:11px; margin:2px 3px 2px 0; }
.pill.danger { border-color:#dd6b20; color:#dd6b20; }
.heat { display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:7px; }
.tile { border:1px solid #e2e8f0; border-radius:8px; padding:7px 9px; }
.tile .t { font-size:11px; font-weight:650; } .tile .n { font-size:19px; font-weight:800; }
.tile .p { font-size:9px; opacity:.9; word-break:break-word; }
.attack { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:9px; }
.acol .tac { font-size:10px; text-transform:uppercase; letter-spacing:.03em; color:#718096;
             border-bottom:1px solid #e2e8f0; padding-bottom:3px; margin-bottom:5px; }
.tech { border-left:3px solid #cbd5e0; background:#f7fafc; border-radius:5px; padding:4px 7px; margin-bottom:5px; }
.tech .tid { font-size:10px; color:#718096; } .tech .tnm { font-size:12px; font-weight:600; }
.tags { font-size:0; } .tag2 { font-size:10px; color:#3b82f6; border:1px solid #e2e8f0;
        border-radius:999px; padding:1px 7px; margin-left:5px; }
.sim { display:flex; gap:12px; border:1px solid #e2e8f0; border-radius:8px; padding:8px 11px; margin:6px 0; }
.sim .ss { font-size:20px; font-weight:800; min-width:46px; }
pre { background:#f7fafc; border:1px solid #e2e8f0; border-radius:8px; padding:11px;
      font-size:11px; overflow:auto; white-space:pre-wrap; word-break:break-word; }
ul,ol { margin:6px 0; padding-left:22px; font-size:13px; }
.foot { margin-top:34px; padding-top:12px; border-top:1px solid #e2e8f0; color:#a0aec0; font-size:11px; }
.noprint { position:fixed; top:14px; right:14px; }
.noprint button { background:#3b4cb8; color:#fff; border:0; padding:9px 15px; border-radius:7px;
                  font-size:13px; cursor:pointer; }
@media print { .noprint { display:none; } body { background:#fff; } .page { max-width:none; padding:0 6px; }
               h2 { break-after:avoid; }
               .find,.tile,.tech,.sim,pre,.card,svg,.grid2>div,table { break-inside:avoid; }
               .grid2 { display:block; } .grid2>.card { margin-bottom:14px; } }
"""


def build_report_html(
    *, static: dict, viz: Visualizations, dynamic: dict | None,
    understanding: dict | None, rules: RuleBundle, similar: SimilarResult,
    sha256: str, filename: str | None, risk: float | None, target_os: str | None,
) -> str:
    label, color = _verdict(risk)
    gen = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    h = static.get("hashes") or {}
    ent = static.get("entropy") or {}
    n_ind = len(static.get("indicators") or [])
    n_ioc = len(static.get("iocs") or [])

    imphash_row = (f'<tr><td>imphash</td><td class="mono">{_e(h.get("imphash"))}</td></tr>'
                   if h.get("imphash") else "")
    tlsh_row = (f'<tr><td>TLSH</td><td class="mono">{_e(h.get("tlsh"))}</td></tr>'
                if h.get("tlsh") else "")
    meta_rows = (
        f'<tr><td>File name</td><td class="mono">{_e(filename or "—")}</td></tr>'
        f'<tr><td>File type</td><td>{_e(static.get("file_type"))} '
        f'<span class="muted">({_e(static.get("detected_mime"))})</span></td></tr>'
        f'<tr><td>Size</td><td>{static.get("size", 0):,} bytes</td></tr>'
        f'<tr><td>SHA256</td><td class="mono">{_e(sha256)}</td></tr>'
        f'{imphash_row}{tlsh_row}'
        f'<tr><td>Entropy</td><td>{_e(ent.get("overall"))} '
        f'<span class="muted">(packing: {_e(ent.get("packing_likelihood"))})</span></td></tr>'
        f'<tr><td>Target OS</td><td>{_e(target_os or "—")}</td></tr>'
    )
    drivers = " · ".join(_e(d) for d in viz.top_drivers) or "none"
    android = static.get("file_type") in ("apk", "dex")
    heat_card = (f'<div class="card"><h3>Permission heatmap</h3>'
                 f'{_heatmap_html(viz.permission_heatmap, static.get("file_type", ""))}</div>'
                 if android else "")
    radar_span = "" if android else ' style="grid-column:1/-1"'

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis report — {_e(filename or sha256[:12])}</title><style>{_CSS}</style></head>
<body><div class="noprint"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="page">
  <h1>🛡️ Aegis Sandbox — Analysis Report</h1>
  <div class="muted">Generated {gen}</div>

  <div class="top">
    <div class="score" style="color:{color}">{(risk or 0):.0f}</div>
    <div><span class="badge" style="background:{color}">{label}</span>
      <div class="metar">{n_ind} indicator(s) · {n_ioc} IOC(s) · risk {(risk or 0):.1f}/100</div>
      <div class="metar"><b>Top drivers:</b> {drivers}</div></div>
  </div>

  <h2>Sample</h2><table class="kv"><tbody>{meta_rows}</tbody></table>

  <h2>Findings</h2>{_findings_html(static)}

  <h2>Visual analysis</h2>
  <div class="grid2">
    <div class="card"{radar_span}><h3>Capability radar</h3>{_radar_svg(viz.capability_radar)}</div>
    {heat_card}
  </div>
  <div class="card" style="margin-top:14px"><h3>MITRE ATT&CK</h3>{_attack_html(viz.attack_matrix)}</div>
  <div class="card" style="margin-top:14px"><h3>Behaviour &amp; network graph</h3>{_graph_svg(viz.behavior_graph)}</div>

  {_android_html(static)}
  {_dynamic_html(dynamic)}
  {_understanding_html(understanding)}

  <h2>Indicators of Compromise</h2>{_iocs_html(static)}

  {_similar_html(similar)}
  {_rules_html(rules)}

  <div class="foot">Aegis Sandbox · AI-assisted malware analysis · findings are heuristic and require analyst review.</div>
</div></body></html>"""
