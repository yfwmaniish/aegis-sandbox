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
* { box-sizing:border-box; }
body { font-family:"Inter",-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color:#0f172a; background:#eef2f7; margin:0; padding:0; font-variant-numeric:tabular-nums; }
.page { max-width:980px; margin:22px auto; padding:0 0 44px; background:#fff; border-radius:16px;
        overflow:hidden; box-shadow:0 1px 3px rgba(15,23,42,.08),0 20px 50px -30px rgba(15,23,42,.3); }
.pad { padding:0 40px; }
.masthead { background:linear-gradient(120deg,#0b1220 0%,#141d33 60%,#12283a 100%); color:#fff;
            padding:26px 40px; display:flex; align-items:center; gap:16px; }
.masthead .logo { width:42px; height:42px; flex:0 0 42px; }
.masthead .wm { font-size:23px; font-weight:800; letter-spacing:-.02em; line-height:1; }
.masthead .wm span { background:linear-gradient(135deg,#4f7dfb,#22d3ee); -webkit-background-clip:text; background-clip:text; color:transparent; }
.masthead .sub { font-size:10px; font-weight:600; letter-spacing:.2em; text-transform:uppercase; color:#8ea0c0; margin-top:5px; }
.masthead .gen { margin-left:auto; text-align:right; font-size:11px; color:#8ea0c0; }
h1 { font-size:20px; margin:0; font-weight:750; letter-spacing:-.01em; }
h2 { font-size:15px; margin:30px 0 10px; font-weight:700; letter-spacing:.01em; color:#0f172a;
     padding-bottom:7px; border-bottom:1px solid #e6ebf2; display:flex; align-items:center; gap:8px; }
h2::before { content:""; width:4px; height:15px; border-radius:2px; background:linear-gradient(#4f7dfb,#22d3ee); }
h3 { font-size:12px; margin:14px 0 6px; color:#475569; font-weight:650; text-transform:uppercase; letter-spacing:.03em; }
.muted { color:#64748b; }
.mono { font-family:ui-monospace,"Cascadia Code",Consolas,monospace; font-size:12px; word-break:break-all; }
.top { display:flex; align-items:center; gap:22px; border:1px solid #e6ebf2; border-radius:14px;
       padding:20px 24px; margin-top:20px; background:linear-gradient(180deg,#fbfcfe,#f4f7fb); }
.score { font-size:52px; font-weight:800; line-height:1; letter-spacing:-.03em; min-width:92px; text-align:center; }
.score .u { font-size:14px; font-weight:600; color:#94a3b8; }
.badge { color:#fff; font-weight:750; padding:5px 14px; border-radius:999px; font-size:12px;
         text-transform:uppercase; letter-spacing:.04em; }
.metar { color:#64748b; font-size:13px; margin-top:6px; }
table { width:100%; border-collapse:collapse; font-size:13px; margin-top:4px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid #eef2f7; vertical-align:top; }
th { color:#64748b; font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.03em; }
table.kv td:first-child { color:#64748b; width:150px; font-weight:500; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:start; }
.card { border:1px solid #e6ebf2; border-radius:14px; padding:15px 17px; background:#fff; }
.card h3 { margin-top:0; }
.find { position:relative; border:1px solid #eef2f7; border-left:3px solid #94a3b8; background:#fbfcfe;
        border-radius:9px; padding:9px 13px; margin:7px 0; }
.find .sev { color:#fff; font-size:9.5px; font-weight:800; text-transform:uppercase; letter-spacing:.03em; padding:2px 8px; border-radius:5px; }
.find b { font-size:13.5px; }
.find .inf { color:#475569; font-size:12.5px; margin-top:5px; line-height:1.5; }
.find .ev { color:#94a3b8; font-size:11px; font-family:ui-monospace,monospace; margin-top:5px; word-break:break-word; }
.pill { display:inline-block; background:#f1f5f9; border:1px solid #e2e8f0; border-radius:999px;
        padding:2px 9px; font-size:11px; margin:2px 4px 2px 0; color:#334155; }
.pill.danger { border-color:#ea580c; color:#ea580c; background:#fff7ed; }
.heat { display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:8px; }
.tile { border:1px solid #e6ebf2; border-radius:10px; padding:9px 11px; }
.tile .t { font-size:11px; font-weight:650; } .tile .n { font-size:21px; font-weight:800; line-height:1.1; }
.tile .p { font-size:9px; opacity:.9; word-break:break-word; }
.attack { display:grid; grid-template-columns:repeat(auto-fill,minmax(165px,1fr)); gap:10px; }
.acol .tac { font-size:10px; text-transform:uppercase; letter-spacing:.03em; color:#64748b;
             border-bottom:1px solid #e6ebf2; padding-bottom:4px; margin-bottom:6px; font-weight:600; }
.tech { border-left:3px solid #cbd5e1; background:#fbfcfe; border-radius:7px; padding:5px 9px; margin-bottom:6px; }
.tech .tid { font-size:10px; color:#64748b; } .tech .tnm { font-size:12px; font-weight:600; }
.tags { font-size:0; } .tag2 { font-size:10px; color:#4f7dfb; border:1px solid #dbe4f3;
        background:#f5f8ff; border-radius:999px; padding:2px 8px; margin-left:5px; }
.sim { display:flex; gap:14px; align-items:center; border:1px solid #e6ebf2; border-radius:10px; padding:10px 13px; margin:7px 0; }
.sim .ss { font-size:22px; font-weight:800; min-width:46px; text-align:center; }
pre { background:#0f1728; color:#e2e8f0; border:1px solid #1e293b; border-radius:10px; padding:14px;
      font-size:11px; line-height:1.55; overflow:auto; white-space:pre-wrap; word-break:break-word;
      font-family:ui-monospace,Consolas,monospace; }
ul,ol { margin:7px 0; padding-left:22px; font-size:13px; line-height:1.6; }
.foot { margin:36px 40px 0; padding-top:14px; border-top:1px solid #e6ebf2; color:#94a3b8; font-size:11px; }
.noprint { position:fixed; top:16px; right:16px; }
.noprint button { background:linear-gradient(135deg,#4f7dfb,#22d3ee); color:#fff; border:0; padding:10px 16px;
                  border-radius:9px; font-size:13px; font-weight:600; cursor:pointer; box-shadow:0 8px 20px -8px rgba(79,125,251,.6); }
@media print { .noprint { display:none; } body { background:#fff; margin:0; }
               .page { max-width:none; margin:0; border-radius:0; box-shadow:none; }
               .masthead { background:#0b1220 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
               h2 { break-after:avoid; }
               .find,.tile,.tech,.sim,pre,.card,svg,.grid2>div,table { break-inside:avoid; }
               .grid2 { display:block; } .grid2>.card { margin-bottom:14px; } }
"""

_REPORT_LOGO = (
    '<svg class="logo" viewBox="0 0 48 48" fill="none">'
    '<defs><linearGradient id="rmt" x1="6" y1="3" x2="42" y2="45" gradientUnits="userSpaceOnUse">'
    '<stop stop-color="#4f7dfb"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs>'
    '<path d="M24 3 41 9v13c0 11.2-7.2 19.3-17 23-9.8-3.7-17-11.8-17-23V9L24 3Z" '
    'fill="url(#rmt)" fill-opacity="0.18" stroke="url(#rmt)" stroke-width="2" stroke-linejoin="round"/>'
    '<circle cx="24" cy="23" r="8.5" fill="none" stroke="url(#rmt)" stroke-width="2"/>'
    '<circle cx="24" cy="23" r="2.4" fill="url(#rmt)"/>'
    '<path d="M24 9.5V13M24 33v3.5M9.5 23H13M35 23h3.5" stroke="url(#rmt)" stroke-width="2" stroke-linecap="round"/></svg>'
)


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
<title>MalwareTotal report — {_e(filename or sha256[:12])}</title><style>{_CSS}</style></head>
<body><div class="noprint"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="page">
  <div class="masthead">
    {_REPORT_LOGO}
    <div>
      <div class="wm">Malware<span>Total</span></div>
      <div class="sub">Malware Analysis Report</div>
    </div>
    <div class="gen">Generated<br>{gen}</div>
  </div>
  <div class="pad">
  <div class="top">
    <div class="score" style="color:{color}">{(risk or 0):.0f}<span class="u">/100</span></div>
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
  </div>

  <div class="foot"><b>MalwareTotal</b> · AI-assisted malware analysis · findings are heuristic and require analyst review.</div>
</div></body></html>"""
