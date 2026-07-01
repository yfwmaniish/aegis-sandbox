"""Sample similarity — "this looks like that malware" (FR-11).

Self-contained and dependency-light: ranks a target analysis against a corpus of prior
static reports using feature overlap (shared indicators, shared network endpoints, same
package / import hash, file type & size proximity) and, when both samples carry a TLSH
fuzzy hash, a locality-sensitive distance that dominates the score. Everything degrades
gracefully — no TLSH, no Qdrant, no embeddings required. The scoring is structured so a
vector backend (Qdrant) can be swapped in later without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.insights.build import _IGNORED_HOSTS, _host_of
from aegis.intel.models import SimilarMatch, SimilarResult

_NET_IOC_TYPES = {"ipv4", "ip", "ipv6", "domain", "url", "hostname", "telegram", "telegram_channel"}


@dataclass
class CorpusItem:
    analysis_id: str
    sha256: str
    filename: str | None
    file_type: str
    risk_score: float | None
    report: dict
    feats: "Features" = field(init=False)

    def __post_init__(self) -> None:
        self.feats = extract_features(self.report)


@dataclass
class Features:
    file_type: str
    size: int
    tlsh: str | None
    imphash: str | None
    package: str | None
    indicators: set[str]
    hosts: set[str]


def extract_features(report: dict) -> Features:
    apk = report.get("apk") or {}
    hashes = report.get("hashes") or {}
    indicators = {i.get("id") for i in (report.get("indicators") or []) if i.get("id")}
    hosts: set[str] = set()
    for ioc in report.get("iocs") or []:
        if str(ioc.get("type", "")).lower() in _NET_IOC_TYPES and ioc.get("value"):
            h = _host_of(str(ioc["value"]))
            if h and h not in _IGNORED_HOSTS:
                hosts.add(h)
    return Features(
        file_type=report.get("file_type", "unknown"),
        size=int(report.get("size") or 0),
        tlsh=hashes.get("tlsh"),
        imphash=hashes.get("imphash"),
        package=apk.get("package"),
        indicators=indicators,  # type: ignore[arg-type]
        hosts=hosts,
    )


def _tlsh_distance(a: str | None, b: str | None) -> int | None:
    if not a or not b:
        return None
    try:
        import tlsh  # type: ignore

        return int(tlsh.diff(a, b))
    except Exception:  # noqa: BLE001 - optional dependency / API drift
        return None


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def score_pair(t: Features, o: Features) -> tuple[float, dict]:
    """Return (score 0-100, detail) for a target vs. other feature set."""
    score = 0.0
    reasons: list[str] = []
    same_type = t.file_type == o.file_type and t.file_type != "unknown"

    dist = _tlsh_distance(t.tlsh, o.tlsh)
    if dist is not None:
        # TLSH: 0 == identical; ~>150 unrelated. Map to a 0..60 contribution.
        tlsh_sim = max(0.0, 1.0 - dist / 300.0)
        score += 60.0 * tlsh_sim
        if tlsh_sim > 0:
            band = "near-identical" if dist <= 30 else ("similar" if dist <= 100 else "distant")
            reasons.append(f"TLSH distance {dist} ({band})")

    shared_ind = t.indicators & o.indicators
    if same_type and shared_ind:
        score += 40.0 * _jaccard(t.indicators, o.indicators)
        reasons.append(f"shares {len(shared_ind)} behaviour indicator(s): "
                       + ", ".join(sorted(shared_ind)[:5]))

    shared_hosts = t.hosts & o.hosts
    if shared_hosts:
        score += 30.0 * _jaccard(t.hosts, o.hosts)
        reasons.append(f"shares {len(shared_hosts)} network endpoint(s): "
                       + ", ".join(sorted(shared_hosts)[:5]))

    same_pkg = bool(t.package and t.package == o.package)
    if same_pkg:
        score += 20.0
        reasons.append(f"same package {t.package}")

    same_imp = bool(t.imphash and t.imphash == o.imphash)
    if same_imp:
        score += 25.0
        reasons.append("identical PE import hash (imphash)")

    if same_type and t.size and o.size:
        ratio = min(t.size, o.size) / max(t.size, o.size)
        if ratio > 0.9:
            score += 6.0 * ratio
            reasons.append("near-identical file size")

    detail = {
        "tlsh_distance": dist, "shared_indicators": sorted(shared_ind),
        "shared_hosts": sorted(shared_hosts), "same_package": same_pkg,
        "same_imphash": same_imp, "reasons": reasons,
    }
    return min(score, 100.0), detail


def find_similar(
    target_report: dict,
    corpus: list[CorpusItem],
    *,
    target_sha256: str,
    limit: int = 10,
    min_score: float = 5.0,
) -> SimilarResult:
    """Rank ``corpus`` against ``target_report``. Excludes the target's own sample and
    dedupes the corpus by sample sha256 (keeps the highest-risk analysis per sample)."""
    tfeats = extract_features(target_report)

    # Dedupe by sha256 (skip the target file itself), preferring higher risk.
    best: dict[str, CorpusItem] = {}
    for item in corpus:
        if item.sha256 == target_sha256:
            continue
        cur = best.get(item.sha256)
        if cur is None or (item.risk_score or 0) > (cur.risk_score or 0):
            best[item.sha256] = item

    matches: list[SimilarMatch] = []
    for item in best.values():
        score, detail = score_pair(tfeats, item.feats)
        if score < min_score:
            continue
        matches.append(SimilarMatch(
            analysis_id=item.analysis_id, sample_sha256=item.sha256,
            filename=item.filename, file_type=item.file_type, score=round(score, 1),
            tlsh_distance=detail["tlsh_distance"], shared_indicators=detail["shared_indicators"],
            shared_hosts=detail["shared_hosts"], same_package=detail["same_package"],
            same_imphash=detail["same_imphash"], reasons=detail["reasons"],
            risk_score=item.risk_score,
        ))
    matches.sort(key=lambda m: m.score, reverse=True)
    matches = matches[:limit]

    note = None
    if not best:
        note = "No other samples in the corpus yet — submit more samples to enable similarity."
    elif not matches:
        note = "No sufficiently similar samples found in the corpus."
    return SimilarResult(
        target_sha256=target_sha256, corpus_size=len(best),
        count=len(matches), matches=matches, note=note,
    )
