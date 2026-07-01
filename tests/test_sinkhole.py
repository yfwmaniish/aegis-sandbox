"""Tests for live network-capture (sinkhole) detonation."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.dynamic.analyze import build_report  # noqa: E402
from aegis.dynamic.models import DynamicEnvironment, EventCategory  # noqa: E402
from aegis.dynamic.normalize import parse_sinkhole  # noqa: E402
from aegis.insights import build_visualizations  # noqa: E402
from aegis.orchestrator.docker_linux import _SINKHOLE_PY, DockerLinuxOrchestrator  # noqa: E402

_LOG = """SINKHOLE up ip=172.20.0.2
DNS evil-c2.example.com
DNS mail-118.196.64.77-connect.cn.
HTTP POST panel.evil.su /gate.php
HTTP GET evil-c2.example.com /beacon
garbage line ignored"""


def test_sinkhole_script_compiles():
    ast.parse(_SINKHOLE_PY)  # the embedded DNS/HTTP sinkhole must be valid Python


def test_parse_sinkhole_dns_and_http():
    evs = parse_sinkhole(_LOG)
    assert len(evs) == 4
    assert all(e.category == EventCategory.NETWORK for e in evs)
    dns = [e for e in evs if e.action == "dns_query"]
    http = [e for e in evs if e.action == "http_request"]
    assert {e.object.value for e in dns} == {"evil-c2.example.com", "mail-118.196.64.77-connect.cn"}
    assert "http://panel.evil.su/gate.php" in {e.object.value for e in http}
    assert http[0].detail["method"] in ("POST", "GET")


def test_c2_beacon_detector_and_rollup():
    rep = build_report(package="/tmp/s", profile="standard",
                       environment=DynamicEnvironment(backend="docker", network_policy="sinkhole"),
                       sinkhole=_LOG, exit_reason="finished")
    assert any(i.id == "dyn.c2_beacon" and i.severity.value == "high" for i in rep.indicators)
    peers = {p.host for p in rep.network_peers}
    assert "evil-c2.example.com" in peers and "panel.evil.su" in peers


def test_c2_beacon_lights_network_capability_and_attack():
    # The dynamic report's indicators feed the visualization layer via the analysis
    # report; here assert the mapping recognises the new indicator.
    from aegis.insights.mapping import ATTACK_MAP
    assert ("Command and Control", "T1437.001", "Application Layer Protocol: Web Protocols") \
        in ATTACK_MAP["dyn.c2_beacon"]
    # And it counts toward the Network/C2 capability axis.
    report = {"file_type": "elf", "indicators": [{"id": "dyn.c2_beacon", "severity": "high"}],
              "iocs": []}
    viz = build_visualizations(report, None)
    net = next(a for a in viz.capability_radar if a.key == "network_c2")
    assert net.score >= 55


def test_run_cmd_sinkhole_isolated_on_internal_net():
    o = DockerLinuxOrchestrator(settings=SimpleNamespace(docker_sinkhole=True), store=None)
    cmd = o._run_cmd_sinkhole("aegis-x", "/stage", "aegis-sinknet-abc", "172.20.0.2", 60)
    joined = " ".join(cmd)
    assert "--network aegis-sinknet-abc" in joined  # the --internal net (created elsewhere)
    assert "--network none" not in joined
    assert "--dns 172.20.0.2" in joined
    # Same lock-down as air-gap mode.
    assert "--cap-drop ALL" in joined and "--read-only" in joined
    assert "--security-opt no-new-privileges" in joined


def test_airgap_mode_still_network_none():
    o = DockerLinuxOrchestrator(settings=SimpleNamespace(docker_sinkhole=False), store=None)
    assert o.sinkhole is False
    assert "--network none" in " ".join(o._run_cmd("c", "/s", 60))
