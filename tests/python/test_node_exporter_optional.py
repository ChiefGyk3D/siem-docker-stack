"""Guards for the optional node_exporter service (issue #224): opt-in profile,
pinned tag, no published ports, read-only root and host mounts, no extra
privileges, and a Prometheus target that points at it."""
import json
import re

import yaml

from conftest import REPO_ROOT

COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
TARGET = REPO_ROOT / "docker" / "prometheus" / "targets" / "node.example.json"
DOC = REPO_ROOT / "docs" / "node-exporter.md"


def problems(svc):
    """Every way a node_exporter service definition breaks the safe default."""
    out = []
    if svc.get("profiles") != ["node-exporter"]:
        out.append("not opt-in")
    if not re.search(r"[:-]v\d+\.\d+\.\d+\}?$", str(svc.get("image", ""))):
        out.append("image not pinned to a version")
    if "ports" in svc:
        out.append("publishes ports")
    if svc.get("read_only") is not True:
        out.append("root filesystem writable")
    if svc.get("privileged") or svc.get("cap_add"):
        out.append("extra privileges")
    if svc.get("pid") == "host" or svc.get("network_mode") == "host":
        out.append("host namespace")
    if svc.get("networks") != ["siem-net"]:
        out.append("not on siem-net only")
    if "no-new-privileges:true" not in svc.get("security_opt", []):
        out.append("no-new-privileges missing")
    if svc.get("cap_drop") != ["ALL"]:
        out.append("capabilities not dropped")
    for vol in svc.get("volumes", []):
        parts = str(vol).split(":")
        if len(parts) < 3 or "ro" not in parts[2].split(","):
            out.append(f"mount not read-only: {vol}")
    if not any("--path.rootfs=/host" == str(c) for c in svc.get("command", [])):
        out.append("path.rootfs missing")
    return out


def _svc():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["node-exporter"]


def test_node_exporter_is_safe_by_default():
    assert problems(_svc()) == []


def test_host_mount_is_the_documented_one():
    assert "/:/host:ro,rslave" in _svc()["volumes"]


def test_guard_bites_on_each_mutant():
    base = _svc()
    mutants = {
        "ports": {**base, "ports": ["9100:9100"]},
        "loopback-less bind": {**base, "ports": ["0.0.0.0:9100:9100"]},
        "writable root": {**base, "read_only": False},
        "rw mount": {**base, "volumes": ["/:/host"]},
        "rw mount flag": {**base, "volumes": ["/:/host:rslave"]},
        "privileged": {**base, "privileged": True},
        "host pid": {**base, "pid": "host"},
        "host net": {**base, "network_mode": "host"},
        "always on": {k: v for k, v in base.items() if k != "profiles"},
        "latest": {**base, "image": "quay.io/prometheus/node-exporter:latest"},
    }
    for name, svc in mutants.items():
        assert problems(svc) != [], name


def test_target_points_at_the_service_and_is_not_a_real_address():
    data = json.loads(TARGET.read_text(encoding="utf-8"))
    assert data and data[0]["targets"] == ["node-exporter:9100"]
    assert data[0]["labels"]["instance_name"]


def test_doc_covers_install_verify_rollback():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("cp docker-compose.yml docker-compose.yml.bak",
                   "up -d --no-deps node-exporter",
                   'job="node"', "Rollback", "infra-alerts.yml"):
        assert needle in text, needle
