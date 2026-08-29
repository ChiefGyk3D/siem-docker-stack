"""JSON validity and schema sanity for Grafana dashboards, n8n workflows,
Prometheus file_sd examples, and OpenSearch templates."""
import json

import pytest

from conftest import REPO_ROOT

DASHBOARDS = sorted((REPO_ROOT / "dashboards").glob("*.json"))
N8N_WORKFLOWS = sorted((REPO_ROOT / "n8n").glob("*.json"))
FILE_SD_EXAMPLES = sorted(
    (REPO_ROOT / "docker" / "prometheus" / "targets").glob("*.example.json"))
OPENSEARCH_TEMPLATES = sorted((REPO_ROOT / "docker" / "opensearch").glob("*.json"))

# Not a dashboard: an exported list of Grafana datasource definitions.
NON_DASHBOARD_FILES = {"datasources_reference.json"}


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_dashboard_json_schema(path):
    data = _load(path)  # raises on invalid JSON
    if path.name in NON_DASHBOARD_FILES:
        assert isinstance(data, list) and data
        assert all(isinstance(ds, dict) for ds in data)
        return
    assert isinstance(data, dict)
    assert isinstance(data.get("title"), str) and data["title"].strip()
    assert isinstance(data.get("panels"), list) and data["panels"]


@pytest.mark.parametrize("path", N8N_WORKFLOWS, ids=lambda p: p.name)
def test_n8n_workflow_valid_json(path):
    data = _load(path)
    assert isinstance(data, dict)
    assert isinstance(data.get("nodes"), list) and data["nodes"]


@pytest.mark.parametrize("path", FILE_SD_EXAMPLES, ids=lambda p: p.name)
def test_prometheus_file_sd_example_schema(path):
    data = _load(path)
    assert isinstance(data, list) and data
    for group in data:
        assert isinstance(group.get("targets"), list) and group["targets"]
        for target in group["targets"]:
            assert isinstance(target, str) and ":" in target
        labels = group.get("labels", {})
        assert isinstance(labels, dict)
        assert all(isinstance(k, str) and isinstance(v, str)
                   for k, v in labels.items())


@pytest.mark.parametrize("path", OPENSEARCH_TEMPLATES, ids=lambda p: p.name)
def test_opensearch_template_valid_json(path):
    assert isinstance(_load(path), dict)
