"""Guards for the Prometheus OTLP receiver (issue #331 in the maintainer's
tracker): a separate, authenticated instance so pushed series never share a
database with the SIEM alert rules, separate accounts, private file modes,
loopback by default, and docs with the firewall step, verification and
rollback using placeholder addresses only."""
import os
import re
import stat
import subprocess
import textwrap

import pytest
import yaml

from conftest import REPO_ROOT

COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
MAIN_PROM_YML = REPO_ROOT / "docker" / "prometheus" / "prometheus.yml"
OTLP_DIR = REPO_ROOT / "docker" / "prometheus-otlp"
OTLP_YML = OTLP_DIR / "prometheus.yml"
WEB_EXAMPLE = OTLP_DIR / "web.yml.example"
DOC = REPO_ROOT / "docs" / "prometheus-otlp.md"
README = REPO_ROOT / "README.md"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DATASOURCES = (REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources"
               / "datasources.yml")
RENDER = REPO_ROOT / "scripts" / "render-prometheus-web-config.sh"
GITIGNORE = REPO_ROOT / ".gitignore"

OTLP_FLAG = "--web.enable-otlp-receiver"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
# Documentation range (RFC 5737) plus loopback and wildcard are the only
# addresses a public doc may name.
ALLOWED_IP = re.compile(r"^(192\.0\.2\.\d{1,3}(/\d{1,2})?|127\.0\.0\.1|0\.0\.0\.0)$")


def non_placeholder_ips(text):
    return [m for m in IPV4.findall(text) if not ALLOWED_IP.match(m)]


def services_with(services, flag):
    return sorted(n for n, s in services.items() if flag in s.get("command", []))


def _services():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def _yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_guards_bite():
    assert non_placeholder_ips("allow 10.1.2.3 and 192.0.2.10") == ["10.1.2.3"]
    assert non_placeholder_ips("allow 198.51.100.7/24") == ["198.51.100.7/24"]
    assert non_placeholder_ips("allow 192.0.2.10 and 192.0.2.0/24") == []
    assert services_with({"a": {"command": [OTLP_FLAG]}, "b": {}}, OTLP_FLAG) == ["a"]


# --- the receiver lives in its own instance --------------------------------

def test_only_the_dedicated_instance_has_the_receiver():
    assert services_with(_services(), OTLP_FLAG) == ["prometheus-otlp"]


def test_main_prometheus_unchanged_by_the_receiver():
    main = _services()["prometheus"]
    assert OTLP_FLAG not in main["command"]
    assert not any("web.config.file" in c for c in main["command"])
    assert main["ports"] == ["${BIND_ADDR:-127.0.0.1}:${PROMETHEUS_PORT:-9090}:9090"]


def test_receiver_instance_is_least_privilege():
    svc = _services()["prometheus-otlp"]
    cmd = svc["command"]
    assert "--web.config.file=/etc/prometheus/web.yml" in cmd
    # no lifecycle or admin API reach for any account
    assert not any("web.enable-lifecycle" in c or "web.enable-admin-api" in c for c in cmd)
    assert svc["user"] == "65534"
    ports = svc["ports"]
    assert len(ports) == 1
    assert ports[0].startswith("${PROMETHEUS_OTLP_BIND_ADDR:-127.0.0.1}:"), ports[0]
    assert "./prometheus-otlp/web.yml:/etc/prometheus/web.yml:ro" in svc["volumes"]


def test_receiver_config_has_window_and_no_scrape_or_rules():
    data = _yaml(OTLP_YML)
    assert data["storage"]["tsdb"]["out_of_order_time_window"] == "30m"
    otlp = data.get("otlp")
    assert isinstance(otlp, dict) and not otlp.get("promote_all_resource_attributes")
    assert "scrape_configs" not in data and "rule_files" not in data


def test_main_prometheus_scrapes_receiver_with_its_own_account():
    data = _yaml(MAIN_PROM_YML)
    job = [j for j in data["scrape_configs"] if j["job_name"] == "prometheus-otlp"][0]
    assert job["basic_auth"]["username"] == "scrape"
    assert job["basic_auth"]["password_file"] == "/etc/prometheus/secrets/otlp-scrape-password"
    assert job["static_configs"][0]["targets"] == ["prometheus-otlp:9090"]
    assert "storage" not in data and "otlp" not in data


def test_grafana_reads_the_receiver_with_its_own_account():
    sources = {d["uid"]: d for d in _yaml(DATASOURCES)["datasources"]}
    ds = sources["prometheus-otlp"]
    assert ds["url"] == "http://prometheus-otlp:9090"
    assert ds["basicAuth"] is True and ds["basicAuthUser"] == "grafana"
    assert ds["secureJsonData"]["basicAuthPassword"] == "$PROMETHEUS_OTLP_GRAFANA_PASSWORD"
    # the SIEM Prometheus datasource is untouched
    assert "basicAuth" not in sources["prometheus"]
    env = _services()["grafana"]["environment"]
    line = [e for e in env if e.startswith("PROMETHEUS_OTLP_GRAFANA_PASSWORD=")]
    assert line and ":?" in line[0]


def test_web_config_example_has_three_separate_accounts():
    assert sorted(_yaml(WEB_EXAMPLE)["basic_auth_users"]) == ["grafana", "scrape", "sender"]


def test_rendered_files_are_ignored_by_git():
    ignore = GITIGNORE.read_text(encoding="utf-8")
    assert "docker/prometheus-otlp/web.yml" in ignore
    assert "docker/prometheus-otlp/secrets/*" in ignore


def test_env_example_lists_the_accounts_and_loopback_default():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for name in ("PROMETHEUS_OTLP_SENDER_PASSWORD", "PROMETHEUS_OTLP_GRAFANA_PASSWORD",
                 "PROMETHEUS_OTLP_SCRAPE_PASSWORD", "PROMETHEUS_OTLP_BIND_ADDR"):
        assert name in text


# --- render script: private modes, separate secrets ----------------------------

SENDER, GRAFANA, SCRAPE = "Zx9-unique-sender", "Zx9-unique-grafana", "Zx9-unique-scrape"


@pytest.fixture()
def render(tmp_path):
    """Run the script against a temp tree with a stub htpasswd (hermetic)."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "htpasswd"
    stub.write_text(textwrap.dedent("""\
        #!/bin/sh
        # fake: read the password on stdin, print user:<fixed bcrypt-shaped hash>
        cat > /dev/null
        printf '%s:$2y$12$stubstubstubstubstubstubstubstubstubstubstubstubstubstu\\n' "$3"
        """), encoding="utf-8")
    stub.chmod(0o755)
    base = tmp_path / "docker"
    base.mkdir()

    def run(**extra):
        env = {"PATH": f"{stub_dir}:/usr/bin:/bin", "HOME": str(tmp_path),
               "PROMETHEUS_OTLP_SENDER_PASSWORD": SENDER,
               "PROMETHEUS_OTLP_GRAFANA_PASSWORD": GRAFANA,
               "PROMETHEUS_OTLP_SCRAPE_PASSWORD": SCRAPE}
        env.update(extra)
        return subprocess.run(["bash", str(RENDER), str(base)], env=env, text=True,
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    run.out = base / "prometheus-otlp"
    return run


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_render_refuses_to_write_a_readable_secret_when_unprivileged(render):
    if os.geteuid() == 0:
        pytest.skip("running as root: the unprivileged refusal cannot be exercised")
    proc = render()  # default owner uid is 65534, which is not us
    assert proc.returncode != 0
    assert "refusing" in proc.stderr
    assert not render.out.exists(), "nothing may be written before the privilege check"


def test_render_modes_are_private_and_secrets_stay_off_disk(render):
    proc = render(PROMETHEUS_FILE_UID=str(os.geteuid()))
    assert proc.returncode == 0, proc.stderr
    web, pw, secrets = (render.out / "web.yml",
                        render.out / "secrets" / "otlp-scrape-password",
                        render.out / "secrets")
    assert mode(web) == 0o400 and mode(pw) == 0o400
    assert mode(secrets) == 0o500
    for path in (web, pw, secrets):
        assert path.stat().st_uid == os.geteuid()
    # the scrape password must be plain (Prometheus sends it); the sender and
    # Grafana passwords are never written, and web.yml holds hashes only
    assert pw.read_text(encoding="utf-8") == SCRAPE
    on_disk = web.read_text(encoding="utf-8") + pw.read_text(encoding="utf-8")
    assert SENDER not in on_disk and GRAFANA not in on_disk
    assert SCRAPE not in web.read_text(encoding="utf-8")
    assert sorted(yaml.safe_load(web.read_text(encoding="utf-8"))["basic_auth_users"]) == \
        ["grafana", "scrape", "sender"]


def test_render_can_be_rerun(render):
    assert render(PROMETHEUS_FILE_UID=str(os.geteuid())).returncode == 0
    assert render(PROMETHEUS_FILE_UID=str(os.geteuid())).returncode == 0


def test_render_rejects_shared_or_placeholder_passwords(render):
    own = {"PROMETHEUS_FILE_UID": str(os.geteuid())}
    assert render(PROMETHEUS_OTLP_GRAFANA_PASSWORD=SENDER, **own).returncode != 0
    assert render(PROMETHEUS_OTLP_SCRAPE_PASSWORD="changeme", **own).returncode != 0
    assert not (render.out / "web.yml").exists()


def test_render_keeps_passwords_off_the_command_line():
    text = RENDER.read_text(encoding="utf-8")
    assert "htpasswd -niBC" in text
    assert "htpasswd -nb" not in text and "htpasswd -nBb" not in text


# --- docs ------------------------------------------------------------------------

def test_doc_has_required_sections_and_warning():
    text = DOC.read_text(encoding="utf-8")
    assert "authenticated and firewalled" in text
    for heading in ("## Firewall", "## Apply order", "## Verify", "## Rollback"):
        assert heading in text, f"missing {heading}"
    for needle in ("DOCKER-USER", "/api/v1/otlp/v1/metrics", "30 minute", "least privilege"):
        assert needle in text, needle


def test_doc_uses_placeholder_addresses_only():
    assert non_placeholder_ips(DOC.read_text(encoding="utf-8")) == []


def test_readme_links_doc_and_names_the_bind_variable():
    text = README.read_text(encoding="utf-8")
    assert "docs/prometheus-otlp.md" in text
    assert "PROMETHEUS_OTLP_BIND_ADDR" in text
