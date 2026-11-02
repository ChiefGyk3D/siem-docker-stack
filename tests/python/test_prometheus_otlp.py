"""Guards for the Prometheus OTLP receiver (issue #331 in the maintainer's
tracker): a separate, authenticated instance so pushed series never share a
database with the SIEM alert rules, separate accounts, private file modes,
loopback by default, and docs with the firewall step, verification and
rollback using placeholder addresses only."""
import os
import re
import shutil
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
MAIN_WEB_EXAMPLE = REPO_ROOT / "docker" / "prometheus" / "web.yml.example"
RULES = sorted((REPO_ROOT / "docker" / "prometheus" / "rules").glob("*.yml"))
DOC = REPO_ROOT / "docs" / "prometheus-otlp.md"
README = REPO_ROOT / "README.md"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
DATASOURCES = (REPO_ROOT / "docker" / "grafana" / "provisioning" / "datasources"
               / "datasources.yml")
BASH = shutil.which("bash")
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


def bind_mount(svc, target):
    """The long-form bind mount for `target` (short-form strings are rejected)."""
    found = [v for v in svc["volumes"] if isinstance(v, dict) and v.get("target") == target]
    assert len(found) == 1, f"no long-form mount for {target}"
    assert found[0]["bind"]["create_host_path"] is False, target
    assert found[0]["read_only"] is True, target
    return found[0]


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


def test_main_prometheus_has_no_receiver_and_requires_auth():
    main = _services()["prometheus"]
    assert OTLP_FLAG not in main["command"]
    assert "--web.config.file=/etc/prometheus/web.yml" in main["command"]
    assert main["ports"] == ["${BIND_ADDR:-127.0.0.1}:${PROMETHEUS_PORT:-9090}:9090"]
    assert bind_mount(main, "/etc/prometheus/web.yml")["source"] == "./prometheus/web.yml"
    assert bind_mount(main, "/etc/prometheus/secrets")["source"] == "./prometheus/secrets"


def unauthenticated_lifecycle(services):
    """Services that expose the lifecycle or admin API without a web config."""
    return sorted(
        n for n, s in services.items()
        if any(c.startswith(("--web.enable-lifecycle", "--web.enable-admin-api"))
               for c in s.get("command", []))
        and not any(c.startswith("--web.config.file=") for c in s["command"]))


def test_lifecycle_guard_bites():
    bad = {"p": {"command": ["--web.enable-lifecycle"]}}
    good = {"p": {"command": ["--web.enable-lifecycle", "--web.config.file=/w.yml"]}}
    assert unauthenticated_lifecycle(bad) == ["p"]
    assert unauthenticated_lifecycle(good) == []
    assert unauthenticated_lifecycle(
        {"p": {"command": ["--web.enable-admin-api"]}}) == ["p"]


def test_no_service_has_lifecycle_without_authentication():
    services = _services()
    assert any("--web.enable-lifecycle" in s.get("command", []) for s in services.values()), \
        "nothing collected: expected the SIEM Prometheus to enable lifecycle"
    assert unauthenticated_lifecycle(services) == []


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
    assert bind_mount(svc, "/etc/prometheus/web.yml")["source"] == "./prometheus-otlp/web.yml"
    # disk bound for pushed data on the shared hot tier
    assert any(c.startswith("--storage.tsdb.retention.size=") for c in cmd)
    # TLS in front of the credentials
    assert bind_mount(svc, "/etc/prometheus/tls")["source"] == "./prometheus-otlp/tls"


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
    assert job["scheme"] == "https"
    assert "storage" not in data and "otlp" not in data
    own = [j for j in data["scrape_configs"] if j["job_name"] == "prometheus"][0]
    assert own["basic_auth"]["username"] == "self"
    assert own["basic_auth"]["password_file"] == "/etc/prometheus/secrets/self-scrape-password"


def test_grafana_reads_the_receiver_with_its_own_account():
    sources = {d["uid"]: d for d in _yaml(DATASOURCES)["datasources"]}
    ds = sources["prometheus-otlp"]
    assert ds["url"] == "https://prometheus-otlp:9090"
    assert ds["basicAuth"] is True and ds["basicAuthUser"] == "grafana"
    assert ds["secureJsonData"]["basicAuthPassword"] == "$PROMETHEUS_OTLP_GRAFANA_PASSWORD"
    # the SIEM Prometheus authenticates too, with its own account
    siem = sources["prometheus"]
    assert siem["basicAuth"] is True and siem["basicAuthUser"] == "grafana"
    assert siem["secureJsonData"]["basicAuthPassword"] == "$PROMETHEUS_GRAFANA_PASSWORD"
    env = _services()["grafana"]["environment"]
    for var in ("PROMETHEUS_OTLP_GRAFANA_PASSWORD", "PROMETHEUS_GRAFANA_PASSWORD"):
        line = [e for e in env if e.startswith(var + "=")]
        assert line and ":?" in line[0], var


def test_otlp_web_config_example_enables_tls():
    tls = _yaml(WEB_EXAMPLE)["tls_server_config"]
    assert tls["cert_file"] == "/etc/prometheus/tls/server.crt"
    assert tls["key_file"] == "/etc/prometheus/tls/server.key"
    assert tls["min_version"] == "TLS12"


def test_web_config_examples_have_separate_accounts():
    assert sorted(_yaml(WEB_EXAMPLE)["basic_auth_users"]) == ["grafana", "scrape", "sender"]
    assert sorted(_yaml(MAIN_WEB_EXAMPLE)["basic_auth_users"]) == ["grafana", "self"]


def test_rendered_files_are_ignored_by_git():
    ignore = GITIGNORE.read_text(encoding="utf-8")
    for path in ("docker/prometheus-otlp/web.yml", "docker/prometheus/web.yml",
                 "docker/prometheus/secrets/"):
        assert path in ignore


def test_env_example_lists_the_accounts_and_loopback_default():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    for name in ("PROMETHEUS_OTLP_SENDER_PASSWORD", "PROMETHEUS_OTLP_GRAFANA_PASSWORD",
                 "PROMETHEUS_OTLP_SCRAPE_PASSWORD", "PROMETHEUS_GRAFANA_PASSWORD",
                 "PROMETHEUS_SELF_PASSWORD", "PROMETHEUS_OTLP_BIND_ADDR"):
        assert name in text


# --- render script: private modes, separate secrets ----------------------------

# Built at run time from short pieces so no token-shaped literal sits in the
# source for a secret scanner to flag; the values still reach the script unchanged.
PASSWORD_VARS = ("PROMETHEUS_OTLP_SENDER_PASSWORD", "PROMETHEUS_OTLP_GRAFANA_PASSWORD",
                 "PROMETHEUS_OTLP_SCRAPE_PASSWORD", "PROMETHEUS_GRAFANA_PASSWORD",
                 "PROMETHEUS_SELF_PASSWORD")
PASSWORDS = {name: "-".join(["Zx9", "unique", str(i)]) for i, name in enumerate(PASSWORD_VARS)}


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
        printf '%s:$2y$12$stubstubstubstubstubstubstubstubstubstubstubstubstubs\\n' "$3"
        """), encoding="utf-8")
    stub.chmod(0o755)
    base = tmp_path / "docker"
    base.mkdir()

    def run(**extra):
        env = {"PATH": f"{stub_dir}:/usr/bin:/bin", "HOME": str(tmp_path), **PASSWORDS}
        env.update(extra)
        return subprocess.run([BASH, str(RENDER), str(base)], env=env, text=True,
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    run.out = base / "prometheus-otlp"
    run.main = base / "prometheus"
    run.stub_dir = stub_dir
    yield run
    # the script leaves the secrets directory 0500; reopen it so pytest can clean up
    secrets = run.main / "secrets"
    if secrets.exists():
        secrets.chmod(0o700)


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_render_refuses_to_write_a_readable_secret_when_unprivileged(render):
    if os.geteuid() == 0:
        pytest.skip("running as root: the unprivileged refusal cannot be exercised")
    proc = render()  # default owner uid is 65534, which is not us
    assert proc.returncode != 0
    assert "refusing" in proc.stderr
    assert not render.out.exists() and not render.main.exists(), \
        "nothing may be written before the privilege check"


def test_render_modes_are_private_and_secrets_stay_off_disk(ready):
    proc = ready(PROMETHEUS_FILE_UID=str(os.geteuid()))
    assert proc.returncode == 0, proc.stderr
    secrets = ready.main / "secrets"
    web_main, web_otlp = ready.main / "web.yml", ready.out / "web.yml"
    plain = {secrets / "self-scrape-password": PASSWORDS["PROMETHEUS_SELF_PASSWORD"],
             secrets / "otlp-scrape-password": PASSWORDS["PROMETHEUS_OTLP_SCRAPE_PASSWORD"]}
    for path in (web_main, web_otlp, *plain):
        assert mode(path) == 0o400, path
        assert path.stat().st_uid == os.geteuid()
    assert mode(secrets) == 0o500 and secrets.stat().st_uid == os.geteuid()
    for path, value in plain.items():
        assert path.read_text(encoding="utf-8") == value
    # only the two scrape passwords are written in plain text; the rest never
    # reach disk, and the web configs hold hashes only
    written = "".join(p.read_text(encoding="utf-8") for p in (web_main, web_otlp, *plain))
    for name in ("PROMETHEUS_OTLP_SENDER_PASSWORD", "PROMETHEUS_OTLP_GRAFANA_PASSWORD",
                 "PROMETHEUS_GRAFANA_PASSWORD"):
        assert PASSWORDS[name] not in written, name
    for path in (web_main, web_otlp):
        text = path.read_text(encoding="utf-8")
        assert not any(v in text for v in PASSWORDS.values())
    assert sorted(yaml.safe_load(web_main.read_text(encoding="utf-8"))["basic_auth_users"]) == \
        ["grafana", "self"]
    assert sorted(yaml.safe_load(web_otlp.read_text(encoding="utf-8"))["basic_auth_users"]) == \
        ["grafana", "scrape", "sender"]


def test_render_can_be_rerun(ready):
    assert ready(PROMETHEUS_FILE_UID=str(os.geteuid())).returncode == 0
    assert ready(PROMETHEUS_FILE_UID=str(os.geteuid())).returncode == 0


def test_render_rejects_shared_or_placeholder_passwords(ready):
    own = {"PROMETHEUS_FILE_UID": str(os.geteuid())}
    shared = ready(PROMETHEUS_OTLP_GRAFANA_PASSWORD=PASSWORDS["PROMETHEUS_OTLP_SENDER_PASSWORD"], **own)
    assert shared.returncode != 0
    assert ready(PROMETHEUS_SELF_PASSWORD="changeme", **own).returncode != 0
    assert not (ready.out / "web.yml").exists()


def tls_files(base):
    tls = base / "prometheus-otlp" / "tls"
    tls.mkdir(parents=True, exist_ok=True)
    for d in (tls.parent, tls):
        d.chmod(0o755)  # the script refuses group-writable directories
    (tls / "server.crt").write_text("cert", encoding="utf-8")
    (tls / "server.key").write_text("key", encoding="utf-8")
    return tls


def own():
    return {"PROMETHEUS_FILE_UID": str(os.geteuid())}


def test_render_requires_tls_files_and_makes_them_private(render):
    base = render.main.parent
    missing = render(**own())
    assert missing.returncode != 0 and "tls" in missing.stderr.lower()
    assert not (render.out / "web.yml").exists()
    tls = tls_files(base)
    assert render(**own()).returncode == 0
    assert mode(tls / "server.key") == 0o400 and mode(tls) == 0o500
    text = (render.out / "web.yml").read_text(encoding="utf-8")
    cfg = yaml.safe_load(text)
    assert cfg["tls_server_config"]["cert_file"] == "/etc/prometheus/tls/server.crt"
    tls.chmod(0o700)


@pytest.fixture()
def ready(render):
    tls = tls_files(render.main.parent)
    yield render
    for d in (tls, render.main / "secrets"):
        if d.exists():
            d.chmod(0o700)


def test_render_keeps_last_good_files_when_hashing_fails(ready):
    assert ready(**own()).returncode == 0
    before = (ready.out / "web.yml").read_bytes() if os.access(ready.out / "web.yml", os.R_OK) else None
    assert before is not None
    # an htpasswd that fails must not leave empty hashes or remove the old set
    failing = ready.stub_dir.parent / "bin-fail"
    failing.mkdir(exist_ok=True)
    (failing / "htpasswd").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (failing / "htpasswd").chmod(0o755)
    bad = ready(PATH=f"{failing}:/usr/bin:/bin", **own())
    assert bad.returncode != 0, "must fail when hashing fails"
    assert (ready.out / "web.yml").read_bytes() == before
    assert (ready.main / "web.yml").exists()
    for f in (ready.main / "web.yml", ready.out / "web.yml"):
        assert "basic_auth_users" in f.read_text(encoding="utf-8")


def test_render_rejects_malformed_hash_output(ready, tmp_path):
    broken = tmp_path / "bin2"
    broken.mkdir()
    (broken / "htpasswd").write_text("#!/bin/sh\ncat >/dev/null\nprintf '%s:\\n' \"$3\"\n", encoding="utf-8")
    (broken / "htpasswd").chmod(0o755)
    proc = ready(PATH=f"{broken}:/usr/bin:/bin", **own())
    assert proc.returncode != 0
    assert not (ready.out / "web.yml").exists()


def test_render_rejects_secrets_that_bcrypt_would_truncate_or_envs_would_mangle(ready):
    long_a = "A" * 72 + "x"
    assert ready(PROMETHEUS_SELF_PASSWORD=long_a, **own()).returncode != 0
    assert ready(PROMETHEUS_SELF_PASSWORD="Zx9-has-$-dollar", **own()).returncode != 0
    assert ready(PROMETHEUS_SELF_PASSWORD="A" * 72, **own()).returncode == 0


def test_render_reads_quoted_env_values_like_check_env(ready, tmp_path):
    env_file = ready.main.parent / ".env"
    env_file.write_text('PROMETHEUS_SELF_PASSWORD="Zx9-quoted-self"\n', encoding="utf-8")
    env = {k: v for k, v in PASSWORDS.items() if k != "PROMETHEUS_SELF_PASSWORD"}
    proc = subprocess.run([BASH, str(RENDER), str(ready.main.parent)],
                          env={"PATH": ready_path(ready), "HOME": str(tmp_path), **env, **own()},
                          text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert (ready.main / "secrets" / "self-scrape-password").read_text(encoding="utf-8") == "Zx9-quoted-self"


def ready_path(render):
    return f"{render.stub_dir}:/usr/bin:/bin"


def test_render_ignores_the_uid_override_when_root():
    text = RENDER.read_text(encoding="utf-8")
    assert re.search(r'id -u\)" -eq 0 \].*\n?.*OWNER_UID=65534|OWNER_UID=65534\s*# root', text), \
        "root must not honour PROMETHEUS_FILE_UID"


def test_render_refuses_symlinked_directories(ready, tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    ready.main.mkdir(parents=True, exist_ok=True)
    ready.main.chmod(0o755)
    (ready.main / "secrets").symlink_to(victim)
    proc = ready(**own())
    assert proc.returncode != 0 and "symlink" in proc.stderr
    assert list(victim.iterdir()) == []


def test_render_refuses_symlinked_files(ready, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    ready.main.mkdir(parents=True, exist_ok=True)
    ready.main.chmod(0o755)
    (ready.main / "web.yml").symlink_to(victim)
    proc = ready(**own())
    assert proc.returncode != 0 and "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "keep"


def test_render_refuses_a_world_writable_target_directory(ready):
    ready.main.mkdir(parents=True, exist_ok=True)
    ready.main.chmod(0o777)
    proc = ready(**own())
    ready.main.chmod(0o755)
    assert proc.returncode != 0 and "writable" in proc.stderr


def test_render_replaces_a_directory_stub_left_by_docker(ready):
    ready.main.mkdir(parents=True, exist_ok=True)
    ready.main.chmod(0o755)
    (ready.main / "web.yml").mkdir()
    assert ready(**own()).returncode == 0
    assert (ready.main / "web.yml").is_file()


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


# --- alert rules are scoped to their scrape job -----------------------------------

JOB_MATCHER = re.compile(r"\bjob\s*(=~|=)\s*\"")


def unscoped_alerts(rule_files):
    bad = []
    for path in rule_files:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for rule in group["rules"]:
                if "alert" in rule and not JOB_MATCHER.search(rule["expr"]):
                    bad.append(rule["alert"])
    return bad


def test_scope_guard_bites(tmp_path):
    f = tmp_path / "r.yml"
    f.write_text("groups:\n- name: g\n  rules:\n  - alert: A\n    expr: foo > 1\n"
                 "  - alert: B\n    expr: foo{job=\"x\"} > 1\n", encoding="utf-8")
    assert unscoped_alerts([f]) == ["A"]


def test_every_alert_rule_selects_a_scrape_job():
    assert RULES, "no rule files collected"
    assert unscoped_alerts(RULES) == []


def test_rule_comment_does_not_claim_a_label_proves_origin():
    text = "\n".join(p.read_text(encoding="utf-8") for p in RULES)
    assert "NOT proof of origin" in text


# --- examples carry no hash-shaped literal -----------------------------------------

BCRYPT = re.compile(r"\$2[aby]\$\d{2}\$")


def test_bcrypt_guard_bites():
    assert BCRYPT.search("x: $2y$12$abcdefghijklmnopqrstuv")
    assert not BCRYPT.search("x: REPLACE_WITH_BCRYPT_HASH")


def test_web_config_examples_hold_placeholders_not_hashes():
    examples = [WEB_EXAMPLE, MAIN_WEB_EXAMPLE]
    for path in examples:
        text = path.read_text(encoding="utf-8")
        assert not BCRYPT.search(text), path
        users = yaml.safe_load(text)["basic_auth_users"]
        assert users and set(users.values()) == {"REPLACE_WITH_BCRYPT_HASH"}, path


# --- deploy keeps the rendered files ---------------------------------------------

DEPLOY = REPO_ROOT / "scripts" / "03-deploy.sh"
RENDERED = ("prometheus/web.yml", "prometheus/secrets/self-scrape-password",
            "prometheus-otlp/web.yml", "prometheus-otlp/tls/server.key")


def deploy_filters():
    return re.findall(r"--filter='(P [^']+)'", DEPLOY.read_text(encoding="utf-8"))


def run_rsync_delete(tmp_path, filters):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    for rel in RENDERED:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        (dst / rel).write_text("kept", encoding="utf-8")
        (dst / rel).chmod(0o400)
    (src / "prometheus").mkdir()
    (src / "prometheus" / "prometheus.yml").write_text("x", encoding="utf-8")
    cmd = ["rsync", "-a", "--delete"] + [f"--filter={f}" for f in filters] + [f"{src}/", f"{dst}/"]
    subprocess.run(cmd, check=True, capture_output=True, timeout=30)
    return dst


def test_deploy_guard_bites_without_the_filters(tmp_path):
    dst = run_rsync_delete(tmp_path, [])
    assert not (dst / "prometheus-otlp" / "web.yml").exists()


def test_deploy_keeps_rendered_credentials_and_tls_files(tmp_path):
    filters = deploy_filters()
    assert filters, "no rsync filters collected from 03-deploy.sh"
    dst = run_rsync_delete(tmp_path, filters)
    for rel in RENDERED:
        assert (dst / rel).read_text(encoding="utf-8") == "kept", rel
        assert mode(dst / rel) == 0o400


def test_deploy_preflights_the_rendered_files():
    text = DEPLOY.read_text(encoding="utf-8")
    for rel in ("prometheus/web.yml", "prometheus-otlp/web.yml",
                "prometheus/secrets/self-scrape-password"):
        assert re.search(rf"test -f [^\n]*{re.escape(rel)}", text), rel


# --- docs say what is true ---------------------------------------------------------

def _doc():
    return DOC.read_text(encoding="utf-8")


def test_doc_states_accounts_have_identical_web_access_and_why_no_proxy():
    text = _doc()
    assert "identical web access" in text
    assert "full read and write" in text
    assert "firewall" in text.split("identical web access", 1)[1]


def test_doc_firewall_and_verify_commands_use_the_resolved_port():
    text = _doc()
    assert "OTLP_PORT=" in text
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        if "iptables" in block or "SIEM_HOST" in block or "127.0.0.1" in block:
            assert "9091" not in block.replace("PROMETHEUS_OTLP_PORT:-9091", ""), block[:80]


def test_doc_uses_https_for_senders_and_verification():
    text = _doc()
    assert "http://SIEM_HOST:9091" not in text and "http://127.0.0.1:9091" not in text
    assert "--cacert" in text and "https://" in text
    assert "tls_server_config" in text or "server.crt" in text


def test_doc_notes_ip_scope_dollar_alphabet_and_disk_bound():
    text = _doc()
    assert "IPv4" in text and "nftables" in text
    assert "`$`" in text
    assert "retention.size" in text or "PROMETHEUS_OTLP_RETENTION_SIZE" in text


def test_env_example_has_disk_bound_and_tls_notes():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    assert "PROMETHEUS_OTLP_RETENTION_SIZE" in text
