"""Second hardening round for the Prometheus OTLP receiver: trusted ownership
for the root-run renderer, a deploy preflight that passes after a correct
render, an accurate disk-bound story, verified internal TLS, and a firewall
port that comes from the running container. Test values are built at run time
so no secret-shaped literal sits in the source."""
import os
import pathlib
import re
import stat
import subprocess

import pytest

from test_prometheus_otlp import (  # noqa: F401  (fixtures are used by name)
    BASH, DEPLOY, MAIN_PROM_YML, REPO_ROOT, RENDER, RULES, _doc, _services, _yaml,
    bind_mount, own, ready, render,
)

SUDO_STUB = "#!/bin/sh\nexec \"$@\"\n"
PREFLIGHT = re.compile(r'run_on_server "((?:sudo )?test -f[^"\n]*PROM_AUTH_OK[^"\n]*)"')


def script():
    return RENDER.read_text(encoding="utf-8")


def preflight_command(base):
    m = PREFLIGHT.search(DEPLOY.read_text(encoding="utf-8"))
    assert m, "preflight command not found in 03-deploy.sh"
    return m.group(1).replace("${DEPLOY_DIR}", str(base))


def run_preflight(base, tmp_path):
    sudo_dir = tmp_path / "sudo-bin"
    sudo_dir.mkdir(exist_ok=True)
    (sudo_dir / "sudo").write_text(SUDO_STUB, encoding="utf-8")
    (sudo_dir / "sudo").chmod(0o755)
    return subprocess.run([BASH, "-c", preflight_command(base)],
                          env={"PATH": f"{sudo_dir}:/usr/bin:/bin"}, text=True,
                          capture_output=True, timeout=30)


# --- renderer trust ----------------------------------------------------------------

def test_render_refuses_a_tree_it_does_not_trust(render):
    if os.geteuid() == 0:
        pytest.skip("root trusts root-owned trees; this refusal is for other owners")
    proc = render(at="/usr", **own())  # root-owned, so untrusted for an unprivileged caller
    assert proc.returncode != 0 and "owned by" in proc.stderr
    assert not pathlib.Path("/usr/prometheus").exists()


def test_render_stages_outside_the_target_tree():
    text = script()
    assert 'mktemp -d "${MAIN_DIR}' not in text and 'mktemp -d "${TARGET_BASE}' not in text
    assert "STAGE_ROOT" in text


def test_render_verifies_ownership_after_placing_files():
    assert "verify_owner" in script()


def test_render_rejects_values_compose_would_parse_differently(ready):
    for part in ("with space", "back" + chr(92) + "slash", "line" + chr(13) + "break", "in" + chr(39) + "quote"):
        value = "-".join(["Zx9", part])
        assert ready(PROMETHEUS_SELF_PASSWORD=value, **own()).returncode != 0, repr(part)


def test_render_no_longer_sends_passwords_to_a_registry_image():
    text = script()
    assert "docker run" not in text and "htpasswd" in text


# --- deploy preflight --------------------------------------------------------------

def test_preflight_uses_sudo_for_every_check():
    cmd = preflight_command("/x")
    assert cmd.count("test -f") >= 5
    assert cmd.count("sudo test -f") == cmd.count("test -f")


def test_preflight_passes_after_a_correct_render(ready, tmp_path):
    assert ready(**own()).returncode == 0
    out = run_preflight(ready.main.parent, tmp_path)
    assert "PROM_AUTH_OK" in out.stdout, out.stderr


def test_preflight_fails_when_a_file_is_missing(ready, tmp_path):
    assert ready(**own()).returncode == 0
    secrets = ready.main / "secrets"
    secrets.chmod(0o700)
    (secrets / "self-scrape-password").unlink()
    out = run_preflight(ready.main.parent, tmp_path)
    assert "PROM_AUTH_OK" not in out.stdout


# --- disk bound --------------------------------------------------------------------

def test_receiver_has_a_memory_limit_and_a_storage_alert():
    svc = _services()["prometheus-otlp"]
    assert "PROMETHEUS_OTLP_MEM_LIMIT" in str(svc.get("mem_limit", ""))
    alerts = {r["alert"]: r for p in RULES for g in _yaml(p)["groups"]
              for r in g["rules"] if "alert" in r}
    assert "OtlpReceiverStorageHigh" in alerts
    assert 'job="prometheus-otlp"' in alerts["OtlpReceiverStorageHigh"]["expr"]


def test_doc_describes_the_disk_bound_accurately():
    text = _doc()
    overclaim = "a misbehaving sender must not be able to fill the disk"
    assert overclaim not in text
    assert "not a hard" in text and "quota" in text


# --- internal TLS ------------------------------------------------------------------

def test_scrape_verifies_the_receiver_certificate():
    data = _yaml(MAIN_PROM_YML)
    job = [j for j in data["scrape_configs"] if j["job_name"] == "prometheus-otlp"][0]
    tls = job["tls_config"]
    assert "insecure_skip_verify" not in tls
    assert tls["ca_file"] == "/etc/prometheus/otlp-ca/otlp-ca.crt"
    assert tls["server_name"] == "prometheus-otlp"
    mount = bind_mount(_services()["prometheus"], "/etc/prometheus/otlp-ca")
    assert mount["source"] == "./prometheus/otlp-ca"


def test_doc_covers_san_expiry_and_the_grafana_limit():
    text = _doc()
    assert "DNS:prometheus-otlp" in text
    assert "does not verify" in text and "Grafana" in text
    assert "openssl x509" in text and "-enddate" in text


# --- port source -------------------------------------------------------------------

def test_doc_reads_the_port_from_the_running_container_not_the_shell():
    text = _doc()
    assert "docker port prometheus-otlp" in text
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        assert "OTLP_PORT=${PROMETHEUS_OTLP_PORT" not in block, block[:60]
    assert "prometheus-otlp-firewall.sh" in text
    fw = (REPO_ROOT / "scripts" / "prometheus-otlp-firewall.sh").read_text(encoding="utf-8")
    assert "--ctorigdst" in fw and '"$IPT" -C' in fw
    assert ":127.0.0.1" not in text.split("## Verify", 1)[1].split("## Rollback", 1)[0]


def test_doc_does_not_overclaim_atomicity():
    assert "leaves the previous set untouched" not in _doc()


# --- the private key reaches only the receiver ---------------------------------------

KEY_DIR = "prometheus-otlp/tls"


def key_exposed_to(services):
    """Services other than the receiver whose relative bind mounts can see the TLS
    key: the tls directory, the receiver directory, the stack root or the key file."""
    exposed = []
    for name, svc in services.items():
        if name == "prometheus-otlp":
            continue
        for vol in svc.get("volumes", []):
            src = vol["source"] if isinstance(vol, dict) else str(vol).split(":")[0]
            if os.path.isabs(src):
                continue  # host paths (such as cadvisor's read-only host root) are outside this check
            norm = os.path.normpath(src)
            if norm in (".", "prometheus-otlp") or norm.startswith(KEY_DIR):
                exposed.append((name, src))
    return exposed


def test_key_guard_bites():
    bad = {"a": {"volumes": ["./prometheus-otlp/tls:/x:ro"]},
           "b": {"volumes": [{"type": "bind", "source": "./prometheus-otlp", "target": "/y"}]},
           "c": {"volumes": ["./prometheus-otlp/tls/server.key:/k:ro"]},
           "ok": {"volumes": ["./prometheus/otlp-ca:/ca:ro"]},
           "prometheus-otlp": {"volumes": ["./prometheus-otlp/tls/server.key:/k"]}}
    assert sorted(n for n, _ in key_exposed_to(bad)) == ["a", "b", "c"]


def test_no_service_but_the_receiver_can_see_the_tls_key():
    services = _services()
    assert "prometheus-otlp" in services and len(services) > 3, "nothing collected"
    assert key_exposed_to(services) == []


def test_verifiers_get_only_a_certificate_directory_without_the_key():
    main = bind_mount(_services()["prometheus"], "/etc/prometheus/otlp-ca")
    assert main["source"] == "./prometheus/otlp-ca"


def test_render_publishes_the_certificate_for_verifiers_without_the_key(ready):
    assert ready(**own()).returncode == 0
    ca = ready.main / "otlp-ca"
    assert sorted(f.name for f in ca.iterdir()) == ["otlp-ca.crt"]
    assert (ca / "otlp-ca.crt").read_bytes() == (ready.out / "tls" / "server.crt").read_bytes()
    assert stat.S_IMODE((ca / "otlp-ca.crt").stat().st_mode) == 0o444
    assert stat.S_IMODE(ca.stat().st_mode) == 0o555


def test_deploy_protects_and_checks_the_certificate_copy():
    text = DEPLOY.read_text(encoding="utf-8")
    assert "prometheus/otlp-ca" in text
    assert "sudo test -f ${DEPLOY_DIR}/prometheus/otlp-ca/otlp-ca.crt" in text
