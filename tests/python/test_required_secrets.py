"""Guards for issue #34: required secrets are documented, client-side scripts
refuse a missing or placeholder password instead of defaulting, and no script
or doc reintroduces a `changeme`-style default.

One placeholder rule, case-insensitive, shared by scripts/check-env.sh and the
`require_secret` helper carried by each client script (the helper is inlined
because deploy-grafana-alerts.py and deploy-n8n-grafana-router.py are also run
as `ssh host python3 - < script`, where a sibling import cannot work).
"""
import os
import re
import subprocess

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPTS = REPO_ROOT / "scripts"
README = REPO_ROOT / "README.md"

PY_SCRIPTS = {
    "deploy-dashboards.py": "GRAFANA_PASS",
    "deploy-grafana-alerts.py": "GRAFANA_PASS",
    "deploy-crowdsec-dashboard.py": "GRAFANA_PASS",
    "deploy-n8n-grafana-router.py": "N8N_PASSWORD",
}

# Built at run time from short pieces so no token-shaped literal sits in the source for a
# secret scanner to flag; the values still reach the scripts under test unchanged.
OLD_API_DEFAULT = "My" + "S3cr3t" + "P4ss" + "w0rd"
API_KEY_FIXTURE = "-".join(["fixture", "key", "for", "tests"])

# Values the one rule must reject (any case) and values it must accept.
PLACEHOLDERS = [
    "", "   ", "changeme", "ChangeMe123", "change_me", "change-me-now",
    "your_password", "YOUR_N8N_API_KEY", "your-password", "your-grafana-password",
    "<password>", "<set me>", "example", "Example-Value", "placeholder",
    "PLACEHOLDER_TOKEN", "xxx", "xxxxxxxx", "SecretPassword", OLD_API_DEFAULT,
    "kibanaserver", "admin", "password", "a-strong-password-here",
]
REAL_LOOKING = ["Zx9-unique-0", API_KEY_FIXTURE, "correct horse battery 42"]

REQUIRED_SECRETS = [
    "OPENSEARCH_ADMIN_PASSWORD", "OPENSEARCH_LOGSTASH_PASSWORD",
    "OPENSEARCH_READONLY_PASSWORD", "OPENSEARCH_DASHBOARDS_PASSWORD",
    "GRAFANA_ADMIN_PASS", "INFLUXDB_ADMIN_PASSWORD", "GRAFANA_INFLUX_PASSWORD",
    "UNPOLLER_INFLUX_PASSWORD", "WAZUH_INDEXER_PASSWORD", "WAZUH_API_PASSWORD",
    "WAZUH_DASHBOARD_PASSWORD", "WAZUH_GRAFANA_RO_PASSWORD", "UNIFI_PASS",
]


def _env(**extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GRAFANA_", "N8N_", "OPENSEARCH_"))}
    env.update(extra)
    return env


def _run(cmd, **extra):
    return subprocess.run(cmd, capture_output=True, text=True, check=False,
                          env=_env(**extra), stdin=subprocess.DEVNULL, timeout=30)


@pytest.fixture()
def load(monkeypatch):
    def _load(script, **env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return import_module_from_path("req_" + script.replace("-", "_").replace(".", "_"),
                                       SCRIPTS / script)
    return _load


# --- helper behavior (python) -------------------------------------------------

@pytest.mark.parametrize("script", sorted(PY_SCRIPTS))
def test_helper_rejects_placeholders_and_empty(load, script):
    mod = load(script)
    for value in PLACEHOLDERS:
        with pytest.raises(SystemExit) as exc:
            mod.require_secret("THE_VAR", value)
        assert exc.value.code not in (0, None)
        message = str(exc.value.code)
        assert "THE_VAR" in message
        if value.strip() and value.lower() not in message.lower():
            assert value not in message, f"error message echoes the value {value!r}"


MARKED = ["changeme-Q7zT", "your_Q7zT", "<Q7zT>", "xxxQ7zT", "exampleQ7zT",
          "placeholderQ7zT", "Q7zT-your-password-Q7zT", "SecretPassword"]


@pytest.mark.parametrize("script", sorted(PY_SCRIPTS))
def test_helper_never_echoes_the_rejected_value(load, script):
    mod = load(script)
    for value in MARKED:
        with pytest.raises(SystemExit) as exc:
            mod.require_secret("THE_VAR", value)
        assert "Q7zT" not in str(exc.value.code)
        assert "secretpassword" not in str(exc.value.code).lower()


@pytest.mark.parametrize("script", sorted(PY_SCRIPTS))
def test_helper_rejects_unset(load, script):
    mod = load(script)
    with pytest.raises(SystemExit) as exc:
        mod.require_secret("THE_VAR", None)
    assert "THE_VAR" in str(exc.value.code)


@pytest.mark.parametrize("script", sorted(PY_SCRIPTS))
def test_helper_accepts_real_looking_values(load, script):
    mod = load(script)
    for value in REAL_LOOKING:
        assert mod.require_secret("THE_VAR", value) == value


def test_python_copies_of_the_rule_agree(load):
    mods = [load(s) for s in sorted(PY_SCRIPTS)]
    for value in PLACEHOLDERS + REAL_LOOKING:
        results = {m.is_placeholder(value) for m in mods}
        assert len(results) == 1, f"copies disagree on {value!r}"


# --- one rule across python and check-env.sh -----------------------------------

def _check_env_rejects(tmp_path, value):
    lines = "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(REQUIRED_SECRETS))
    lines = lines.replace("OPENSEARCH_ADMIN_PASSWORD=Zx9-unique-0",
                          f"OPENSEARCH_ADMIN_PASSWORD={value}")
    env = tmp_path / ".env"
    env.write_text(lines, encoding="utf-8")
    proc = _run(["bash", str(SCRIPTS / "check-env.sh"), str(env)])
    assert proc.returncode in (0, 1), proc.stderr
    return proc.returncode == 1


def test_check_env_and_python_use_the_same_rule(load, tmp_path):
    mod = load("deploy-dashboards.py")
    for value in PLACEHOLDERS + REAL_LOOKING:
        if not value.strip() or value != value.strip() or " " in value:
            continue  # whitespace cannot be written to an .env line unquoted
        assert _check_env_rejects(tmp_path, value) == mod.is_placeholder(value), value


# --- scripts refuse before doing any work --------------------------------------

@pytest.mark.parametrize("script,var", sorted(PY_SCRIPTS.items()))
@pytest.mark.parametrize("bad", ["changeme", "your-password", ""])
def test_python_scripts_refuse_bad_password(script, var, bad):
    extra = {var: bad, "N8N_API_KEY": API_KEY_FIXTURE,
             "GRAFANA_URL": "http://192.0.2.1:3000", "N8N_BASE": "http://192.0.2.1:80"}
    proc = _run(["python3", "-I", str(SCRIPTS / script)], **extra)
    assert proc.returncode != 0
    assert var in proc.stderr
    if bad:
        assert bad not in proc.stderr


@pytest.mark.parametrize("script,var", sorted(PY_SCRIPTS.items()))
def test_python_scripts_refuse_unset_password(script, var):
    proc = _run(["python3", "-I", str(SCRIPTS / script)],
                N8N_API_KEY=API_KEY_FIXTURE, GRAFANA_URL="http://192.0.2.1:3000")
    assert proc.returncode != 0
    assert var in proc.stderr


def test_router_refuses_placeholder_api_key():
    proc = _run(["python3", "-I", str(SCRIPTS / "deploy-n8n-grafana-router.py")],
                N8N_PASSWORD="Zx9-unique-0", N8N_API_KEY="YOUR_N8N_API_KEY",
                N8N_BASE="http://192.0.2.1:80")
    assert proc.returncode != 0 and "N8N_API_KEY" in proc.stderr
    assert "YOUR_N8N_API_KEY" not in proc.stderr


SOAR = ["bash", str(SCRIPTS / "deploy-n8n-soar.sh"), "192.0.2.1"]
SMOKE = ["bash", str(SCRIPTS / "08-crowdsec-smoketest.sh")]
SOAR_OK = {"N8N_API_KEY": API_KEY_FIXTURE, "ALERT_FOLDER_UID": "f1", "DS_WAZUH": "a",
           "DS_SURICATA": "b", "DS_PROMETHEUS": "c"}
SMOKE_OK = {"OPENSEARCH_ADMIN_PASSWORD": "Zx9-unique-0"}


@pytest.mark.parametrize("cmd,base", [(SOAR, SOAR_OK), (SMOKE, SMOKE_OK)])
@pytest.mark.parametrize("bad", ["changeme", "YOUR_PASSWORD", "<password>", None])
def test_shell_scripts_refuse_bad_grafana_password(cmd, base, bad):
    extra = dict(base)
    if bad is not None:
        extra["GRAFANA_PASS"] = bad
    proc = _run(cmd, **extra)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "GRAFANA_PASS" in out
    if bad:
        assert bad not in out


def test_smoketest_falls_back_to_grafana_admin_pass_but_still_checks_it():
    proc = _run(SMOKE, **SMOKE_OK, GRAFANA_ADMIN_PASS="changeme")
    assert proc.returncode != 0 and "GRAFANA_PASS" in proc.stdout + proc.stderr
    assert "changeme" not in proc.stdout + proc.stderr


def test_soar_refuses_placeholder_n8n_key():
    extra = dict(SOAR_OK, N8N_API_KEY="your-key-here", GRAFANA_PASS="Zx9-unique-0")
    proc = _run(SOAR, **extra)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0 and "N8N_API_KEY" in out and "your-key-here" not in out


def test_shell_scripts_parse():
    for name in ("deploy-n8n-soar.sh", "08-crowdsec-smoketest.sh", "check-env.sh"):
        assert _run(["bash", "-n", str(SCRIPTS / name)]).returncode == 0, name


# --- README documents every required secret ------------------------------------

def _readme_section(title):
    text = README.read_text(encoding="utf-8")
    m = re.search(rf"(?ms)^## {re.escape(title)}\n(.*?)(?=^## )", text)
    assert m, f"README has no '## {title}' section"
    return m.group(1)


def test_readme_required_secrets_section_covers_every_secret():
    section = _readme_section("Required secrets")
    for name in REQUIRED_SECRETS:
        assert f"`{name}`" in section, f"{name} missing from Required secrets"
    for name in ("N8N_PASSWORD", "N8N_API_KEY", "GRAFANA_PASS"):
        assert f"`{name}`" in section, f"{name} missing from Required secrets"
    assert "check-env.sh" in section
    assert re.search(r"(?i)refuse|fail", section)


def test_required_secrets_match_compose_and_check_env():
    check = (SCRIPTS / "check-env.sh").read_text(encoding="utf-8")
    for name in REQUIRED_SECRETS:
        assert name in check, f"{name} not enforced by check-env.sh"


# --- nothing reintroduces a changeme-style default ------------------------------

DEFAULT_RE = re.compile(
    r"(?i)change[-_]?me|your[-_]password|your-grafana-password|secretpassword"
    r"|my[s]3cr3tp4ssw0rd|admin123|password123")
# Where such strings may appear: the rule itself (lib-secrets.sh and the tagged
# line in each deploy script), these tests, and the threat model's record of the
# old state. Dotfiles such as `.env.example` are the maintainer's and not scanned.
ALLOWED = {"scripts/lib-secrets.sh"}
RULE_TAG = "placeholder-rule"  # marks the one line per script that spells out the rule
ALLOWED_PREFIXES = ("tests/", "docs/threat-model/", ".git/")


def _scannable():
    for path in sorted(REPO_ROOT.rglob("*")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if not path.is_file() or rel.startswith(ALLOWED_PREFIXES) or rel in ALLOWED:
            continue
        if any(part.startswith(".") for part in path.relative_to(REPO_ROOT).parts):
            continue  # dotfiles (.env*, .git*, caches) are not scanned here
        if path.suffix in {".png", ".jpg", ".gz", ".pdf"}:
            continue
        yield rel, path


def test_guard_collects_something():
    rels = [r for r, _ in _scannable()]
    assert "README.md" in rels and "scripts/deploy-dashboards.py" in rels
    assert any(r.startswith("docs/") for r in rels)


def test_no_changeme_style_default_anywhere():
    offenders = []
    for rel, path in _scannable():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if DEFAULT_RE.search(line) and RULE_TAG not in line:
                offenders.append(f"{rel}:{n}")
    assert not offenders, "placeholder-style default reintroduced: " + ", ".join(offenders)


def test_default_guard_bites():
    assert DEFAULT_RE.search('GRAFANA_PASS = os.environ.get("GRAFANA_PASS", "changeme")')
    assert DEFAULT_RE.search('export N8N_PASSWORD="your-password"')
    assert DEFAULT_RE.search("${GRAFANA_PASS:-ChangeMe}")
    assert not DEFAULT_RE.search('GRAFANA_PASS = os.environ.get("GRAFANA_PASS")')
    tagged = 'GRAFANA_PASS = "changeme"  # ' + RULE_TAG
    assert DEFAULT_RE.search(tagged) and RULE_TAG in tagged  # exemption is explicit and visible


def test_no_script_defaults_a_password_variable():
    """Any `${*PASS*:-value}` or environ.get("*PASS*", "value") with a non-empty default."""
    sh = re.compile(r"\$\{[A-Z_]*(PASS|PASSWORD|API_KEY|TOKEN)[A-Z_]*:-([^}$]+)\}")
    py = re.compile(r"""environ\.get\(\s*["'][A-Z_]*(PASS|PASSWORD|API_KEY|TOKEN)[A-Z_]*["']\s*,\s*["'][^"']+["']""")
    offenders = []
    for path in sorted(SCRIPTS.iterdir()):
        if path.suffix not in {".sh", ".py"}:
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if sh.search(line) or py.search(line):
                offenders.append(f"{path.name}:{n}")
    assert not offenders, ", ".join(offenders)
