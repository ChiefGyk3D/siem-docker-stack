"""The OpenSearch security init script never puts a credential in an argument or an environment.

A stub engine (standing in for the container engine) records its argument list, its environment and
its standard input for every call. The script runs against it with a sentinel secret in each of the
four passwords. The sentinel must reach the engine on standard input only: never in any recorded
argument list, and never in a recorded environment. A password with a line break is refused before
any engine call.
"""
import os
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPTS = REPO_ROOT / "scripts"
SCRIPT = "08b-init-opensearch-security.sh"
SECURITY_SRC = REPO_ROOT / "docker" / "opensearch" / "security"

SENTINEL = "S3ntinel-Pw-9f2c"  # recognizable, no shell or curl-config special characters
PASS_VARS = ["OPENSEARCH_ADMIN_PASSWORD", "OPENSEARCH_LOGSTASH_PASSWORD",
             "OPENSEARCH_READONLY_PASSWORD", "OPENSEARCH_DASHBOARDS_PASSWORD"]

# Records one block per call under $REC: argv (one word per line), env, stdin. Answers like the engine
# would: the probe (no credentials) 200, hashing a bcrypt-looking line, an authenticated curl 200 and
# an unauthenticated one 401. Credentials are recognized wherever they might travel (-u, -K, -e).
STUB = r"""#!/bin/sh
n=$(ls "$REC" | wc -l)
n=$((n + 1))
d="$REC/call-$n"
mkdir "$d"
for a in "$@"; do printf '%s\n' "$a"; done > "$d/argv"
/usr/bin/env > "$d/env"
cat > "$d/stdin"
case " $* " in
    *hash.sh*) echo '$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345' ;;
    *" curl "*)
        case " $* " in
            *" -u "* | *" -K "*) printf 200 ;;
            *"/_cluster/health"*) printf 401 ;;
            *) printf 200 ;;
        esac
        ;;
esac
exit 0
"""


def make_sandbox(tmp_path, script_text=None):
    """A copy of the script and helper whose ce_init picks the stub engine; returns (script, rec dir)."""
    box = tmp_path / "box"
    scripts = box / "scripts"
    scripts.mkdir(parents=True)
    scripts.chmod(0o755)
    rec = tmp_path / "rec"
    rec.mkdir()
    stub = tmp_path / "engine-stub"
    # ce_run starts the engine with an empty environment, so the record directory is written into the stub
    stub.write_text("#!/bin/sh\nREC='" + str(rec) + "'\n" + STUB.split("\n", 1)[1], encoding="utf-8")
    stub.chmod(0o755)
    text = script_text if script_text is not None else (SCRIPTS / SCRIPT).read_text(encoding="utf-8")
    (scripts / SCRIPT).write_text(text, encoding="utf-8")
    (scripts / SCRIPT).chmod(0o755)
    lib = (SCRIPTS / "lib-container-engine.sh").read_text(encoding="utf-8")
    lib += f"\nce_init() {{ CE_NAME=docker; CE_BIN='{stub}'; }}\n"
    (scripts / "lib-container-engine.sh").write_text(lib, encoding="utf-8")
    (scripts / "lib-container-engine.sh").chmod(0o644)
    deploy = box / "deploy"
    sec = deploy / "opensearch" / "security"
    sec.mkdir(parents=True)
    (sec / "internal_users.yml.template").write_text(
        (SECURITY_SRC / "internal_users.yml.template").read_text(encoding="utf-8"), encoding="utf-8")
    return scripts / SCRIPT, rec, deploy


def run_script(script, deploy, rec, passwords=None):
    env = {"PATH": "/usr/bin:/bin", "REC": str(rec), "SIEM_DEPLOY_DIR": str(deploy), "HOME": str(rec.parent)}
    for var in PASS_VARS:
        env[var] = (passwords or {}).get(var, SENTINEL)
    return subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, timeout=120)


def calls(rec):
    out = []
    for d in sorted(rec.iterdir(), key=lambda p: int(p.name.split("-")[1])):
        out.append({k: (d / k).read_text(encoding="utf-8", errors="replace") for k in ("argv", "env", "stdin")})
    return out


def test_sentinel_never_in_argv_or_environment(tmp_path):
    script, rec, deploy = make_sandbox(tmp_path)
    proc = run_script(script, deploy, rec)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    recorded = calls(rec)
    assert len(recorded) >= 7  # one probe, four hashes, securityadmin, two verify calls
    for c in recorded:
        assert SENTINEL not in c["argv"], f"secret in an argument list:\n{c['argv']}"
        assert SENTINEL not in c["env"], "secret in an environment"
    assert SENTINEL not in proc.stdout + proc.stderr


def test_sentinel_reaches_the_engine_on_stdin(tmp_path):
    """The fix moves the secret, it does not drop it: hashing and the admin check both get it on stdin."""
    script, rec, deploy = make_sandbox(tmp_path)
    assert run_script(script, deploy, rec).returncode == 0
    with_secret = [c for c in calls(rec) if SENTINEL in c["stdin"]]
    assert len(with_secret) == 5  # four hash calls and the admin check
    admin = [c for c in with_secret if "-K\n-\n" in c["argv"]]
    assert len(admin) == 1
    assert admin[0]["stdin"] == f'user = "admin:{SENTINEL}"\n'


def test_distinct_secrets_do_not_cross_into_argv(tmp_path):
    script, rec, deploy = make_sandbox(tmp_path)
    secrets = {v: f"Zq{i}-unique-{v[11:15]}" for i, v in enumerate(PASS_VARS)}
    assert run_script(script, deploy, rec, secrets).returncode == 0
    for c in calls(rec):
        for s in secrets.values():
            assert s not in c["argv"]
            assert s not in c["env"]


@pytest.mark.parametrize("hostile", [
    'pa"ss\\word',                # quote and backslash, escaped in the curl config
    "pw$(touch /nonexistent)`id`",  # shell metacharacters
    "pw -o /etc/x",               # looks like options
])
def test_hostile_password_stays_one_config_line(tmp_path, hostile):
    script, rec, deploy = make_sandbox(tmp_path)
    proc = run_script(script, deploy, rec, {"OPENSEARCH_ADMIN_PASSWORD": hostile})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    admin = [c for c in calls(rec) if "-K\n-\n" in c["argv"]]
    assert len(admin) == 1
    stdin = admin[0]["stdin"]
    assert stdin.count("\n") == 1 and stdin.startswith('user = "admin:') and stdin.endswith('"\n')
    escaped = hostile.replace("\\", "\\\\").replace('"', '\\"')
    assert stdin == f'user = "admin:{escaped}"\n'
    for c in calls(rec):
        assert hostile not in c["argv"] and hostile not in c["env"]


@pytest.mark.parametrize("var", PASS_VARS)
@pytest.mark.parametrize("bad", ['pw\noutput = /tmp/owned', "pw\rx"])
def test_line_break_in_a_password_is_refused_before_any_engine_call(tmp_path, var, bad):
    script, rec, deploy = make_sandbox(tmp_path)
    proc = run_script(script, deploy, rec, {var: bad})
    assert proc.returncode != 0
    assert var in proc.stderr
    assert "/tmp/owned" not in proc.stdout + proc.stderr
    assert list(rec.iterdir()) == []
