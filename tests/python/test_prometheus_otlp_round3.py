"""Third hardening round: renderer re-runs and rotation, script trust, stage
privacy, firewall rule ordering and validation. Ownership is simulated with
stub `id`, `stat` and `chown` programs, so the root-only paths run unprivileged;
the stubs change nothing about the files themselves."""
import json
import os
import re
import stat
import subprocess
import textwrap

import pytest

from test_prometheus_otlp import (  # noqa: F401  (fixtures are used by name)
    BASH, DOC, REPO_ROOT, RENDER, _doc, own, ready, render,
)

FIREWALL = REPO_ROOT / "scripts" / "prometheus-otlp-firewall.sh"
CLOSED = ("secrets", "tls", "otlp-ca", "web.yml", "self-scrape-password",
          "otlp-scrape-password", "server.key", "server.crt", "otlp-ca.crt")
ROOT_OWNED = ("scripts", "lib-secrets.sh", "render-prometheus-web-config.sh", "prom-render*")


def write_stub(directory, name, body):
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture()
def sim(ready, tmp_path):
    """Run the renderer as a simulated root with a per-name uid table."""
    stubs = tmp_path / "root-stubs"
    stubs.mkdir()
    write_stub(stubs, "id", textwrap.dedent("""\
        #!/usr/bin/env python3
        import os, sys
        print(0 if os.environ.get("STUB_ROOT") == "1" else os.getuid())
        """))
    write_stub(stubs, "chown", "#!/bin/sh\nexit 0\n")
    write_stub(stubs, "stat", textwrap.dedent("""\
        #!/usr/bin/env python3
        import json, os, sys
        args = sys.argv[1:]
        if len(args) >= 3 and args[0] == "-c" and args[1] == "%u":
            table = json.loads(os.environ.get("STUB_UIDS", "{}"))
            for path in args[2:]:
                name = os.path.basename(path.rstrip("/"))
                uid = None
                for key, value in table.items():
                    if key.endswith("*") and name.startswith(key[:-1]) or key == name:
                        uid = value
                print(uid if uid is not None else os.stat(path).st_uid)
            sys.exit(0)
        if len(args) >= 3 and args[0] == "-c" and args[1] == "%a":
            roots = json.loads(os.environ.get("STUB_UIDS", "{}"))
            for path in args[2:]:
                name = os.path.basename(path.rstrip("/"))
                fake = [k for k, v in roots.items() if v == 0 and not name.startswith("prom-render") and (k == name or k.endswith("*") and name.startswith(k[:-1]))]
                print("755" if fake else os.popen("/usr/bin/stat -c %a " + path).read().strip())
            sys.exit(0)
        os.execv("/usr/bin/stat", ["stat"] + args)
        """))
    stage_base = tmp_path / "stage-base"
    stage_base.mkdir()

    def run(uids=None, **extra):
        table = {name: 65534 for name in CLOSED}
        table.update({name: 0 for name in ROOT_OWNED})
        table.update(uids or {})
        env = {"PATH": f"{stubs}:{ready.stub_dir}:/usr/bin:/bin", "HOME": str(tmp_path),
               "STUB_ROOT": "1", "STUB_UIDS": json.dumps(table),
               "SUDO_UID": str(os.getuid()), "PROMETHEUS_STAGE_BASE": str(stage_base),
               **{k: v for k, v in __import__("test_prometheus_otlp").PASSWORDS.items()}}
        env.update(extra)
        return subprocess.run([BASH, str(RENDER), str(ready.main.parent)], env=env, text=True,
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    run.stage_base = stage_base
    run.ready = ready
    return run


def test_rerun_after_a_first_render_works(sim):
    first = sim()
    assert first.returncode == 0, first.stderr
    second = sim()  # directories are now closed and owned by the container user
    assert second.returncode == 0, second.stderr


def test_rerun_still_refuses_a_foreign_owner(sim):
    assert sim().returncode == 0
    proc = sim(uids={"secrets": 4242})
    assert proc.returncode != 0 and "not trusted" in proc.stderr


def test_rerun_still_refuses_symlinks(sim, tmp_path):
    assert sim().returncode == 0
    ca = sim.ready.main / "otlp-ca"
    ca.chmod(0o700)
    (ca / "otlp-ca.crt").unlink()
    (ca / "otlp-ca.crt").symlink_to(tmp_path / "elsewhere")
    proc = sim()
    assert proc.returncode != 0 and "symlink" in proc.stderr


def test_root_refuses_scripts_that_are_not_root_owned(sim):
    proc = sim(uids={"scripts": 1234, "lib-secrets.sh": 1234,
                     "render-prometheus-web-config.sh": 1234})
    assert proc.returncode != 0 and "root-owned" in proc.stderr
    assert not (sim.ready.main / "web.yml").exists()


def test_stage_ignores_the_callers_runtime_and_temp_dirs(sim, tmp_path):
    user_run, user_tmp = tmp_path / "xdg", tmp_path / "usertmp"
    user_run.mkdir()
    user_tmp.mkdir()
    proc = sim(XDG_RUNTIME_DIR=str(user_run), TMPDIR=str(user_tmp))
    assert proc.returncode == 0, proc.stderr
    assert list(user_run.iterdir()) == [] and list(user_tmp.iterdir()) == []
    text = RENDER.read_text(encoding="utf-8")
    assert "XDG_RUNTIME_DIR" not in text
    assert "|| mktemp -d" not in text


def test_root_path_uses_a_fixed_path_and_no_environment_passthrough_is_needed():
    text = RENDER.read_text(encoding="utf-8")
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in text
    assert "sudo -E" not in _doc()


# --- firewall script -----------------------------------------------------------------

@pytest.fixture()
def fw(tmp_path):
    stubs = tmp_path / "fw-stubs"
    stubs.mkdir()
    log, state = tmp_path / "ipt.log", tmp_path / "ipt.state"
    state.write_text("", encoding="utf-8")
    write_stub(stubs, "iptables", textwrap.dedent("""\
        #!/usr/bin/env python3
        import os, sys
        args = sys.argv[1:]
        with open(os.environ["IPT_LOG"], "a") as f:
            f.write(" ".join(args) + "\\n")
        state = open(os.environ["IPT_STATE"]).read()
        if args[:2] == ["-S", "DOCKER-USER"]:
            if os.environ.get("IPT_FAIL_S") == "1":
                sys.exit(1)
            sys.stdout.write(state)
        if args and args[0] == "-N":
            if ("-N " + args[1]) in state.split("\\n"):
                sys.exit(1)
        sys.exit(0)
        """))
    write_stub(stubs, "docker", textwrap.dedent("""\
        #!/usr/bin/env python3
        import os, sys
        sys.stdout.write(os.environ.get("DOCKER_PORT_OUT", ""))
        """))

    def run(*args, docker_out="127.0.0.1:9091\n", state="", **extra_env):
        state_path = tmp_path / "ipt.state"
        state_path.write_text(state, encoding="utf-8")
        log.write_text("", encoding="utf-8")
        env = {"PATH": f"{stubs}:/usr/bin:/bin", "IPT_LOG": str(log), "IPT_STATE": str(state_path),
               "IPTABLES": str(stubs / "iptables"), "DOCKER": str(stubs / "docker"),
               "DOCKER_PORT_OUT": docker_out, "PROM_FW_NO_SUDO": "1", **extra_env}
        proc = subprocess.run([BASH, str(FIREWALL), *args], env=env, text=True,
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
        proc.calls = [line for line in log.read_text(encoding="utf-8").splitlines() if line]
        return proc
    run.stubs = stubs
    run.log = log
    return run


GOOD = ("apply", "192.0.2.1", "192.0.2.10", "192.0.2.11")


def test_firewall_applies_rules_before_the_jump_and_never_flushes_a_live_chain(fw):
    proc = fw(*GOOD)
    assert proc.returncode == 0, proc.stderr
    calls = proc.calls
    jump = next(i for i, c in enumerate(calls) if c.startswith("-I DOCKER-USER"))
    drop = next(i for i, c in enumerate(calls) if c.endswith("-j DROP"))
    returns = [i for i, c in enumerate(calls) if "-j RETURN" in c]
    assert returns and max(returns) < drop < jump
    assert "--ctorigdst 192.0.2.1 --ctorigdstport 9091" in calls[jump]
    assert not any(c.startswith("-F") for c in calls)


def test_firewall_swaps_chains_so_there_is_never_a_window_without_rules(fw):
    old = "-N PROM-OTLP-A\n-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdst 192.0.2.1 --ctorigdstport 9091 -j PROM-OTLP-A\n"
    proc = fw(*GOOD, state=old)
    assert proc.returncode == 0, proc.stderr
    calls = proc.calls
    insert = next(i for i, c in enumerate(calls) if c.startswith("-I DOCKER-USER") and "PROM-OTLP-B" in c)
    delete = next(i for i, c in enumerate(calls) if c.startswith("-D DOCKER-USER") and "PROM-OTLP-A" in c)
    flush = next(i for i, c in enumerate(calls) if c == "-F PROM-OTLP-A")
    assert insert < delete < flush


@pytest.mark.parametrize("args", [
    ("apply", "0.0.0.0", "192.0.2.10"),
    ("apply", "not-an-address", "192.0.2.10"),
    ("apply", "192.0.2.1"),
    ("apply", "192.0.2.1", "192.0.2.300"),
    ("apply", "192.0.2.1", "any"),
], ids=["wildcard", "name", "no-senders", "bad-sender", "sender-any"])
def test_firewall_rejects_bad_arguments(fw, args):
    proc = fw(*args)
    assert proc.returncode != 0 and not any(c.startswith(("-N", "-I")) for c in proc.calls)


@pytest.mark.parametrize("out", ["", "127.0.0.1:9091\n127.0.0.1:9092\n", "[::]:9091\n", "0.0.0.0:abc\n"],
                         ids=["empty", "multi", "ipv6-only", "bad-port"])
def test_firewall_refuses_unusable_docker_port_output(fw, out):
    proc = fw(*GOOD, docker_out=out)
    assert proc.returncode != 0 and not any(c.startswith(("-N", "-I")) for c in proc.calls)


def test_firewall_refuses_an_ipv6_line_next_to_an_ipv4_line(fw):
    proc = fw(*GOOD, docker_out="[::]:9091\n127.0.0.1:9091\n")
    assert proc.returncode != 0 and not any(c.startswith(("-N", "-I")) for c in proc.calls)


def test_firewall_remove_derives_everything_from_the_live_rules(fw):
    state = "-N PROM-OTLP-B\n-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdst 192.0.2.1 --ctorigdstport 9091 -j PROM-OTLP-B\n"
    proc = fw("remove", state=state)
    assert proc.returncode == 0, proc.stderr
    calls = proc.calls
    assert any(c.startswith("-D DOCKER-USER") and "PROM-OTLP-B" in c for c in calls)
    assert calls.index("-F PROM-OTLP-B") < calls.index("-X PROM-OTLP-B")


# --- docs ---------------------------------------------------------------------------

def test_doc_uses_the_firewall_script_and_orders_rule_before_address():
    text = _doc()
    assert "prometheus-otlp-firewall.sh" in text
    assert "iptables -F PROM-OTLP-ALLOW" not in text
    order = text.split("## Apply order", 1)[1].split("## Verify", 1)[0]
    assert order.index("prometheus-otlp-firewall.sh") < order.index("PROMETHEUS_OTLP_BIND_ADDR")
    assert "remove" in text.split("## Rollback", 1)[1]


def test_doc_runs_the_renderer_from_a_root_owned_copy():
    text = _doc()
    assert "/usr/local/libexec" in text and "root-owned" in text


# --- firewall script: root trust, reply traffic, broad senders, failed reads -------

def test_firewall_rule_matches_only_the_original_direction(fw):
    proc = fw(*GOOD)
    assert proc.returncode == 0, proc.stderr
    jump = next(c for c in proc.calls if c.startswith("-I DOCKER-USER"))
    assert "--ctstate DNAT" in jump and "--ctdir ORIGINAL" in jump
    check = next(c for c in proc.calls if c.startswith("-C DOCKER-USER"))
    assert "--ctdir ORIGINAL" in check, "the verification must test the same rule"


def test_doc_says_netfilter_behavior_is_checked_at_apply_time():
    text = _doc()
    assert "original direction" in text or "original-direction" in text
    assert "verify step" in text.lower() or "[Verify](#verify)" in text


@pytest.mark.parametrize("sender", ["10.0.0.0/0", "192.0.2.10/0", "0.0.0.0/0"])
def test_firewall_refuses_prefix_zero_senders(fw, sender):
    proc = fw("apply", "192.0.2.1", sender)
    assert proc.returncode != 0 and not any(c.startswith(("-N", "-I")) for c in proc.calls)


def test_a_failed_rule_listing_changes_nothing(fw):
    proc = fw(*GOOD, IPT_FAIL_S="1")
    assert proc.returncode != 0
    assert not any(c.startswith(("-N", "-F", "-X", "-I", "-D", "-A")) for c in proc.calls)
    removal = fw("remove", IPT_FAIL_S="1")
    assert removal.returncode != 0
    assert not any(c.startswith(("-F", "-X", "-D")) for c in removal.calls)


@pytest.fixture()
def fw_root(fw, tmp_path):
    """The firewall script as real uid 0 inside a user namespace (`unshare -r`, no real
    privilege: the caller's own files appear root-owned), with hostile stubs for id,
    stat, iptables and docker first in PATH and the test overrides set. The calls
    that reach the stubs are logged in fw.log; a hostile `id` or `stat` also touches
    a marker file."""
    probe = subprocess.run(["unshare", "-r", "true"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        pytest.skip("unprivileged user namespaces are not available")
    stubs = tmp_path / "fw-root-stubs"
    stubs.mkdir()
    marker = tmp_path / "hostile-program-ran"
    for name in ("id", "stat", "dirname"):
        write_stub(stubs, name, f"#!/bin/sh\ntouch {marker}\nprintf 1000\n")
    copy_dir = tmp_path / "root-copy"
    copy_dir.mkdir()
    copy_dir.chmod(0o755)

    def run(mode="755", *args, env_extra=None):
        script = copy_dir / "prometheus-otlp-firewall.sh"
        script.write_bytes(FIREWALL.read_bytes())
        script.chmod(int(mode, 8))
        env = {"PATH": f"{stubs}:{fw.stubs}:/usr/bin:/bin", "IPT_LOG": str(fw.log),
               "IPT_STATE": str(tmp_path / "ipt.state"), "PROM_FW_NO_SUDO": "1",
               "IPTABLES": str(fw.stubs / "iptables"), "DOCKER": str(fw.stubs / "docker"),
               **(env_extra or {})}
        fw.log.write_text("", encoding="utf-8")
        proc = subprocess.run(["unshare", "-r", BASH, str(script), *(args or GOOD)], env=env,
                              text=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
        proc.calls = [x for x in fw.log.read_text(encoding="utf-8").splitlines() if x]
        proc.marker = marker
        return proc
    return run


def test_firewall_root_refuses_a_group_writable_script(fw_root):
    proc = fw_root("775")
    assert proc.returncode != 0 and "root-owned" in proc.stderr


def test_firewall_root_runs_no_program_from_the_callers_path(fw_root):
    # A bad bind address stops the script after the root checks and before any
    # iptables or docker call, so nothing real is touched.
    proc = fw_root("755", "apply", "0.0.0.0", "192.0.2.10")
    assert "0.0.0.0" in proc.stderr and "root-owned" not in proc.stderr
    assert not proc.marker.exists(), "a program from the caller's PATH ran as root"


def test_firewall_root_ignores_the_iptables_and_docker_overrides(fw_root):
    proc = fw_root("755", "remove")  # trusted script: it must not call the override programs
    assert "run as root" not in proc.stderr and "root-owned" not in proc.stderr
    assert proc.calls == [], "the override stubs must not be used as root"
    assert not proc.marker.exists()


@pytest.mark.parametrize("fake", ["1234", "0", "", "abc"])
def test_a_caller_supplied_euid_cannot_move_a_real_root_off_the_root_path(fw_root, fake):
    # Bash imports EUID from the environment; the decision must come from the kernel.
    proc = fw_root("755", "remove", env_extra={"EUID": fake})
    assert "run as root" not in proc.stderr
    assert proc.calls == [], "an override program ran as root"
    assert not proc.marker.exists()
    refused = fw_root("775", env_extra={"EUID": fake})
    assert refused.returncode != 0 and "root-owned" in refused.stderr


def test_euid_zero_from_the_environment_does_not_make_a_normal_user_root(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "EUID": "0", "UID": "0"}
    proc = subprocess.run([BASH, str(FIREWALL), "remove"], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=tmp_path)
    assert proc.returncode != 0 and "run as root" in proc.stderr


def test_firewall_decides_root_from_the_kernel_after_resetting_path():
    text = FIREWALL.read_text(encoding="utf-8")
    code = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    first = next(i for i, ln in enumerate(code) if ln.startswith("PATH="))
    assert "EUID" not in "\n".join(code), "the root decision must not read EUID"
    assert first < next(i for i, ln in enumerate(code) if '"$ID_BIN" -u' in ln)


def test_firewall_resets_path_for_real_root():
    text = FIREWALL.read_text(encoding="utf-8")
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in text


def test_doc_tells_the_maintainer_to_run_a_root_owned_firewall_copy():
    text = _doc()
    assert "/usr/local/libexec/siem/prometheus-otlp-firewall.sh" in text
