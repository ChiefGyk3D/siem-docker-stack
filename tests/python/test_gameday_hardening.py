"""Fix round 1 for scripts/gameday.py (issue #84): the Daybreak review findings.

The /etc/hosts scripts run under the local sh against a temp file standing in
for /etc/hosts. The one redirect test uses two throwaway loopback servers.
"""
import http.server
import json
import os
import stat
import subprocess
import threading

import pytest

from conftest import REPO_ROOT
from test_gameday import ENV, Fakes, go, gd

RID = "abcdef0123456789"
LINE = gd.hosts_line("discord.com", RID)
ORIGINAL = "127.0.0.1 localhost\n::1 localhost\n10.0.0.5 other # gameday-84\n"


def sh(script, env=None):
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, env=env)


@pytest.fixture
def hosts(tmp_path):
    f = tmp_path / "hosts"
    f.write_text(ORIGINAL)
    return f


# ---- 1. hosts scripts --------------------------------------------------------

def test_hosts_scenarios_use_a_run_unique_exact_line_and_no_shared_tmp():
    _, out, _ = go(["discord-unreachable", "--run-id", RID])
    assert f"# gameday-84-{RID}" in out
    assert "/tmp" not in out and "mktemp" not in out and "sed -i" not in out


def test_hosts_add_then_remove_restores_the_exact_original(hosts):
    assert sh(gd.hosts_add_script(LINE, str(hosts))).returncode == 0
    assert LINE in hosts.read_text()
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_text() == ORIGINAL


def test_hosts_remove_takes_only_this_runs_exact_line_all_copies(hosts):
    other = gd.hosts_line("discord.com", "00000000ffffffff")
    hosts.write_text(ORIGINAL + LINE + "\n" + other + "\n" + LINE + "\n")
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_text() == ORIGINAL + other + "\n"  # another run's line and the old marker stay


def test_hosts_remove_ignores_a_decoy_symlink_next_to_it(hosts, tmp_path):
    (tmp_path / ".gameday-hosts").symlink_to(hosts)
    sh(gd.hosts_add_script(LINE, str(hosts)))
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_text() == ORIGINAL


def test_hosts_scripts_refuse_a_symlinked_hosts_file(hosts, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(hosts)
    for script in (gd.hosts_add_script(LINE, str(link)), gd.hosts_remove_script(LINE, str(link))):
        assert sh(script).returncode != 0
    assert hosts.read_text() == ORIGINAL


def test_hosts_remove_fails_loudly_when_grep_fails_and_changes_nothing(hosts, tmp_path):
    hosts.write_text(ORIGINAL + LINE + "\n")
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "grep").write_text("#!/bin/sh\nexit 2\n")
    (stub / "grep").chmod(0o755)
    r = sh(gd.hosts_remove_script(LINE, str(hosts)), env={"PATH": f"{stub}:/usr/bin:/bin"})
    assert r.returncode != 0
    assert hosts.read_text() == ORIGINAL + LINE + "\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_hosts_remove_fails_loudly_when_the_write_fails(hosts):
    hosts.write_text(ORIGINAL + LINE + "\n")
    hosts.chmod(0o444)
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode != 0


def test_hosts_remove_missing_file_fails_and_absent_line_is_a_noop(hosts, tmp_path):
    assert sh(gd.hosts_remove_script(LINE, str(tmp_path / "nope"))).returncode != 0
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode == 0
    assert hosts.read_text() == ORIGINAL


def test_hosts_remove_refuses_to_leave_an_empty_file(hosts):
    hosts.write_text(LINE + "\n")
    assert sh(gd.hosts_remove_script(LINE, str(hosts))).returncode != 0
    assert hosts.read_text() == LINE + "\n"


def test_hosts_revert_needs_the_run_id_to_apply():
    rc, out, fakes = go(["discord-unreachable", "--revert", "--apply", "--confirm-live"])
    assert rc == 2 and "--run-id" in out and fakes.commands == []
    rc, out, fakes = go(["discord-unreachable", "--revert", "--apply", "--confirm-live", "--run-id", RID])
    assert rc == 0 and RID in " ".join(fakes.commands[0])


def test_inject_prints_the_revert_command_with_the_run_id():
    _, out, _ = go(["discord-unreachable", "--apply", "--confirm-live", "--run-id", RID])
    assert f"--run-id {RID}" in out


@pytest.mark.parametrize("bad", ["x", "ABC", "abcdef01; reboot", "../../x", "a" * 40])
def test_bad_run_id_is_rejected(bad):
    rc, _, fakes = go(["discord-unreachable", "--apply", "--confirm-live", "--run-id", bad])
    assert rc == 2 and fakes.commands == []


# ---- 2. exceptions never skip the revert ---------------------------------------

class Raiser(Fakes):
    def __init__(self, first, second=None):
        super().__init__()
        self.first, self.second = first, second

    def run(self, argv):
        self.commands.append(argv)
        exc = self.first if len(self.commands) == 1 else self.second
        if exc:
            raise exc
        return 0, ""


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), subprocess.TimeoutExpired("docker", 1), RuntimeError("x")])
def test_exception_during_injection_still_runs_the_revert_then_reraises(exc):
    fakes = Raiser(exc)
    with pytest.raises(type(exc)):
        go(["n8n-down", "--apply", "--confirm-live"], fakes=fakes)
    assert fakes.commands == [["docker", "stop", "n8n"], ["docker", "start", "n8n"]]


def test_revert_failure_cannot_mask_the_original_exception():
    fakes = Raiser(KeyboardInterrupt(), RuntimeError("revert broke"))
    with pytest.raises(KeyboardInterrupt):
        go(["n8n-down", "--apply", "--confirm-live"], fakes=fakes)
    assert len(fakes.commands) == 2


def test_exception_in_revert_mode_is_reraised():
    fakes = Raiser(RuntimeError("x"))
    with pytest.raises(RuntimeError):
        go(["n8n-down", "--revert", "--apply", "--confirm-live"], fakes=fakes)
    assert fakes.commands == [["docker", "start", "n8n"]]


def test_resolver_exception_propagates_and_the_log_is_still_written(tmp_path):
    fakes = Fakes()
    fakes.resolve = lambda cfg: (_ for _ in ()).throw(RuntimeError("no docker"))
    log = tmp_path / "g.jsonl"
    with pytest.raises(RuntimeError):
        go(["wrong-header", "--apply", "--confirm-live", "--log", str(log)], fakes=fakes)
    assert json.loads(log.read_text())["ok"] is False


# ---- 3. wrong-header base validation and redirects ------------------------------

@pytest.mark.parametrize("base", [
    "http://169.254.169.254", "http://user:pw@10.0.0.1", "ftp://10.0.0.1", "http://example.com",
    "http://8.8.8.8", "http://10.0.0.1/x", "http://10.0.0.1/?a=1", "http://0.0.0.0", "http://10.0.0.1#f",
])
def test_bad_n8n_base_is_refused_and_nothing_is_posted(base):
    rc, _, fakes = go(["wrong-header", "--apply", "--confirm-live"], env={**ENV, "GAMEDAY_N8N_BASE": base})
    assert fakes.posts == [] and rc != 0


@pytest.mark.parametrize("base", ["http://192.0.2.10:80", "http://127.0.0.1:5678", "https://10.1.2.3",
                                  "http://10.1.2.3/"])
def test_good_n8n_bases_are_accepted(base):
    assert gd.validate_base(base)


def test_resolver_output_is_validated_too():
    fakes = Fakes()
    fakes.resolve = lambda cfg: "http://169.254.169.254"
    env = {k: v for k, v in ENV.items() if k != "GAMEDAY_N8N_BASE"}
    rc, _, fakes = go(["wrong-header", "--apply", "--confirm-live"], env=env, fakes=fakes)
    assert fakes.posts == [] and rc != 0


class Srv:
    def __init__(self, handler):
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


def test_real_poster_does_not_follow_redirects_or_forward_authorization():
    seen = []

    class Target(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *a):
            pass

    target = Srv(Target)

    class Redirect(Target):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", target.url + "/x")
            self.end_headers()

    redirector = Srv(Redirect)
    try:
        status = gd.real_poster(redirector.url + "/webhook/p", {"Authorization": "Bearer gameday-wrong-value"}, "{}")
    finally:
        redirector.close()
        target.close()
    assert status == 302 and seen == []  # urllib would re-send a 302 POST as a GET with the headers


# ---- 4. argparse abbreviations ----------------------------------------------------

@pytest.mark.parametrize("args", [["--app", "--confirm-live"], ["--apply", "--conf"], ["--app", "--conf"],
                                  ["--apply", "--confirm"], ["--re", "--apply", "--confirm-live"]])
def test_abbreviated_options_are_rejected_and_nothing_runs(args):
    rc, _, fakes = go(["n8n-down", *args])
    assert rc == 2 and fakes.commands == []


# ---- 5. --log hardening --------------------------------------------------------------

def test_log_through_a_symlink_is_refused_but_the_scenario_result_stands(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep\n")
    link = tmp_path / "g.jsonl"
    link.symlink_to(target)
    rc, out, fakes = go(["n8n-down", "--apply", "--confirm-live", "--log", str(link)])
    assert rc == 0 and target.read_text() == "keep\n"
    assert "not written" in out.lower()
    assert fakes.commands == [["docker", "stop", "n8n"]]


def test_log_to_a_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    rc, out, _ = go(["n8n-down", "--apply", "--confirm-live", "--log", str(fifo)])
    assert rc == 0 and "not written" in out.lower()


def test_log_to_a_device_file_is_refused():
    rc, out, _ = go(["n8n-down", "--apply", "--confirm-live", "--log", "/dev/null"])
    assert rc == 0 and "not a regular file" in out


def test_log_is_created_private_and_appended(tmp_path):
    old = os.umask(0)
    try:
        log = tmp_path / "g.jsonl"
        go(["n8n-down", "--apply", "--confirm-live", "--log", str(log)])
        go(["n8n-down", "--apply", "--confirm-live", "--log", str(log)])
    finally:
        os.umask(old)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    assert len(log.read_text().splitlines()) == 2


def test_log_failure_does_not_block_the_auto_revert(tmp_path):
    bad = str(tmp_path / "no" / "dir" / "x")
    rc, _, fakes = go(["n8n-down", "--apply", "--confirm-live", "--log", bad], fakes=Fakes(rc=1))
    assert rc == 1 and len(fakes.commands) == 2


# ---- 6. container CLI allowlist -------------------------------------------------------

@pytest.mark.parametrize("exe", ["docker", "podman"])
def test_cli_allowlist_accepts_docker_and_podman(exe):
    assert gd.load_config({"GAMEDAY_DOCKER": exe})["docker"] == exe


@pytest.mark.parametrize("exe", ["/tmp/attacker-program", "sh", "docker; x", "./docker"])
def test_cli_allowlist_rejects_anything_else(exe):
    with pytest.raises(gd.GamedayError):
        gd.load_config({"GAMEDAY_DOCKER": exe})
    rc, _, fakes = go(["n8n-down", "--apply", "--confirm-live"], env={**ENV, "GAMEDAY_DOCKER": exe})
    assert rc == 2 and fakes.commands == []
