"""Tests for scripts/gameday.py: game-day failure scenarios (issue #84).

The container runtime and the HTTP call are faked; nothing here touches a live
system. Guards covered: dry-run default, --apply gating, --confirm-live,
revert printing, input validation, config precedence, failure auto-revert.
"""
import io
import json

import pytest

from conftest import REPO_ROOT, import_module_from_path

gd = import_module_from_path("gameday", REPO_ROOT / "scripts" / "gameday.py")

ENV = {
    "GAMEDAY_HEARTBEAT_HOST": "observer.example.com",
    "GAMEDAY_ROUTER_WORKFLOW_ID": "AbC123",
    "GAMEDAY_ROUTER_PATH": "private-path-1",
    "GAMEDAY_N8N_BASE": "http://192.0.2.10:80",
}


class Fakes:
    def __init__(self, rc=0, status=401):
        self.commands, self.posts, self.rc, self.status = [], [], rc, status

    def run(self, argv):
        self.commands.append(argv)
        return self.rc, "boom" if self.rc else ""

    def post(self, url, headers, body):
        self.posts.append((url, headers, body))
        return self.status

    def resolve(self, cfg):
        return cfg.get("n8n_base") or "http://192.0.2.99:80"


def go(args, env=None, fakes=None):
    fakes = fakes or Fakes()
    out = io.StringIO()
    rc = gd.execute(args, env=dict(ENV if env is None else env), run=fakes.run, post=fakes.post,
                    resolve=fakes.resolve, out=out)
    return rc, out.getvalue(), fakes


# ---- collection is loose, assertions strict -------------------------------

def test_every_listed_scenario_exists_and_is_collected():
    assert len(gd.SCENARIO_NAMES) >= 5
    cfg = gd.load_config(dict(ENV))
    for name in gd.SCENARIO_NAMES:
        sc = gd.get_scenario(cfg, name)
        assert sc.name == name and sc.observe


@pytest.mark.parametrize("name", gd.SCENARIO_NAMES)
def test_dry_run_default_prints_plan_and_runs_nothing(name):
    rc, out, fakes = go([name])
    assert rc == 0
    assert fakes.commands == [] and fakes.posts == []
    assert "DRY-RUN: nothing was changed" in out
    for word in ("WOULD DO", "OBSERVE:", "REVERT"):
        assert word in out


# ---- apply gating ---------------------------------------------------------

@pytest.mark.parametrize("name", gd.SCENARIO_NAMES)
def test_apply_without_confirm_live_is_refused(name):
    rc, out, fakes = go([name, "--apply"])
    assert rc == 2
    assert "REFUSED" in out and "--confirm-live" in out
    assert fakes.commands == [] and fakes.posts == []


def test_confirm_live_alone_is_still_a_dry_run():
    rc, out, fakes = go(["n8n-down", "--confirm-live"])
    assert rc == 0 and fakes.commands == [] and "DRY-RUN" in out


def test_apply_with_confirm_live_runs_through_the_runner():
    rc, out, fakes = go(["n8n-down", "--apply", "--confirm-live"])
    assert rc == 0
    assert fakes.commands == [["docker", "stop", "n8n"]]
    assert "gameday.py n8n-down --revert --apply --confirm-live" in out


def test_revert_apply_runs_only_the_revert_steps():
    rc, out, fakes = go(["n8n-down", "--revert", "--apply", "--confirm-live"])
    assert rc == 0 and fakes.commands == [["docker", "start", "n8n"]]


def test_revert_dry_run_prints_revert_and_runs_nothing():
    rc, out, fakes = go(["n8n-down", "--revert"])
    assert rc == 0 and fakes.commands == []
    assert "revert only" in out and "docker start n8n" in out


# ---- revert printing ------------------------------------------------------

@pytest.mark.parametrize("name", [n for n in gd.SCENARIO_NAMES if n != "wrong-header"])
def test_every_changing_scenario_prints_a_concrete_revert_command(name):
    _, out, _ = go([name])
    revert = out.split("\nREVERT:")[1].split("DRY-RUN")[0]
    assert "$ docker" in revert


def test_hosts_scenarios_revert_removes_only_the_marked_line():
    _, out, _ = go(["discord-unreachable"])
    assert "grep -v '\\''# gameday-84'\\''" in out
    assert "sed -i" not in out  # /etc/hosts is a bind mount; sed -i would fail


def test_wrong_header_says_nothing_to_revert():
    _, out, _ = go(["wrong-header"])
    assert "REVERT: none needed" in out


# ---- failure handling -----------------------------------------------------

def test_failed_step_triggers_automatic_revert_and_nonzero_exit():
    fakes = Fakes(rc=1)
    rc, out, fakes = go(["discord-unreachable", "--apply", "--confirm-live"], fakes=fakes)
    assert rc == 1
    assert "Running the revert steps now" in out
    assert len(fakes.commands) == 2  # the inject, then the revert


def test_failed_revert_tells_the_operator_to_do_it_by_hand():
    rc, out, _ = go(["n8n-down", "--apply", "--confirm-live"], fakes=Fakes(rc=1))
    assert rc == 1 and "REVERT FAILED" in out


# ---- wrong-header ---------------------------------------------------------

def test_wrong_header_posts_a_made_up_value_and_expects_rejection():
    rc, out, fakes = go(["wrong-header", "--apply", "--confirm-live"])
    assert rc == 0
    (url, headers, _), = fakes.posts
    assert url == "http://192.0.2.10:80/webhook/private-path-1"
    assert headers == {"Authorization": "Bearer gameday-wrong-value"}


def test_wrong_header_open_webhook_is_a_failure():
    rc, out, _ = go(["wrong-header", "--apply", "--confirm-live"], fakes=Fakes(status=200))
    assert rc == 1 and "FAILED" in out


# ---- config ---------------------------------------------------------------

def test_missing_required_config_is_a_clear_error_and_runs_nothing():
    rc, out, fakes = go(["heartbeat-silent", "--apply", "--confirm-live"], env={})
    assert rc == 2 and "GAMEDAY_HEARTBEAT_HOST" in out and fakes.commands == []


def test_toml_config_is_read_and_environment_wins(tmp_path):
    f = tmp_path / "g.toml"
    f.write_text('n8n_container = "n8n-file"\ngrafana_container = "graf-file"\n')
    cfg = gd.load_config({"GAMEDAY_GRAFANA_CONTAINER": "graf-env"}, str(f))
    assert cfg["n8n_container"] == "n8n-file" and cfg["grafana_container"] == "graf-env"


def test_unknown_toml_key_is_rejected(tmp_path):
    f = tmp_path / "g.toml"
    f.write_text('password = "x"\n')
    with pytest.raises(gd.GamedayError):
        gd.load_config({}, str(f))


@pytest.mark.parametrize("env", [
    {"GAMEDAY_N8N_CONTAINER": "n8n; rm -rf /"},
    {"GAMEDAY_N8N_CONTAINER": "-v"},
    {"GAMEDAY_DISCORD_HOST": "x'; reboot; '"},
    {"GAMEDAY_ROUTER_WORKFLOW_ID": "1 --foo"},
])
def test_hostile_config_values_are_rejected(env):
    rc, out, fakes = go(["discord-unreachable" if "HOST" in list(env)[0] or "CONTAINER" in list(env)[0]
                         else "router-inactive", "--apply", "--confirm-live"], env={**ENV, **env})
    assert rc == 2 and fakes.commands == []


def test_log_records_one_json_line_without_commands(tmp_path):
    log = tmp_path / "g.jsonl"
    rc, _, _ = go(["n8n-down", "--apply", "--confirm-live", "--log", str(log)])
    rec = json.loads(log.read_text())
    assert rec["scenario"] == "n8n-down" and rec["mode"] == "inject" and rec["ok"] is True
    assert "docker" not in log.read_text()




def test_docs_and_script_have_no_dashes_and_cover_every_scenario():
    doc = (REPO_ROOT / "docs" / "game-day.md").read_text()
    text = doc + (REPO_ROOT / "scripts" / "gameday.py").read_text()
    assert "—" not in text and "–" not in text  # no em or en dashes
    for name in gd.SCENARIO_NAMES:
        assert f"`{name}`" in doc
    for section in ("## Checklist", "## Rollback", "## Safety model"):
        assert section in doc
