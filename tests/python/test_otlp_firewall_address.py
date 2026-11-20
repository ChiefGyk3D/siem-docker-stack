"""Guards for issue #58: the OTLP firewall script's handling of the published address.

Everything runs the real script under bash with a stub `iptables` and `docker`
(no root, no netfilter). The stub records each call as a JSON argument list, so
a test can prove the script passes argument lists and never a re-split string.
The Docker-specific chain model (docs/design/podman.md) is out of scope here.
"""
import json
import shutil
import stat
import subprocess
import textwrap

import pytest

from conftest import REPO_ROOT

FIREWALL = REPO_ROOT / "scripts" / "prometheus-otlp-firewall.sh"
DOC = REPO_ROOT / "docs" / "prometheus-otlp.md"
BASH = shutil.which("bash")
SH = shutil.which("sh")
GOOD = ("apply", "192.0.2.1", "192.0.2.10", "192.0.2.11")
CHANGING = ("-N", "-F", "-X", "-I", "-D", "-A")

IPT_STUB = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    args = sys.argv[1:]
    with open(os.environ["IPT_LOG"], "a") as f:
        f.write(json.dumps(args) + "\\n")
    state = open(os.environ["IPT_STATE"]).read()
    if args[:2] == ["-S", "DOCKER-USER"]:
        sys.stdout.write(state)
    sys.exit(0)
    """)
DOCKER_STUB = textwrap.dedent("""\
    #!/usr/bin/env python3
    import os, sys
    # the engine runs with a scrubbed environment (issue #130), so the canned output is a file
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker.out")) as fh:
        sys.stdout.write(fh.read())
    """)


def _stub(directory, name, body):
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


@pytest.fixture()
def fw(tmp_path):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    _stub(stubs, "iptables", IPT_STUB)
    _stub(stubs, "docker", DOCKER_STUB)
    log, state = tmp_path / "ipt.log", tmp_path / "ipt.state"

    def run(*args, docker_out="127.0.0.1:9091\n", state_text="", shell=BASH):
        state.write_text(state_text, encoding="utf-8")
        (stubs / "docker.out").write_text(docker_out, encoding="utf-8")
        log.write_text("", encoding="utf-8")
        env = {"PATH": f"{stubs}:/usr/bin:/bin", "IPT_LOG": str(log), "IPT_STATE": str(state),
               "IPTABLES": str(stubs / "iptables"), "DOCKER": str(stubs / "docker"),
               "DOCKER_PORT_OUT": docker_out, "PROM_FW_NO_SUDO": "1"}
        proc = subprocess.run([shell, str(FIREWALL), *args], env=env, text=True,
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=30, cwd=tmp_path)
        proc.calls = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x]
        proc.changes = [c for c in proc.calls if c and c[0] in CHANGING]
        return proc
    return run


def _refused(proc, *words):
    assert proc.returncode != 0, proc.stdout
    assert proc.changes == [], proc.changes
    assert proc.stderr.startswith("prometheus-otlp-firewall:"), proc.stderr
    for word in words:
        assert word in proc.stderr, (word, proc.stderr)


# --- the bind address ----------------------------------------------------------------

BAD_BINDS = {
    "empty": ("", "usage"),
    "ipv6-any": ("::", "IPv6"),
    "ipv6-loopback": ("::1", "IPv6"),
    "ipv6-global": ("2001:db8::1", "IPv6"),
    "ipv4-mapped": ("::ffff:192.0.2.1", "IPv6"),
    "ipv4-mapped-hex": ("::ffff:c000:201", "IPv6"),
    "bracketed-ipv6": ("[::1]", "IPv4"),
    "wildcard": ("0.0.0.0", "0.0.0.0"),
    "zero-network": ("0.1.2.3", "interface"),
    "loopback": ("127.0.0.1", "interface"),
    "loopback-other": ("127.8.8.8", "interface"),
    "broadcast": ("255.255.255.255", "interface"),
    "multicast": ("224.0.0.1", "interface"),
    "reserved": ("240.0.0.1", "interface"),
    "with-prefix": ("192.0.2.1/32", "IPv4"),
    "leading-zero": ("192.0.2.01", "IPv4"),
    "octet-too-big": ("192.0.2.256", "IPv4"),
    "short": ("192.0.2", "IPv4"),
    "five-octets": ("192.0.2.1.1", "IPv4"),
    "hostname": ("localhost", "IPv4"),
    "hex-form": ("0x7f.0.0.1", "IPv4"),
    "leading-space": (" 192.0.2.1", "IPv4"),
    "trailing-space": ("192.0.2.1 ", "IPv4"),
    "trailing-newline": ("192.0.2.1\n", "IPv4"),
    "newline-then-option": ("192.0.2.1\n-j ACCEPT", "IPv4"),
    "space-then-option": ("192.0.2.1 -j ACCEPT", "IPv4"),
    "semicolon": ("192.0.2.1;id", "IPv4"),
    "command-substitution": ("$(id)", "IPv4"),
    "backtick": ("`id`", "IPv4"),
    "glob": ("*", "IPv4"),
    "option-like": ("-j", "IPv4"),
    "long-option": ("--help", "IPv4"),
    "negation": ("!", "IPv4"),
}


@pytest.mark.parametrize("value,word", BAD_BINDS.values(), ids=BAD_BINDS.keys())
def test_bind_address_is_refused_with_a_clear_message(fw, value, word):
    _refused(fw("apply", value, "192.0.2.10"), word)


def test_a_refused_bind_never_reaches_iptables_or_docker(fw):
    proc = fw("apply", "192.0.2.1 -j ACCEPT", "192.0.2.10")
    assert proc.calls == []


def test_a_good_bind_is_one_argument_in_the_jump_and_the_check(fw):
    proc = fw(*GOOD)
    assert proc.returncode == 0, proc.stderr
    jump = next(c for c in proc.calls if c[:2] == ["-I", "DOCKER-USER"])
    check = next(c for c in proc.calls if c[:2] == ["-C", "DOCKER-USER"])
    assert jump[jump.index("--ctorigdst") + 1] == "192.0.2.1"
    assert jump[jump.index("--ctorigdstport") + 1] == "9091"
    assert check[2:] == jump[2:]


# --- the senders ---------------------------------------------------------------------

BAD_SENDERS = {
    "empty": "",
    "option-like": "-j",
    "space-then-option": "192.0.2.10 -j ACCEPT",
    "newline": "192.0.2.10\n",
    "semicolon": "192.0.2.10;id",
    "ipv6": "::1",
    "ipv4-mapped": "::ffff:192.0.2.10",
    "ipv6-cidr": "2001:db8::/32",
    "prefix-too-long": "192.0.2.10/33",
    "negative-prefix": "192.0.2.10/-1",
    "empty-prefix": "192.0.2.10/",
    "zero-prefix": "192.0.2.10/0",
    "wildcard": "0.0.0.0",
    "wildcard-cidr": "0.0.0.0/0",
    "hostname": "sender.example.com",
}


@pytest.mark.parametrize("sender", BAD_SENDERS.values(), ids=BAD_SENDERS.keys())
def test_sender_is_refused_with_a_clear_message(fw, sender):
    _refused(fw("apply", "192.0.2.1", sender), "sender")


def test_one_bad_sender_among_good_ones_changes_nothing(fw):
    _refused(fw("apply", "192.0.2.1", "192.0.2.10", "192.0.2.11 -j ACCEPT"), "sender")


def test_duplicate_senders_make_one_rule_each(fw):
    proc = fw("apply", "192.0.2.1", "192.0.2.10", "192.0.2.11", "192.0.2.10")
    assert proc.returncode == 0, proc.stderr
    returns = [c for c in proc.calls if c[:1] == ["-A"] and c[-2:] == ["-j", "RETURN"]]
    assert sorted(c[c.index("-s") + 1] for c in returns) == ["192.0.2.10", "192.0.2.11"]


# --- the address the container is published on -----------------------------------

@pytest.mark.parametrize("out,word", [
    ("0.0.0.0:9091\n", "every address"),
    ("198.51.100.5:9091\n", "198.51.100.5"),
], ids=["wildcard-published", "other-address"])
def test_a_publish_address_the_rule_would_not_cover_is_refused(fw, out, word):
    proc = fw(*GOOD, docker_out=out)
    _refused(proc, word)


@pytest.mark.parametrize("out", ["127.0.0.1:9091\n", "192.0.2.1:9091\n", "127.0.0.1:9091\n\n"],
                         ids=["loopback-before-widening", "already-on-the-bind-address", "trailing-blank-line"])
def test_a_publish_address_that_the_rule_covers_is_accepted(fw, out):
    proc = fw(*GOOD, docker_out=out)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("out", [
    "[::]:9091\n",
    "[::1]:9091\n",
    "[2001:db8::1]:9091\n",
    "[::]:9091\n127.0.0.1:9091\n",
    "127.0.0.1:9091\n[::]:9091\n",
    "127.0.0.1:9091\n[::1]:9091\n",
    "127.0.0.1:9091\n[2001:db8::1]:9091\n",
    "127.0.0.1:9091\nWARNING something\n",
    "127.0.0.1:9091\n192.0.2.1:abc\n",
    "127.0.0.1:9091 \n",
], ids=["v6-wildcard", "v6-loopback", "v6-global", "v6-then-v4", "v4-then-v6-wildcard",
        "v4-then-v6-loopback", "v4-then-v6-global", "v4-then-noise", "v4-then-bad-port",
        "trailing-space"])
def test_any_published_mapping_the_ipv4_rule_would_not_guard_is_refused(fw, out):
    _refused(fw(*GOOD, docker_out=out), "IPv4")


# --- argument lists, never shell strings -----------------------------------------------

REAL_LIVE = ("-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdst 192.0.2.1/32 "
             "--ctorigdstport 9091 --ctdir ORIGINAL -j PROM-OTLP-A\n")


def test_old_rule_is_deleted_with_the_exact_words_iptables_printed(fw):
    proc = fw(*GOOD, state_text=REAL_LIVE)
    assert proc.returncode == 0, proc.stderr
    deleted = [c for c in proc.calls if c[:2] == ["-D", "DOCKER-USER"]]
    assert deleted == [["-D", "DOCKER-USER", "-p", "tcp", "-m", "conntrack", "--ctstate", "DNAT",
                        "--ctorigdst", "192.0.2.1/32", "--ctorigdstport", "9091",
                        "--ctdir", "ORIGINAL", "-j", "PROM-OTLP-A"]]


HOSTILE_LIVE = {
    "quoted-comment": REAL_LIVE.replace("-j PROM-OTLP-A", '-m comment --comment "a b" -j PROM-OTLP-A'),
    "semicolon": REAL_LIVE.replace("-j PROM-OTLP-A", "; touch pwned -j PROM-OTLP-A"),
    "substitution": REAL_LIVE.replace("--ctorigdst 192.0.2.1/32", "--ctorigdst $(touch pwned)"),
    "glob": REAL_LIVE.replace("--ctorigdst 192.0.2.1/32", "--ctorigdst *"),
    "backtick": REAL_LIVE.replace("--ctorigdst 192.0.2.1/32", "--ctorigdst `touch pwned`"),
}


@pytest.mark.parametrize("state", HOSTILE_LIVE.values(), ids=HOSTILE_LIVE.keys())
def test_a_live_rule_that_cannot_be_split_safely_is_refused_untouched(fw, state, tmp_path):
    (tmp_path / "keep-me").write_text("x", encoding="utf-8")
    for command in (GOOD, ("remove",)):
        proc = fw(*command, state_text=state)
        _refused(proc, "PROM-OTLP")
        assert not (tmp_path / "pwned").exists()
    assert (tmp_path / "keep-me").exists()


def test_rules_that_jump_to_both_chains_are_refused(fw):
    both = REAL_LIVE + REAL_LIVE.replace("PROM-OTLP-A", "PROM-OTLP-B")
    _refused(fw(*GOOD, state_text=both), "remove")


def test_unrelated_docker_user_rules_are_never_touched(fw):
    other = "-A DOCKER-USER -s 198.51.100.7/32 -j DROP\n-A DOCKER-USER -j RETURN\n"
    proc = fw(*GOOD, state_text=other + REAL_LIVE)
    assert proc.returncode == 0, proc.stderr
    assert not any(c[:2] == ["-D", "DOCKER-USER"] and "198.51.100.7/32" in c for c in proc.calls)
    assert len([c for c in proc.calls if c[:2] == ["-D", "DOCKER-USER"]]) == 1


# --- idempotent -------------------------------------------------------------------------

def _rules_added(proc):
    return [c for c in proc.calls if c[:1] == ["-A"]]


def test_the_same_arguments_give_the_same_rule_set_every_run(fw):
    first = fw(*GOOD)
    second = fw(*GOOD, state_text=REAL_LIVE)
    third = fw(*GOOD, state_text=REAL_LIVE.replace("PROM-OTLP-A", "PROM-OTLP-B"))
    for proc in (first, second, third):
        assert proc.returncode == 0, proc.stderr

    def shape(proc):
        return [[w.replace("PROM-OTLP-A", "CHAIN").replace("PROM-OTLP-B", "CHAIN") for w in c]
                for c in _rules_added(proc)]
    assert shape(first) == shape(second) == shape(third)


def test_remove_twice_is_harmless(fw):
    proc = fw("remove")
    assert proc.returncode == 0, proc.stderr
    assert not any(c[:2] == ["-D", "DOCKER-USER"] for c in proc.calls)


# --- bash only, docs ----------------------------------------------------------------------

def test_script_is_bash_syntax_clean():
    assert subprocess.run([BASH, "-n", str(FIREWALL)], capture_output=True).returncode == 0


def test_sh_never_reports_success():
    proc = subprocess.run([SH, str(FIREWALL), "apply", "192.0.2.1", "192.0.2.10"],
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30,
                          env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode != 0


def test_doc_states_the_address_rules():
    text = DOC.read_text(encoding="utf-8")
    for needle in ("IPv4-mapped", "loopback", "published address", "refuses"):
        assert needle in text, needle
