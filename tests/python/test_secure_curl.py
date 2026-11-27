"""scripts/secure-curl.sh: the password reaches curl only as a config on stdin.

A recording curl wrapper stores argv, environ and stdin of the one child. Everything below runs the script by
its path (the `-p` shebang), the way the docs tell people to, plus the explicit-interpreter spellings that must
not leak either.
"""

import os
import re
import subprocess

import pytest

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "secure-curl.sh"
PATH_LINE = "PATH=/usr/local/sbin:"
SENTINEL = "S3ntinel-Pw-9f2c"

FAKE_CURL = r"""#!/bin/bash
REC='@REC@'
id=$$
for a in "$@"; do printf '%s\n' "$a"; done > "$REC/curl-$id-argv"
cat /proc/$$/environ > "$REC/curl-$id-environ"
cat > "$REC/curl-$id-stdin"
case "$*" in *fail*) exit 22 ;; esac
exit 0
"""


class Box:
    def __init__(self, tmp_path):
        self.rec = tmp_path / "rec"
        self.rec.mkdir()
        bindir = tmp_path / "bin"
        bindir.mkdir()
        curl = bindir / "curl"
        curl.write_text(FAKE_CURL.replace("@REC@", str(self.rec)), encoding="utf-8")
        curl.chmod(0o755)
        text = SCRIPT.read_text(encoding="utf-8")
        assert PATH_LINE in text
        text = text.replace(PATH_LINE, f"PATH={bindir}:/usr/local/sbin:", 1)
        self.script = tmp_path / "secure-curl.sh"
        self.script.write_text(text, encoding="utf-8")
        self.script.chmod(0o755)
        self.tmp = tmp_path

    def run(self, password=SENTINEL, args=("admin", "-sk", "https://localhost:9200/x"), env=None,
            interpreter=(), raw=None):
        stdin = raw if raw is not None else password + "\n"
        full_env = {"PATH": "/usr/bin:/bin", "HOME": str(self.tmp), **(env or {})}
        return subprocess.run([*interpreter, str(self.script), *args], env=full_env, input=stdin, text=True,
                              capture_output=True, timeout=60)

    def recorded(self, suffix):
        return {p.name: p.read_text(encoding="utf-8", errors="replace")
                for p in self.rec.iterdir() if p.name.endswith(suffix)}


def only(d):
    assert len(d) == 1, d
    return next(iter(d.values()))


def test_the_script_is_executable_and_privileged():
    assert os.access(SCRIPT, os.X_OK)
    assert SCRIPT.read_text(encoding="utf-8").startswith("#!/bin/bash -p\n")


def test_curl_gets_the_exact_escaped_config_on_stdin_and_nothing_else(tmp_path):
    box = Box(tmp_path)
    proc = box.run()
    assert proc.returncode == 0, proc.stderr
    assert only(box.recorded("-stdin")) == f'user = "admin:{SENTINEL}"\n'
    argv = only(box.recorded("-argv")).split("\n")
    assert argv[:4] == ["-q", "-K", "-", "-sk"] and "https://localhost:9200/x" in argv
    assert SENTINEL not in only(box.recorded("-argv"))
    assert SENTINEL not in only(box.recorded("-environ"))
    assert SENTINEL not in proc.stdout + proc.stderr


def test_an_exported_name_does_not_reach_curl(tmp_path):
    box = Box(tmp_path)
    proc = box.run(env={"sc_pw": "Other-Exported-1", "sc_cred": "Other-Exported-2", "sc_user": "Other-Exported-3"})
    assert proc.returncode == 0, proc.stderr
    environ = only(box.recorded("-environ"))
    for needle in ("sc_pw=", "sc_cred=", "sc_user=", "Other-Exported", SENTINEL):
        assert needle not in environ, needle
    assert only(box.recorded("-stdin")) == f'user = "admin:{SENTINEL}"\n'


@pytest.mark.parametrize("password,expected", [
    ('a"b', 'a\\"b'),
    ("a\\b", "a\\\\b"),
    ('a\\"b', 'a\\\\\\"b'),
    ("  lead and trail  ", "  lead and trail  "),
    ("p;ss$(id) `x` %s", "p;ss$(id) `x` %s"),
    ('x" -o /tmp/pwned "', 'x\\" -o /tmp/pwned \\"'),
])
def test_a_hostile_password_stays_one_config_line(tmp_path, password, expected):
    box = Box(tmp_path)
    proc = box.run(password=password)
    assert proc.returncode == 0, proc.stderr
    assert only(box.recorded("-stdin")) == f'user = "admin:{expected}"\n'


@pytest.mark.parametrize("raw", ["a\rb\n", "a\tb\n", "a\x01b\n", "a\x7fb\n", "\n", ""])
def test_control_characters_and_an_empty_password_are_refused_before_curl(tmp_path, raw):
    box = Box(tmp_path)
    proc = box.run(raw=raw)
    assert proc.returncode == 2, proc.stderr
    assert not box.recorded("-argv")
    assert "a\rb" not in proc.stdout + proc.stderr


@pytest.mark.parametrize("user", ["", "ad:min", "ad\rmin", "ad\nmin"])
def test_a_bad_user_is_refused_before_curl(tmp_path, user):
    box = Box(tmp_path)
    proc = box.run(args=(user, "-s", "https://h/"))
    assert proc.returncode == 2, proc.stderr
    assert not box.recorded("-argv")


def test_usage_error_without_curl_arguments(tmp_path):
    box = Box(tmp_path)
    proc = box.run(args=("admin",))
    assert proc.returncode == 2
    assert not box.recorded("-argv")


def test_curls_exit_status_is_returned(tmp_path):
    box = Box(tmp_path)
    proc = box.run(args=("admin", "-s", "https://h/fail"))
    assert proc.returncode == 22


TRACE_ENVS = {
    "ps4_names_the_password": {"PS4": "+ ${sc_pw} ${sc_cred} "},
    "ps4_cred_only": {"PS4": "+ ${sc_cred} "},
    "shellopts_xtrace": {"SHELLOPTS": "xtrace", "PS4": "+ ${sc_pw} ${sc_cred} "},
    "bashopts_and_posix": {"BASHOPTS": "extdebug", "SHELLOPTS": "xtrace:posix"},
}


@pytest.mark.parametrize("name", sorted(TRACE_ENVS))
@pytest.mark.parametrize("interpreter", [(), ("bash",), ("bash", "-x"), ("bash", "-o", "xtrace")],
                         ids=["by-path", "bash", "bash-x", "bash-o-xtrace"])
def test_no_trace_setting_ever_prints_the_password(tmp_path, name, interpreter):
    box = Box(tmp_path)
    proc = box.run(env=TRACE_ENVS[name], interpreter=interpreter)
    assert SENTINEL not in proc.stdout + proc.stderr, proc.stderr
    if proc.returncode == 0:
        assert only(box.recorded("-stdin")) == f'user = "admin:{SENTINEL}"\n'
    else:  # failing closed is fine (extdebug installs a DEBUG hook, which the script refuses)
        assert proc.returncode == 2, proc.stderr
        assert not box.recorded("-argv")


def test_a_trace_file_descriptor_is_refused(tmp_path):
    box = Box(tmp_path)
    proc = box.run(env={"BASH_XTRACEFD": "2"})
    assert proc.returncode == 2
    assert SENTINEL not in proc.stdout + proc.stderr
    assert not box.recorded("-argv")


def test_a_bash_env_file_that_turns_tracing_on_is_ignored_by_path(tmp_path):
    hook = tmp_path / "hook.sh"
    hook.write_text('PS4="+ \\${sc_pw}\\${sc_cred} "\nset -x\n', encoding="utf-8")
    box = Box(tmp_path)
    proc = box.run(env={"BASH_ENV": str(hook)})
    assert proc.returncode == 0, proc.stderr
    assert SENTINEL not in proc.stdout + proc.stderr


def run_with_stdin_file(box, args, text=SENTINEL + "\n"):
    """Run with stdin from a seekable file; the returned offset shows whether the password was read."""
    path = box.tmp / "stdin.txt"
    path.write_text(text, encoding="utf-8")
    with open(path, "rb") as fh:
        proc = subprocess.run([str(box.script), *args], stdin=fh, capture_output=True, text=True, timeout=60,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(box.tmp)})
        return proc, fh.tell()


URL = "https://localhost:9200/x"
PAIR = "a" + chr(58) + "b"  # built from pieces: no line of this file looks like a command with a credential
BLOCKED = [
    ["-K", "cfg", URL], ["--config", "cfg", URL], ["--config=cfg", URL],
    ["--libcurl", "/dev/stdout", URL], ["--libc", "/dev/stdout", URL], ["--libcurl=/dev/stdout", URL],
    ["--trace", "-", URL], ["--trace-ascii", "x", URL], ["--trace-time", URL], ["--trace-config", "all", URL],
    ["-v", URL], ["--verbose", URL], ["--verb", URL], ["-sv", URL],
    ["-" + "u", PAIR, URL], ["--" + "user", PAIR, URL], ["--" + "user=" + PAIR, URL],
    ["--proxy-" + "user", PAIR, URL],
    ["-n", URL], ["--netrc", URL], ["--netrc-file", "x", URL], ["--netrc-optional", URL],
    ["--variable", "x@/etc/passwd", URL], ["--expand-url", "{{x}}", URL],
    ["-sK", "cfg", URL], ["-Ku", URL], ["-sKu", URL],
    ["-d", "@-", URL], ["--data-binary", "@-", URL], ["-w", "@-", URL],
    ["--max-t", "1", URL], ["-m5", URL], ["--", URL], ["-X"], ["--unknown-option", URL],
]


@pytest.mark.parametrize("args", BLOCKED, ids=[" ".join(a) for a in BLOCKED])
def test_a_curl_option_that_can_expose_the_password_is_refused_before_it_is_read(tmp_path, args):
    box = Box(tmp_path)
    proc, offset = run_with_stdin_file(box, ["admin", *args])
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert offset == 0, "the password was read before the options were checked"
    assert not box.recorded("-argv"), "curl was started"
    assert SENTINEL not in proc.stdout + proc.stderr


ALLOWED = [
    ["-s", "-S", "-k", "-f", "-I", "-L", URL], ["-sk", URL], ["-sS", URL], ["-sSf", URL], ["-fsSL", URL],
    ["-X", "POST", URL], ["-H", "Content-Type: application/json", URL], ["-d", '{"a":1}', URL],
    ["--data-binary", "@body.json", URL], ["--max-time", "5", URL], ["--connect-timeout", "3", URL],
    ["--cacert", "server.crt", URL], ["--resolve", "SIEM_HOST:9200:192.0.2.1", URL],
    ["-o", "/dev/null", "-w", "%{http_code}\\n", URL],
]


@pytest.mark.parametrize("args", ALLOWED, ids=[" ".join(a) for a in ALLOWED])
def test_the_options_the_docs_use_still_work_and_q_comes_first(tmp_path, args):
    box = Box(tmp_path)
    proc = box.run(args=("admin", *args))
    assert proc.returncode == 0, proc.stderr
    argv = only(box.recorded("-argv")).split("\n")
    assert argv[:3] == ["-q", "-K", "-"]
    assert argv[3:3 + len(args)] == list(args)
    assert only(box.recorded("-stdin")) == f'user = "admin:{SENTINEL}"\n'


def test_a_nul_byte_in_the_password_is_refused_not_dropped(tmp_path):
    box = Box(tmp_path)
    proc = box.run(raw="ab\0cd\n")
    assert proc.returncode == 2, proc.stderr
    assert not box.recorded("-argv")


def test_real_curl_with_libcurl_never_gets_the_chance_to_print_the_password():
    """curl is a hard dependency of the stack, so this runs the real binary (no skip): --libcurl would write
    CURLOPT_USERPWD with the plaintext password."""
    proc = subprocess.run([str(SCRIPT), "admin", "--libcurl", "/dev/stdout", "--max-time", "1",
                           "http://127.0.0.1:1/"], input=SENTINEL + "\n", text=True, capture_output=True,
                          timeout=60, env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 2
    assert SENTINEL not in proc.stdout + proc.stderr
    assert "CURLOPT_USERPWD" not in proc.stdout


# The docs scan: every documented use goes through the helper by its path.
def doc_files():
    return [REPO_ROOT / "README.md"] + sorted(REPO_ROOT.glob("docs/**/*.md"))


def test_docs_call_the_helper_by_path_and_never_read_stdin_for_data():
    uses = 0
    hits = []
    for path in doc_files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "secure-curl.sh" not in line:
                continue
            uses += 1
            where = f"{path.relative_to(REPO_ROOT)}:{n}: {line.strip()}"
            if re.search(r"\b(?:ba|da|z|k)?sh\s+(?:\S+\s+)*\S*secure-curl\.sh", line):
                hits.append("through an interpreter: " + where)
            if re.search(r"(?:-d|--data\S*|--json|-T|--upload-file)[= ]+['\"]?@?-(?:\s|$|['\"])", line):
                hits.append("reads data from stdin: " + where)
    assert uses, "no doc shows the helper"
    assert not hits, "\n".join(hits)
