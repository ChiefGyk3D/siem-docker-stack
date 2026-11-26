"""Guards for issue #60: the GRAFANA_WEBHOOK_SECRET check in scripts/check-env.sh
must not be fooled by alternate .env line forms.

Docker Compose, a shell that sources the file and an editor can each read the
same line differently, so the check measures only the plain `NAME=value` form
and fails closed on every other form of an assignment to that variable (export
prefix, indentation, spaces before the equals sign, a carriage return, a
duplicate in any of those forms, or an assignment inside a multi-line quoted
value). No test needs root, a network or a container runtime.
"""
import re
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

CHECK_ENV = REPO_ROOT / "scripts" / "check-env.sh"
BASH = shutil.which("bash")
SH = shutil.which("sh")
VAR = "GRAFANA_WEBHOOK_SECRET"
GOOD = "a" * 40
CR = chr(13)
NUL = chr(0)


def _body():
    ci = (REPO_ROOT / "tests" / "compose.ci.env").read_text(encoding="utf-8").splitlines()
    names = [ln.split("=")[0] for ln in ci if "=" in ln and not ln.startswith("#")]
    names.append("OPENSEARCH_ADMIN_PASSWORD")
    return "".join(f"{n}=Zx9-unique-{i}\n" for i, n in enumerate(dict.fromkeys(names)) if n != VAR)


def run_check(tmp_path, *lines, shell=BASH):
    env = tmp_path / ".env"
    env.write_bytes((_body() + "".join(line + "\n" for line in lines)).encode())
    return subprocess.run([shell, str(CHECK_ENV), str(env)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60, check=False)


def webhook_complaints(proc):
    return [ln for ln in proc.stderr.splitlines() if VAR in ln]


def test_baseline_plain_line_passes(tmp_path):
    proc = run_check(tmp_path, f"{VAR}={GOOD}")
    assert proc.returncode == 0, proc.stderr


# Forms that must be refused, each with a long enough value so that only the form,
# not the length, can be the reason. The value never appears in the output.
REFUSED = {
    "export-prefix": [f"export {VAR}={GOOD}"],
    "export-prefix-tab": [f"export\t{VAR}={GOOD}"],
    "indented": [f"  {VAR}={GOOD}"],
    "tab-indented": [f"\t{VAR}={GOOD}"],
    "space-before-equals": [f"{VAR} ={GOOD}"],
    "space-around-equals": [f"{VAR} = {GOOD}"],
    "tab-before-equals": [f"{VAR}\t={GOOD}"],
    "crlf": [f"{VAR}={GOOD}{CR}"],
    "crlf-quoted": [f'{VAR}="{GOOD}"{CR}'],
    "cr-inside-value": [f"{VAR}={GOOD[:20]}{CR}{GOOD[:20]}"],
    "duplicate-plain-then-export-short": [f"{VAR}={GOOD}", f"export {VAR}=x"],
    "duplicate-export-then-plain": [f"export {VAR}=x", f"{VAR}={GOOD}"],
    "duplicate-indented": [f"{VAR}={GOOD}", f"  {VAR}={GOOD}"],
    "duplicate-spaced": [f"{VAR}={GOOD}", f"{VAR} = {GOOD}"],
    "export-short": [f"export {VAR}=x"],
    "export-empty": [f"export {VAR}="],
    "spaced-empty": [f"{VAR} ="],
    "trailing-backslash": [f"{VAR}={GOOD}\\"],
    "quoted-trailing-backslash": [f'{VAR}="{GOOD}\\"'],
    "inside-multiline-double-quote": ['OTHER="first line', f"{VAR}={GOOD}", 'last line"'],
    "inside-multiline-single-quote": ["OTHER='first line", f"{VAR}={GOOD}", "last line'"],
    "empty-then-good": [f"{VAR}=", f"{VAR}={GOOD}"],
    "good-then-empty": [f"{VAR}={GOOD}", f"{VAR}="],
    "only-comment-value": [f"{VAR}= # {'c' * 40}"],
    "quotes-around-spaces-only": [f"{VAR}='{' ' * 40}'"],
    "empty-double-quotes": [f'{VAR}=""'],
    "empty-single-quotes": [f"{VAR}=''"],
    "whitespace-then-comment": [f"{VAR}=   # {'c' * 40}"],
    "quoted-then-garbage": [f'{VAR}="{GOOD}"junk'],
    "short-after-trailing-spaces": [f"{VAR}=x{' ' * 40}"],
    "dollar": [f"{VAR}={GOOD[:20]}$X{GOOD[:20]}"],
    # Daybreak round 1, finding 3: a shell reads these differently from a plain value.
    "space-after-equals": [f"{VAR}= {GOOD}"],
    "tab-after-equals": [f"{VAR}=\t{GOOD}"],
    "heredoc": [f"{VAR}=<<EOF{GOOD}"],
    "heredoc-after-value": [f"{VAR}={GOOD}<<EOF"],
    "redirect-out": [f"{VAR}={GOOD[:20]}>{GOOD[:20]}"],
    "backtick": [f"{VAR}={GOOD[:20]}`x`{GOOD[:20]}"],
    "command-substitution": [f"{VAR}={GOOD[:20]}$(x){GOOD[:20]}"],
    "command-substitution-quoted": [f'{VAR}="{GOOD[:20]}$(x){GOOD[:20]}"'],
    "dollar-single-quoted": [f"{VAR}='{GOOD[:20]}$X{GOOD[:20]}'"],
    "semicolon": [f"{VAR}={GOOD[:20]};{GOOD[:20]}"],
    "ampersand": [f"{VAR}={GOOD[:20]}&{GOOD[:20]}"],
    "pipe": [f"{VAR}={GOOD[:20]}|{GOOD[:20]}"],
    "parenthesis": [f"{VAR}=({GOOD})"],
    "glob": [f"{VAR}={GOOD[:20]}*{GOOD[:20]}"],
    "tilde-brace-bang": [f"{VAR}={GOOD[:20]}!{GOOD[:20]}"],
    "space-inside-unquoted": [f"{VAR}={GOOD[:20]} {GOOD[:20]}"],
    "space-inside-quoted": [f'{VAR}="{GOOD[:20]} {GOOD[:20]}"'],
    "quote-in-the-middle": [f'{VAR}={GOOD[:20]}"{GOOD[:20]}'],
    "escaped-quote-multiline": ['OTHER="first \\"', f"{VAR}={GOOD}", 'last"'],
    "multiline-value-anywhere": ['OTHER="first', "second", 'last"', f"{VAR}={GOOD}"],
    "nul-in-name": [f"GRAFANA{NUL}_WEBHOOK_SECRET={GOOD}"],
    "nul-in-value": [f"{VAR}={GOOD}{NUL}"],
    "escape-char": [f"{VAR}={GOOD}{chr(27)}"],
    "bell": [f"{VAR}={GOOD[:20]}{chr(7)}{GOOD[:20]}"],
    "control-on-another-line": [f"OTHER=a{chr(1)}b", f"{VAR}={GOOD}"],
    "carriage-return-on-another-line": [f"OTHER=a{CR}", f"{VAR}={GOOD}"],
}


@pytest.mark.parametrize("lines", REFUSED.values(), ids=REFUSED.keys())
def test_alternate_forms_are_refused_without_printing_the_value(tmp_path, lines):
    proc = run_check(tmp_path, *lines)
    assert proc.returncode == 1, proc.stderr
    assert webhook_complaints(proc), proc.stderr
    assert "aaaa" not in proc.stdout + proc.stderr, "the value must not be printed"
    assert "ccc" not in proc.stdout + proc.stderr, "the comment must not be printed"


@pytest.mark.parametrize("lines", [
    [f"{VAR}={GOOD}{' ' * 6}"],                       # trailing whitespace on an unquoted value
    [f"{VAR}={GOOD}\t"],
    [f'{VAR}="{GOOD}"{" " * 4}'],                     # trailing whitespace after a closing quote
    [f"{VAR}='{GOOD}'  # a comment"],
    [f"{VAR}={GOOD} # a comment"],
    [f"# {VAR}=x", f"{VAR}={GOOD}"],                   # a commented-out line is not an assignment
    [f"#{VAR}=x", f"{VAR}={GOOD}"],
    [f"{VAR}_OTHER=x", f"{VAR}={GOOD}"],               # a longer name is a different variable
    [f"X{VAR}=x", f"{VAR}={GOOD}"],
    [f"export OTHER=1", f"{VAR}={GOOD}"],
    ["OTHER='fine'", f"{VAR}={GOOD}", 'ALSO="fine"'],  # quotes balanced on other lines
], ids=["trail-spaces", "trail-tab", "quoted-trail-spaces", "single-quote-comment",
        "unquoted-comment", "commented-out", "hash-no-space", "longer-name", "prefixed-name",
        "export-other", "balanced-quotes-elsewhere"])
def test_harmless_forms_still_pass(tmp_path, lines):
    proc = run_check(tmp_path, *lines)
    assert proc.returncode == 0, proc.stderr


def test_missing_assignment_is_refused(tmp_path):
    proc = run_check(tmp_path, f"# {VAR}={GOOD}")
    assert proc.returncode == 1 and webhook_complaints(proc), proc.stderr


def test_file_without_a_final_newline(tmp_path):
    env = tmp_path / ".env"
    env.write_bytes((_body() + f"{VAR}={GOOD}").encode())
    proc = subprocess.run([BASH, str(CHECK_ENV), str(env)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    env.write_bytes((_body() + f"{VAR}=x").encode())
    proc = subprocess.run([BASH, str(CHECK_ENV), str(env)], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60, check=False)
    assert proc.returncode == 1, proc.stderr


def test_a_symlinked_env_file_is_refused(tmp_path):
    real = tmp_path / "real.env"
    real.write_bytes((_body() + f"{VAR}={GOOD}\n").encode())
    link = tmp_path / "link.env"
    link.symlink_to(real)
    for shell_target in (link,):
        proc = subprocess.run([BASH, str(CHECK_ENV), str(shell_target)], capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=60, check=False)
        assert proc.returncode == 2, proc.stderr
        assert "symlink" in proc.stderr
    ok = subprocess.run([BASH, str(CHECK_ENV), str(real)], capture_output=True, text=True,
                        stdin=subprocess.DEVNULL, timeout=60, check=False)
    assert ok.returncode == 0, ok.stderr


def test_a_directory_or_missing_file_is_still_exit_2(tmp_path):
    for target in (tmp_path, tmp_path / "missing.env"):
        proc = subprocess.run([BASH, str(CHECK_ENV), str(target)], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=60, check=False)
        assert proc.returncode == 2, proc.stderr


def test_the_file_is_read_once_into_memory():
    text = CHECK_ENV.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r'grep[^\n]*"\$ENV_FILE"', code), "a check rereads the file"
    assert 'done < "$ENV_FILE"' not in code, "the webhook scan rereads the file"
    assert code.count('exec 3< "$ENV_FILE"') == 1


def test_messages_explain_the_form_rule(tmp_path):
    proc = run_check(tmp_path, f"export {VAR}={GOOD}")
    assert "plain" in proc.stderr and "NAME=value" in proc.stderr


def test_sh_never_reports_success():
    """The script is bash-only (arrays, [[ ]]). Under a POSIX sh it must fail, not pass."""
    assert SH, "sh not found"
    proc = subprocess.run([SH, str(CHECK_ENV), "/nonexistent-env-file"], capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, timeout=60, check=False)
    assert proc.returncode != 0


def test_docs_describe_the_form_rule():
    text = (REPO_ROOT / "docs" / "update-alerting.md").read_text(encoding="utf-8")
    for needle in ("export", "carriage return", "plain `NAME=value`"):
        assert needle in text, needle
