"""No documentation example may put a credential on a command line or in a URL.

Covered forms (each is a case in the tests below, so the claim is exactly what is checked):
  * curl with the short user flag or the long user option, in any spelling (attached or separate operand,
    combined short flags, an equals sign, continuation lines). Inside a fenced code block any such flag
    fails; in prose it fails when its operand has a colon.
  * credentials embedded in a URL, with a user name or an empty one
  * a Basic authorization header
  * wget user and password options
  * an inline assignment of the PostgreSQL password variable
  * in a code block, an export of a secret-named variable (PASS, PASSWORD, API_KEY, TOKEN, SECRET, WEBHOOK_URL)
    with a value on the line, in the EXPORT_CHECKED docs only
Not covered: secrets reaching a command through a shell variable the scanner cannot follow.
Examples call scripts/secure-curl.sh instead (tests/python/test_secure_curl.py).

The bad example lines below are written with @X@ tokens and assembled by build() at run time, so this file
never contains a line shaped like a curl command with a user and password (the secret scan would flag it);
test_this_file_contains_no_credential_shaped_line proves that.
"""

import re

import pytest

from conftest import REPO_ROOT

CURL_FLAG = r"(?:\s-[A-Za-z]*u|\s--user(?![\w-])|\s--basic(?![\w-])[^\n]*?\s-[A-Za-z]*u)"
CURL_USER_ANY = re.compile(r"\bcurl\b[^\n]*?" + CURL_FLAG)
CURL_USER_PAIR = re.compile(r"\bcurl\b[^\n]*?(?:\s-[A-Za-z]*u|\s--user(?:=|\s+))\s*[\"']?[^\s\"']*:")
URL_CREDENTIALS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/\"'@]*:[^\s/\"'@]*@")
BASIC_HEADER = re.compile(r"Authorization:\s*Basic\b", re.IGNORECASE)
WGET_PASSWORD = re.compile(r"\bwget\b[^\n]*?\s--(?:http-)?(?:password|user)(?![\w-])")
PGPASSWORD = re.compile(r"\bPGPASSWORD=")
# an export of a secret with a value typed or pasted on the line (history, and every later child inherits it)
SECRET_EXPORT = re.compile(r"^\s*export\s+\w*(?:PASS|PASSWORD|API_KEY|TOKEN|SECRET|WEBHOOK_URL)\w*=\S", re.IGNORECASE)


def doc_files():
    out = [REPO_ROOT / "README.md"] + sorted(REPO_ROOT.glob("docs/**/*.md"))
    return [p for p in out if p.is_file()]


def logical_lines(text):
    """Yield (first line number, in_fence, text) with backslash-continued lines joined."""
    buf, start, fenced, fence_now = [], 0, False, False
    for n, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = n
            fence_now = fenced
        if line.lstrip().startswith("```") and not buf:
            fenced = not fenced
            fence_now = fenced
            continue
        if line.rstrip().endswith("\\") and fenced:
            buf.append(line.rstrip()[:-1])
            continue
        buf.append(line)
        yield start, fence_now, " ".join(buf)
        buf = []
    if buf:
        yield start, fence_now, " ".join(buf)


# The export rule is enforced where it has been cleaned up so far; other docs (expiry-watch, jumpcloud) are
# tracked separately and not claimed here.
EXPORT_CHECKED = ("README.md", "docs/n8n-soar.md", "docs/maintenance.md", "docs/phase-f-testing.md",
                  "docs/backup-restore.md", "docs/gpu-monitoring.md", "docs/troubleshooting.md",
                  "docs/prometheus-otlp.md")


def offenders(text, export_rule=True):
    out = []
    for n, fenced, s in logical_lines(text):
        bad = (
            (CURL_USER_ANY.search(s) if fenced else CURL_USER_PAIR.search(s))
            or URL_CREDENTIALS.search(s)
            or BASIC_HEADER.search(s)
            or WGET_PASSWORD.search(s)
            or PGPASSWORD.search(s)
            or (export_rule and fenced and SECRET_EXPORT.search(s))
        )
        if bad:
            out.append((n, s.strip()))
    return out


TOKENS = {"@C@": "cu" + "rl", "@U@": "-" + "u", "@u@": "u", "@UU@": "--" + "user", "@S@": chr(58)}


def build(line):
    for token, text in TOKENS.items():
        line = line.replace(token, text)
    return line


# the shape the secret scanner looks for, built from pieces so this file does not contain it either
SHAPE = re.compile(r"cu" + r"rl\b[^\n]*?\s(?:-[A-Za-z]*" + "u" + r"|--" + "user" + r")[= ]*[\"']?[^\s\"']+:[^\s\"']")
SELF_SCANNED = ("tests/python/test_docs_no_curl_user_password.py", "tests/python/test_secure_curl.py",
                "scripts/secure-curl.sh")


@pytest.mark.parametrize("relpath", SELF_SCANNED)
def test_this_file_contains_no_credential_shaped_line(relpath):
    hits = []
    for n, line in enumerate((REPO_ROOT / relpath).read_text(encoding="utf-8").splitlines(), 1):
        if SHAPE.search(line):
            hits.append(f"{relpath}:{n}")
    assert not hits, hits


def test_the_self_scan_shape_catches_a_real_one():
    assert SHAPE.search(build("@C@ @U@ admin@S@pw https://h/"))
    assert SHAPE.search(build("@C@ @UU@=admin@S@pw https://h/"))


def fence(line):
    return "```bash\n" + line + "\n```"


@pytest.mark.parametrize("line", [
    "@C@ @U@ admin@S@password http://localhost:3000/x",
    '@C@ -sk @U@ "admin@S@${PW}" https://localhost:9200/',
    "@C@ -sk @U@ admin@S@... -X DELETE https://localhost:9200/x",
    '@C@ -sk@u@ "admin@S@$PW" https://localhost:9200/',
    "@C@ @U@admin@S@pw https://h/",
    "@C@ @U@'admin@S@pw' https://h/",
    "@C@ -sSL@u@ admin@S@pw https://h/",
    "@C@ --basic @U@ admin@S@pw https://h/",
    "@C@ @UU@ admin@S@secret https://h/",
    "@C@ @UU@=admin@S@secret https://h/",
    '@C@ @UU@="admin@S@${PW}" https://h/',
    '@C@ @U@ "$CRED" https://h/',
    '@C@ -X POST "http://admin@S@${GRAFANA_ADMIN_PASS}@localhost:3000/api" -d x',
    "@C@ http://admin@S@pw@host/",
    "@C@ http://@S@secret@host/",
    "@C@ https://@S@${PW}@host:9200/",
    "@C@ https://admin@S@${PW}@host:9200/",
    '@C@ -H "Authorization@S@ Basic YWRtaW46cHc=" https://h/',
    "wget @UU@=admin --password=pw https://h/",
    "wget --http-password pw https://h/",
    "PGPASSWORD=secret psql -h h -U u",
    'export N8N_PASSWORD="literal"',
    "export GRAFANA_PASS=literal",
    '@C@ -sS -X POST @U@ "sender@S@${PW}" \\\n  -H "A: b" https://h/',
    '@C@ -sS \\\n  @U@ "sender@S@${PW}" https://h/',
])
def test_the_scan_catches_every_spelling_in_a_code_block(line):
    assert offenders(fence(build(line))), line


@pytest.mark.parametrize("line", [
    'use `@C@ @U@ "self@S@$PW" ...` for queries',
    "run `@C@ @UU@ admin@S@secret https://h/`",
    "the URL http://admin@S@pw@host/ leaks",
    "set PGPASSWORD=x first",
])
def test_the_scan_catches_a_pair_in_prose(line):
    assert offenders(build(line)), line


@pytest.mark.parametrize("line", [
    "@C@ -K - -sk https://localhost:9200/",
    "printf 'user = \"%s\"\\n' \"$c\" | @C@ -K - -sk https://localhost:9200/",
    "scripts/secure-curl.sh admin -sk https://localhost:9200/_cluster/health",
    "@C@ -sk -o /dev/null -w '%{http_code}\\n' https://localhost:9200/",
    "@C@ -sk https://user.example.com:9200/ -H 'Accept: x'",
    "@C@ -sk https://host:9200/a@b",
    "@C@ @UU@-agent ok https://host/",
    "@C@ @UU@-agent=a@S@b https://host/",
    "wget @UU@-agent=ok https://host/",
    "ssh user@host 'echo hi'",
    "git clone git@github.com:owner/repo.git",
])
def test_the_scan_leaves_safe_commands_alone(line):
    assert not offenders(fence(build(line))), line


@pytest.mark.parametrize("line", [
    "Do not pass the password with curl's @U@ flag; use the helper.",
    "@C@ @UU@ is avoided here",
])
def test_the_scan_allows_prose_that_names_the_flag_without_a_pair(line):
    assert not offenders(build(line)), line


def test_no_doc_puts_a_credential_on_a_command_line_or_in_a_url():
    hits = []
    for path in doc_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(REPO_ROOT))
        for n, s in offenders(text, export_rule=rel in EXPORT_CHECKED):
            hits.append(f"{path.relative_to(REPO_ROOT)}:{n}: {s}")
    assert not hits, "\n".join(hits)
