"""The root decision in three more scripts comes from the kernel, not from EUID or UID.

Bash imports EUID and UID from the environment, so `EUID=0 script` (or an exported value) lets a
caller choose the branch a script takes. These scripts decide from the absolute /usr/bin/id (the
pattern of the firewall script), run under the privileged-mode shebang, clear the startup
variables and say that root runs them by path.

The tests are not root: they export EUID and UID as 0 and assert the scripts still refuse, and
they assert the test hooks that exist only for non-root runs keep working with a spoofed value.
"""
import os
import re
import stat
import subprocess

import pytest

from conftest import REPO_ROOT
# Fixtures and helpers of the render script tests (the render fixture builds a hermetic tree).
from test_prometheus_otlp import render, ready, own, BASH  # noqa: F401

SCRIPTS = REPO_ROOT / "scripts"
NAMES = ["render-prometheus-web-config.sh", "02-bootstrap.sh", "01-disk-setup.sh"]
SPOOF = {"EUID": "0", "UID": "0"}

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="the spoof needs a non-root caller")


def _code(name):
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.parametrize("name", NAMES)
def test_script_never_reads_euid_or_uid(name):
    code = "\n".join(_code(name))
    assert not re.search(r"\b(EUID|UID)\b", code), f"{name} reads EUID or UID"


@pytest.mark.parametrize("name", NAMES)
def test_script_uses_the_privileged_shebang_and_clears_startup_variables(name):
    text = (SCRIPTS / name).read_text(encoding="utf-8")
    assert text.startswith("#!/bin/bash -p\n")
    code = "\n".join(_code(name))
    assert re.search(r"^set \+x$", code, re.M)
    assert re.search(r"^unset BASH_ENV ENV CDPATH GLOBIGNORE PS4$", code, re.M)
    assert "/usr/bin/id -u" in code
    assert "by its path" in text.replace("\n# ", " ")


@pytest.mark.parametrize("name", NAMES)
def test_script_refuses_root_run_with_privileged_mode_off(name):
    code = "\n".join(_code(name))
    assert re.search(r'"\$-" == \*p\*', code), f"{name} does not check privileged mode as root"


def _stub_dir(tmp_path, names):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    marker = tmp_path / "marker"
    for n in names:
        p = stubs / n
        p.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
        p.chmod(stat.S_IRWXU)
    return stubs, marker


@pytest.mark.parametrize("name,tools", [
    ("02-bootstrap.sh", ["apt", "apt-get", "sysctl", "systemctl", "ufw", "curl"]),
    ("01-disk-setup.sh", ["lsblk", "wipefs", "sgdisk", "parted", "mkfs.xfs", "mkfs.ext4", "mount", "partprobe"]),
])
def test_exported_euid_zero_does_not_make_a_normal_user_root(tmp_path, name, tools):
    stubs, marker = _stub_dir(tmp_path, tools)
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "HOME": str(tmp_path), **SPOOF}
    proc = subprocess.run([str(SCRIPTS / name)], env=env, text=True, capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=30, cwd=tmp_path)
    assert proc.returncode != 0
    assert "Must run as root" in proc.stdout + proc.stderr
    assert not marker.exists(), "a privileged step ran for a spoofed root"


def test_render_exported_euid_zero_still_refuses_to_write_a_readable_secret(render):
    proc = render(**SPOOF)  # the default container user is not us, so it must stop
    assert proc.returncode != 0 and "refusing" in proc.stderr
    assert not render.out.exists() and not render.main.exists()


def test_render_spoofed_euid_does_not_change_the_unprivileged_test_hooks(ready):
    # As a real non-root run the stage base override and the caller's PATH (for the htpasswd stub)
    # stay in force; the old code read EUID, saw "root", fixed PATH and used /run instead.
    proc = ready(PROMETHEUS_FILE_UID=str(os.geteuid()), **SPOOF)
    assert proc.returncode == 0, proc.stderr


def test_render_spoofed_euid_cannot_skip_the_trusted_tree_check_for_real_root():
    code = "\n".join(_code("render-prometheus-web-config.sh"))
    # every root decision uses the one value taken from the kernel
    assert "$(id -u)" not in code and "$EUID" not in code


DOCS = ["README.md", "docs/phase-f-testing.md", ".env.example", "scripts/03-deploy.sh",
        "scripts/02-bootstrap.sh", "docs/prometheus-otlp.md"]


@pytest.mark.parametrize("doc", DOCS)
def test_docs_run_these_scripts_by_path_not_as_bash_script(doc):
    text = (REPO_ROOT / doc).read_text(encoding="utf-8")
    bad = re.findall(r"bash (?:\./)?scripts/(?:01-disk-setup|02-bootstrap|render-prometheus-web-config)\.sh", text)
    assert not bad, f"{doc} still tells people to run a privileged script as 'bash script': {bad}"
