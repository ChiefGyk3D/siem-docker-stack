"""The root-hardening tests need `unshare -r`. The hosted Ubuntu 24.04 runner restricts
unprivileged user namespaces with AppArmor, so CI must lift that restriction (the runner
is ephemeral) and prove it worked before pytest runs, or the tests fail loudly.
Only a CI run proves the sysctl works; this is a static check of the workflow text.
"""
from conftest import REPO_ROOT

CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SYSCTL = "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
SELF_CHECK = "unshare -r true"


def _command():
    text = CI.read_text(encoding="utf-8")
    return text.split("test-command: |", 1)[1]


def test_ci_lifts_the_userns_restriction_before_anything_else():
    command = _command()
    code = [ln.strip() for ln in command.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert code[0].startswith(SYSCTL), code[0]


def test_ci_checks_that_unshare_works_and_fails_the_step_if_not():
    command = _command()
    assert SELF_CHECK in command
    line = next(ln for ln in command.splitlines() if SELF_CHECK in ln and not ln.strip().startswith("#"))
    assert "exit 1" in line or "||" in line
    assert command.index(SYSCTL) < command.index(SELF_CHECK) < command.index("pytest")


def test_the_loud_skip_helper_still_fails_under_ci():
    text = (REPO_ROOT / "tests" / "python" / "conftest.py").read_text(encoding="utf-8")
    assert 'env.get("CI")' in text and "pytest.fail" in text
