"""Shared helpers for the repo's Python tests."""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def skip_or_fail(reason, env=None):
    """A security-critical test cannot run here. Fail loudly when CI is set (a green CI
    must mean the test ran); otherwise skip with the reason printed."""
    import os
    import pytest

    env = os.environ if env is None else env
    if env.get("CI"):
        pytest.fail(f"required by CI but cannot run: {reason}", pytrace=False)
    pytest.skip(f"SECURITY TEST NOT RUN: {reason}")


def import_module_from_path(name: str, path: Path):
    """Import a module from an arbitrary file path (handles hyphenated names)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
