"""Shared helpers for the repo's Python tests."""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def import_module_from_path(name: str, path: Path):
    """Import a module from an arbitrary file path (handles hyphenated names)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
