"""Tests for the SQLite TTL cache in wazuh/integrations/virustotal.py.

The integration is import-safe (network and socket I/O happen only inside
main()/process_args()); tests point CACHE_DIR/CACHE_DB at a temp directory.
"""
import sqlite3

import pytest

from conftest import REPO_ROOT, import_module_from_path

SCRIPT = REPO_ROOT / "wazuh" / "integrations" / "virustotal.py"


@pytest.fixture()
def vt(tmp_path, monkeypatch):
    """Import the integration with the cache DB redirected to a temp dir."""
    module = import_module_from_path("virustotal_test", SCRIPT)
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(module, "CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(module, "CACHE_DB", str(cache_dir / "vt_cache.db"))
    module.cache_init()
    return module


MD5 = "d41d8cd98f00b204e9800998ecf8427e"
CLEAN_RESPONSE = {"response_code": 1, "positives": 0, "total": 70}


def _expire(vt_module, hash_value, seconds_ago=1):
    """Force a cached row's expiry into the past."""
    conn = sqlite3.connect(vt_module.CACHE_DB)
    conn.execute(
        "UPDATE hash_lookup SET expires_at = datetime('now', ?) WHERE hash = ?",
        (f"-{seconds_ago} seconds", hash_value),
    )
    conn.commit()
    conn.close()


def test_cache_miss_when_empty(vt):
    assert vt.cache_lookup(MD5) is None


def test_cache_hit_within_ttl(vt):
    vt.cache_store(MD5, CLEAN_RESPONSE, 200)
    assert vt.cache_lookup(MD5) == CLEAN_RESPONSE


def test_cache_hit_increments_hit_count(vt):
    vt.cache_store(MD5, CLEAN_RESPONSE, 200)
    vt.cache_lookup(MD5)
    vt.cache_lookup(MD5)
    conn = sqlite3.connect(vt.CACHE_DB)
    (hits,) = conn.execute(
        "SELECT hit_count FROM hash_lookup WHERE hash = ?", (MD5,)
    ).fetchone()
    conn.close()
    assert hits == 2


def test_cache_miss_after_expiry(vt):
    vt.cache_store(MD5, CLEAN_RESPONSE, 200)
    _expire(vt, MD5)
    assert vt.cache_lookup(MD5) is None


def test_store_overwrites_existing_entry(vt):
    vt.cache_store(MD5, CLEAN_RESPONSE, 200)
    detected = {"response_code": 1, "positives": 40, "total": 70}
    vt.cache_store(MD5, detected, 200)
    assert vt.cache_lookup(MD5) == detected


@pytest.mark.parametrize(
    "response, status, verdict",
    [
        (CLEAN_RESPONSE, 200, "clean"),
        ({"response_code": 1, "positives": 40, "total": 70}, 200, "detected"),
        ({"response_code": 1, "positives": 1, "total": 70}, 200, "suspicious"),
        ({"response_code": 0}, 200, "not_found"),
        ({"response_code": 0}, 404, "not_found"),
        ({"response_code": 2}, 200, "unknown"),
        ({"error": 500}, 500, "error"),
    ],
)
def test_classify_verdict(vt, response, status, verdict):
    assert vt.classify_verdict(response, status) == verdict


def test_distinct_verdict_ttls_are_stored(vt):
    cases = {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": (CLEAN_RESPONSE, 200, "clean"),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": (
            {"response_code": 1, "positives": 40, "total": 70}, 200, "detected"),
        "cccccccccccccccccccccccccccccccc": (
            {"response_code": 1, "positives": 1, "total": 70}, 200, "suspicious"),
        "dddddddddddddddddddddddddddddddd": ({"error": 500}, 500, "error"),
    }
    for hash_value, (response, status, _) in cases.items():
        vt.cache_store(hash_value, response, status)

    conn = sqlite3.connect(vt.CACHE_DB)
    for hash_value, (_, _, verdict) in cases.items():
        row = conn.execute(
            "SELECT verdict, ttl_seconds FROM hash_lookup WHERE hash = ?",
            (hash_value,),
        ).fetchone()
        assert row is not None, hash_value
        assert row[0] == verdict
        assert row[1] == vt.TTL_MAP[verdict]
    conn.close()

    # The TTLs themselves are distinct per verdict category.
    ttls = [vt.TTL_MAP[v] for v in ("clean", "detected", "suspicious", "error")]
    assert len(set(ttls)) == len(ttls)


def test_error_ttl_shorter_than_verdict_ttls(vt):
    # Errors must expire quickly so real lookups retry soon.
    assert vt.TTL_MAP["error"] < min(
        vt.TTL_MAP[v] for v in ("clean", "detected", "suspicious", "not_found")
    )
