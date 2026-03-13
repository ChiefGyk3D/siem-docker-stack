# Copyright (C) 2015, Wazuh Inc.
# Modified with SQLite caching layer — reduces VT API usage by caching
# hash lookup results with configurable TTL per verdict type.
#
# Original: /var/ossec/integrations/virustotal.py from wazuh-manager image.
# Cache DB: /var/ossec/integrations/cache/vt_cache.db (bind-mounted volume)
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import re
import sqlite3
import sys
import time
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_VT = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
    from requests.exceptions import Timeout
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# Global vars
debug_enabled = False
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}

# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# Cache configuration
CACHE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cache')
CACHE_DB = os.path.join(CACHE_DIR, 'vt_cache.db')

# TTL per verdict (seconds)
# clean=7d, detected=30d, suspicious=1d, unknown=6h, error=10m, not_found=1d
TTL_MAP = {
    'clean': 604800,
    'detected': 2592000,
    'suspicious': 86400,
    'unknown': 21600,
    'error': 600,
    'not_found': 86400,
}

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7


# ── Cache layer ──────────────────────────────────────────────────────────────

def cache_init():
    """Ensure cache directory and SQLite schema exist."""
    if not os.path.isdir(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR, mode=0o750, exist_ok=True)
        except OSError as e:
            debug(f'# Cache: could not create dir {CACHE_DIR}: {e}')
            return
    try:
        conn = sqlite3.connect(CACHE_DB, timeout=5)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA busy_timeout=5000')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS hash_lookup (
                hash            TEXT PRIMARY KEY,
                hash_type       TEXT NOT NULL,
                vt_result       TEXT NOT NULL,
                verdict         TEXT NOT NULL,
                ttl_seconds     INTEGER NOT NULL,
                status_code     INTEGER,
                cached_at       TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at      TEXT NOT NULL,
                last_accessed_at TEXT,
                hit_count       INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_expires
            ON hash_lookup(expires_at)
        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        debug(f'# Cache: init error: {e}')


def cache_lookup(hash_value):
    """Return cached VT JSON response if present and not expired, else None."""
    try:
        conn = sqlite3.connect(CACHE_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT vt_result, verdict FROM hash_lookup "
            "WHERE hash = ? AND datetime(expires_at) > datetime('now')",
            (hash_value,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE hash_lookup SET hit_count = hit_count + 1, "
                "last_accessed_at = datetime('now') WHERE hash = ?",
                (hash_value,)
            )
            conn.commit()
            conn.close()
            debug(f'# Cache HIT for {hash_value} (verdict={row["verdict"]})')
            return json.loads(row['vt_result'])
        conn.close()
    except (sqlite3.Error, json.JSONDecodeError) as e:
        debug(f'# Cache: lookup error: {e}')
    debug(f'# Cache MISS for {hash_value}')
    return None


def cache_store(hash_value, vt_json, status_code):
    """Store a VT API response in the cache with verdict-based TTL."""
    verdict = classify_verdict(vt_json, status_code)
    ttl = TTL_MAP.get(verdict, TTL_MAP['unknown'])
    try:
        payload = json.dumps(vt_json)
        conn = sqlite3.connect(CACHE_DB, timeout=5)
        conn.execute(
            "INSERT INTO hash_lookup "
            "(hash, hash_type, vt_result, verdict, ttl_seconds, status_code, "
            " cached_at, expires_at, last_accessed_at, hit_count) "
            "VALUES (?, 'md5', ?, ?, ?, ?, datetime('now'), "
            "        datetime('now', '+' || ? || ' seconds'), "
            "        datetime('now'), 0) "
            "ON CONFLICT(hash) DO UPDATE SET "
            "  vt_result=excluded.vt_result, verdict=excluded.verdict, "
            "  ttl_seconds=excluded.ttl_seconds, status_code=excluded.status_code, "
            "  cached_at=excluded.cached_at, expires_at=excluded.expires_at, "
            "  updated_at=datetime('now')",
            (hash_value, payload, verdict, ttl, status_code, ttl)
        )
        conn.commit()
        conn.close()
        debug(f'# Cache STORE {hash_value} verdict={verdict} ttl={ttl}s')
    except sqlite3.Error as e:
        debug(f'# Cache: store error: {e}')


def cache_maintenance():
    """Purge expired rows. Called opportunistically (1-in-100 chance)."""
    import random
    if random.randint(1, 100) != 1:
        return
    try:
        conn = sqlite3.connect(CACHE_DB, timeout=5)
        deleted = conn.execute(
            "DELETE FROM hash_lookup WHERE datetime(expires_at) <= datetime('now')"
        ).rowcount
        conn.commit()
        conn.close()
        if deleted:
            debug(f'# Cache: purged {deleted} expired rows')
    except sqlite3.Error as e:
        debug(f'# Cache: maintenance error: {e}')


def classify_verdict(vt_json, status_code):
    """Map VT API response to a verdict category for TTL selection."""
    if status_code != 200:
        if status_code == 404 or (isinstance(vt_json, dict) and
                                   vt_json.get('response_code') == 0):
            return 'not_found'
        return 'error'

    if not isinstance(vt_json, dict):
        return 'unknown'

    response_code = vt_json.get('response_code', -1)
    if response_code == 0:
        return 'not_found'
    if response_code != 1:
        return 'unknown'

    positives = vt_json.get('positives', 0)
    total = vt_json.get('total', 0)

    if total == 0:
        return 'unknown'
    if positives == 0:
        return 'clean'

    ratio = positives / total
    if ratio >= 0.1:
        return 'detected'
    return 'suspicious'


# ── Original Wazuh integration (with cache integration) ─────────────────────

def main(args):
    global debug_enabled
    global timeout
    global retries
    try:
        bad_arguments: bool = False
        msg = ''
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == 'debug'
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            msg = '# Error: Wrong arguments\n'
            bad_arguments = True

        with open(LOG_FILE, 'a') as f:
            f.write(msg)

        if bad_arguments:
            debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Initialize cache on first run
        cache_init()

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    debug('# Running VirusTotal script (cached)')

    alert_file_location: str = args[ALERT_INDEX]
    apikey: str = args[APIKEY_INDEX]

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Requesting VirusTotal information')
    msg: any = request_virustotal_info(json_alert, apikey)

    if not msg:
        debug('# Error: Empty message')
        raise Exception

    send_msg(msg, json_alert['agent'])

    # Opportunistic cache cleanup
    cache_maintenance()


def debug(msg: str) -> None:
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def request_info_from_api(alert, alert_output, api_key):
    md5 = alert['syscheck']['md5_after']

    # ── Check cache first ──
    cached = cache_lookup(md5)
    if cached is not None:
        return cached

    # ── Cache miss — call VT API ──
    for attempt in range(retries + 1):
        try:
            vt_response_data = query_api(md5, api_key)
            # Store successful response in cache
            cache_store(md5, vt_response_data, 200)
            return vt_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_VT)

    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['virustotal']['error'] = 408
    alert_output['virustotal']['description'] = 'Error: API request timed out'
    # Cache the timeout as an error so we don't hammer VT
    cache_store(md5, {'error': 408, 'description': 'timeout'}, 408)
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_VT)


def request_virustotal_info(alert: any, apikey: str):
    alert_output = {'virustotal': {}, 'integration': 'virustotal'}

    if 'syscheck' not in alert:
        debug('# No syscheck block present in the alert')
        return None

    # Check for md5 hash
    if 'md5_after' not in alert['syscheck']:
        debug('# No md5_after hash in syscheck')
        return None

    # Validate MD5 format
    md5 = alert['syscheck']['md5_after']
    if not re.match(r'^[a-fA-F0-9]{32}$', md5):
        debug(f'# Invalid MD5 hash: {md5}')
        return None

    # Request info (checks cache, then API)
    vt_response_data = request_info_from_api(alert, alert_output, apikey)

    response_code = vt_response_data.get('response_code', -1)

    if response_code == 1:
        alert_output['virustotal']['found'] = 1
        alert_output['virustotal']['malicious'] = vt_response_data.get('positives', 0)
        alert_output['virustotal']['total'] = vt_response_data.get('total', 0)
        alert_output['virustotal']['sha1'] = vt_response_data.get('sha1', '')
        alert_output['virustotal']['scan_date'] = vt_response_data.get('scan_date', '')
        alert_output['virustotal']['permalink'] = vt_response_data.get('permalink', '')
        alert_output['virustotal']['source'] = {
            'alert_id': alert.get('id', ''),
            'file': alert['syscheck'].get('path', ''),
            'md5': md5,
        }

        # Build scanner result list
        if 'scans' in vt_response_data:
            positives = {
                k: v for k, v in vt_response_data['scans'].items()
                if v.get('detected')
            }
            if positives:
                alert_output['virustotal']['positives'] = list(positives.keys())

    elif response_code == 0:
        alert_output['virustotal']['found'] = 0
        alert_output['virustotal']['source'] = {
            'alert_id': alert.get('id', ''),
            'file': alert['syscheck'].get('path', ''),
            'md5': md5,
        }
    else:
        alert_output['virustotal']['found'] = 0
        alert_output['virustotal']['source'] = {
            'alert_id': alert.get('id', ''),
            'file': alert['syscheck'].get('path', ''),
            'md5': md5,
        }

    return alert_output


def query_api(hash: str, apikey: str) -> any:
    params = {'apikey': apikey, 'resource': hash}
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'gzip,  Python library-client-VirusTotal',
    }

    debug('# Querying VirusTotal API')
    response = requests.get(
        'https://www.virustotal.com/vtapi/v2/file/report',
        params=params,
        headers=headers,
        timeout=timeout,
    )

    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        alert_output = {}
        alert_output['virustotal'] = {}
        alert_output['integration'] = 'virustotal'

        if response.status_code == 204:
            # Rate limited — cache so we back off
            cache_store(hash, {'error': 204, 'description': 'rate_limited'}, 204)
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: Public API request rate limit reached'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal Public API request rate limit reached')
        elif response.status_code == 403:
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: Check credentials'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal credentials, required privileges error')
        else:
            cache_store(hash, {'error': response.status_code}, response.status_code)
            alert_output['virustotal']['error'] = response.status_code
            alert_output['virustotal']['description'] = 'Error: API request fail'
            send_msg(alert_output)
            raise Exception('# Error: VirusTotal API error %d' % response.status_code)


def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any'
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))

    debug('# Request result from VT server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)


def get_json_alert(file_location: str) -> any:
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)
