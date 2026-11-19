#!/usr/bin/env python3
"""Credential and key expiry watch (issue #76, slice 1).

Reads items from providers (a registry file, a TLS probe), decides which notices are due
(thresholds, then daily, then expired, each threshold once), and posts each notice to the
n8n alert router in the Grafana webhook shape. Python 3.11+ standard library only.

Usage:
    python3 scripts/expiry_watch.py --config expiry-watch.toml [--dry-run]

Exit codes: 0 ok, 1 a provider or a delivery failed (details on stderr), 2 config or
secret problem. See docs/expiry-watch.md.

The router bearer secret is read from the environment variable named in the config. It
is never read from a file, never printed and never included in an error message.
"""
import argparse
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

MAX_FILE_BYTES = 1024 * 1024
MAX_ITEMS = 1000
MAX_THRESHOLDS = 20
MAX_ADDRESSES = 4
MAX_DAYS = 3650
UTC = dt.timezone.utc
KNOWN_CHANNELS = ("pushover", "discord", "matrix", "email", "webhook")
# Channels the n8n router can deliver today. matrix and email are the next slice.
BUILT_CHANNELS = ("pushover", "discord", "webhook")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN = re.compile(r"[\x21-\x7e]{1,512}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ExpiryWatchError(Exception):
    """A problem the operator must see: bad config, bad input, failed provider or delivery."""


class FileMissing(ExpiryWatchError):
    """A file that does not exist (the state file may legitimately be missing)."""


# --- bounded file reads ----------------------------------------------------------------

class Root:
    """A directory opened ONCE and kept open. Relative reads and writes go through this
    descriptor, so retargeting a symbolic link that names the directory later changes
    nothing. The directory itself is resolved the normal way (it may be a link: it is the
    operator's own choice of location); everything below it is walked without links."""

    def __init__(self, path):
        try:
            self.fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError as e:
            raise ExpiryWatchError(f"cannot open the folder {path}: {e.strerror}") from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def split_raw_path(path):
    """Split a path string into components by looking at the RAW text (pathlib would
    normalize "." and doubled slashes away first). Returns (is_absolute, components)."""
    path = os.fspath(path)
    if not isinstance(path, str) or not path or chr(0) in path:
        raise ExpiryWatchError("a path must be a non-empty string")
    absolute = path.startswith("/")
    parts = (path[1:] if absolute else path).split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ExpiryWatchError(f"{path!r}: a path component may not be empty, . or .. "
                               "(no ./, ../, doubled or trailing slashes)")
    return absolute, parts


def _open_parent(path, root):
    """Walk to the directory that holds the last component of path, without following a
    symbolic link in any component. Returns (dirfd, leaf); the caller closes dirfd.
    A relative path is walked below `root` (a Root, or a path opened just for this call);
    an absolute path is walked from "/"."""
    absolute, parts = split_raw_path(path)
    if absolute:
        dirfd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    elif isinstance(root, Root):
        dirfd = os.dup(root.fd)
    else:
        own = Root(root if root is not None else ".")
        try:
            dirfd = os.dup(own.fd)
        finally:
            own.close()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | nofollow, dir_fd=dirfd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ExpiryWatchError(f"{path}: a symbolic link or a non-directory is in the path "
                                           f"({part}); symbolic links are refused") from None
                raise
            os.close(dirfd)
            dirfd = nxt
    except BaseException:
        os.close(dirfd)
        raise
    return dirfd, parts[-1]


def read_capped(path, label, root=None):
    """Read a regular file of at most MAX_FILE_BYTES.

    No component of the path below `root` (or of an absolute path) may be a symbolic link;
    FIFOs, devices and directories are refused as well.
    """
    try:
        dirfd, leaf = _open_parent(path, root)
        try:
            fd = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                         dir_fd=dirfd)
        finally:
            os.close(dirfd)
    except FileNotFoundError:
        raise FileMissing(f"{label}: file not found: {path}") from None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ExpiryWatchError(f"{label}: {path} is a symbolic link; symbolic links are refused") from None
        raise ExpiryWatchError(f"{label}: cannot read {path}: {e.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ExpiryWatchError(f"{label}: {path} is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise ExpiryWatchError(f"{label}: {path} is too large (limit {MAX_FILE_BYTES} bytes)")
    return data


def read_toml(path, label, root=None):
    data = read_capped(path, label, root)
    try:
        # tomllib rejects duplicate keys and tables itself.
        return tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ExpiryWatchError(f"{label}: TOML parse error in {path}: {e}") from None


# --- items ---------------------------------------------------------------------------------

def _text(label, value, max_len, required=True):
    if not isinstance(value, str):
        raise ExpiryWatchError(f"{label} must be a string")
    value = value.strip()
    if required and not value:
        raise ExpiryWatchError(f"{label} must not be empty")
    if len(value) > max_len:
        raise ExpiryWatchError(f"{label} is longer than {max_len} characters")
    if _CONTROL.search(value):
        raise ExpiryWatchError(f"{label} contains a control character")
    return value


def _date(label, value):
    if isinstance(value, dt.datetime):
        raise ExpiryWatchError(f"{label} must be a plain date (YYYY-MM-DD), not a date and time")
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and _ISO_DATE.fullmatch(value.strip()):
        try:
            return dt.date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise ExpiryWatchError(f"{label} must be a valid date (YYYY-MM-DD)")


def _runbook(value):
    value = _text("runbook", value, 512)
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or " " in value:
        raise ExpiryWatchError("runbook must be an http or https link")
    return value


@dataclass(frozen=True)
class Item:
    name: str
    kind: str
    expires: dt.date
    owner: str
    runbook: str

    @classmethod
    def build(cls, name, kind, expires, owner, runbook):
        """The one place item text is validated, so every provider gets the same limits."""
        return cls(name=_text("name", name, 100), kind=_text("kind", kind, 40), expires=_date("expires", expires),
                   owner=_text("owner", owner, 100), runbook=_runbook(runbook))


# --- providers: plug-ins behind one small interface ---------------------------------------------
#
# A provider is any object with `items() -> list[Item]` that raises ExpiryWatchError when it
# cannot read its source. It is created from its config table by a factory registered with
# register_provider(type_name, factory), where factory(config_dict) returns the provider.

PROVIDER_TYPES = {}


def register_provider(type_name, factory):
    if type_name in PROVIDER_TYPES:
        raise ExpiryWatchError(f"provider type already registered: {type_name}")
    PROVIDER_TYPES[type_name] = factory


def _only_keys(label, table, allowed):
    unknown = sorted(set(table) - set(allowed))
    if unknown:
        raise ExpiryWatchError(f"{label}: unknown field(s): {', '.join(map(str, unknown))}")


class RegistryProvider:
    """Items from a TOML registry file ([[item]] tables) for anything without an API."""

    FIELDS = ("name", "kind", "expires", "owner", "runbook")

    def __init__(self, config, base_dir="."):
        _only_keys("registry provider", config, ("type", "path", "_base_dir"))
        if "_base_dir" in config:  # set by run(): the config file's folder
            base_dir = config["_base_dir"]
        path = config.get("path")
        if not isinstance(path, str) or not path:
            raise ExpiryWatchError("registry provider: path is required")
        self.path, self.root = path, base_dir

    def items(self):
        doc = read_toml(self.path, "registry", self.root)
        _only_keys("registry", doc, ("item",))
        raw = doc.get("item")
        if not isinstance(raw, list) or not all(isinstance(t, dict) for t in raw):
            raise ExpiryWatchError("registry: item must be a list of [[item]] tables")
        if not raw:
            raise ExpiryWatchError("registry: no items found")
        if len(raw) > MAX_ITEMS:
            raise ExpiryWatchError(f"registry: too many items (limit {MAX_ITEMS})")
        items, seen = [], set()
        for n, table in enumerate(raw, 1):
            where = f"registry item {n}"
            _only_keys(where, table, self.FIELDS)
            missing = [f for f in self.FIELDS if f not in table]
            if missing:
                raise ExpiryWatchError(f"{where}: missing field(s): {', '.join(missing)}")
            try:
                item = Item.build(**{f: table[f] for f in self.FIELDS})
            except ExpiryWatchError as e:
                raise ExpiryWatchError(f"{where}: {e}") from None
            if item.name in seen:
                raise ExpiryWatchError(f"{where}: duplicate item name: {item.name}")
            seen.add(item.name)
            items.append(item)
        return items


def _der_read(buf, pos, limit, want=None):
    """Read one DER element at pos that must lie entirely inside buf[:limit].

    Returns (tag, content_start, content_end). Lengths must be minimal (canonical DER).
    """
    if pos + 2 > limit:
        raise ExpiryWatchError("certificate is truncated")
    tag = buf[pos]
    if want is not None and tag != want:
        raise ExpiryWatchError("certificate has an unexpected structure")
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + count > limit:
            raise ExpiryWatchError("certificate has an unsupported length encoding")
        length = int.from_bytes(buf[pos:pos + count], "big")
        if length < 0x80 or buf[pos] == 0:
            raise ExpiryWatchError("certificate has a non-canonical length encoding")
        pos += count
    if pos + length > limit:
        raise ExpiryWatchError("certificate has an element that runs past its enclosing structure")
    return tag, pos, pos + length


def _der_time(buf, tag, start, end):
    text = buf[start:end].decode("ascii", "replace")
    if tag == 0x17 and re.fullmatch(r"\d{12}Z", text):  # UTCTime, RFC 5280 pivot at 50
        yy = int(text[:2])
        text = ("19" if yy >= 50 else "20") + text
    elif not (tag == 0x18 and re.fullmatch(r"\d{14}Z", text)):  # GeneralizedTime
        raise ExpiryWatchError("certificate has an unreadable validity time")
    try:
        return dt.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise ExpiryWatchError("certificate has an invalid validity time") from None


def der_not_after(der):
    """notAfter of a DER X.509 certificate. Reads only the validity field; trusts nothing else.

    Every element must fit inside the structure that encloses it, the validity sequence
    must be consumed exactly by its two times, and nothing may follow the certificate.
    """
    _, cert_start, cert_end = _der_read(der, 0, len(der), 0x30)
    if cert_end != len(der):
        raise ExpiryWatchError("certificate has data after its end")
    _, pos, tbs_end = _der_read(der, cert_start, cert_end, 0x30)
    if pos < tbs_end and der[pos] == 0xA0:  # explicit version
        pos = _der_read(der, pos, tbs_end)[2]
    for _ in range(3):  # serial, signature algorithm, issuer
        pos = _der_read(der, pos, tbs_end)[2]
    _, v_start, v_end = _der_read(der, pos, tbs_end, 0x30)
    tag, s, e = _der_read(der, v_start, v_end)  # notBefore
    _der_time(der, tag, s, e)
    tag, s, e = _der_read(der, e, v_end)  # notAfter
    if e != v_end:
        raise ExpiryWatchError("certificate has an invalid validity field")
    return _der_time(der, tag, s, e)


class TlsProvider:
    """Expiry of the certificate a host presents on a port.

    By default the handshake VERIFIES the chain and the host name with the system trust
    store (or `ca_file`), so a peer that is not who it claims to be is an error, not a
    date. `verify = false` is for internal or self-signed certificates and for finding
    out when an already invalid certificate ended: it reads the date and nothing else,
    sends no application data, and its result must not be used as proof of identity.
    The date comes from the DER bytes of the peer certificate in both modes.
    """

    FIELDS = ("type", "host", "port", "name", "kind", "owner", "runbook", "verify", "ca_file",
              "server_name", "timeout_seconds", "_base_dir")

    def __init__(self, config):
        _only_keys("tls provider", config, self.FIELDS)
        host = config.get("host")
        if not isinstance(host, str) or not _HOST.fullmatch(host) and not _is_ip(host):
            raise ExpiryWatchError("tls provider: host must be a host name or an IP address")
        port = config.get("port", 443)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ExpiryWatchError("tls provider: port must be an integer from 1 to 65535")
        timeout = config.get("timeout_seconds", 10)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise ExpiryWatchError("tls provider: timeout_seconds must be above 0 and at most 60")
        self.verify = config.get("verify", True)
        if not isinstance(self.verify, bool):
            raise ExpiryWatchError("tls provider: verify must be true or false")
        self.ca_file = config.get("ca_file")
        if self.ca_file is not None and (not isinstance(self.ca_file, str) or not self.ca_file):
            raise ExpiryWatchError("tls provider: ca_file must be a path")
        self.root = config.get("_base_dir")
        self.server_name = config.get("server_name", host)
        if not isinstance(self.server_name, str) or not _HOST.fullmatch(self.server_name):
            raise ExpiryWatchError("tls provider: server_name must be a host name")
        self.host, self.port, self.timeout = host, port, float(timeout)
        self.template = dict(name=config.get("name", f"tls:{host}:{port}"), kind=config.get("kind", "tls-cert"),
                             owner=config.get("owner"), runbook=config.get("runbook"))
        Item.build(expires="2000-01-01", **self.template)  # validate the text fields now

    def _context(self):
        if not self.verify:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        if self.ca_file is None:
            return ssl.create_default_context()
        pem = read_capped(self.ca_file, "ca_file", self.root)  # same no-link rules as every other file
        try:
            return ssl.create_default_context(cadata=pem.decode("ascii"))
        except UnicodeDecodeError:
            return ssl.create_default_context(cadata=pem)

    def _probe(self, deadline):
        """The whole probe: resolve, connect, handshake. Runs in a worker thread (see items)."""
        def left():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("overall deadline reached")
            return remaining

        context = self._context()  # reads ca_file first: a bad file is reported without connecting
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)[:MAX_ADDRESSES]
        last = OSError("no address")
        for family, kind, proto, _, addr in infos:
            raw = socket.socket(family, kind, proto)
            try:
                raw.settimeout(left())
                raw.connect(addr)
                raw.settimeout(left())
                with context.wrap_socket(raw, server_hostname=self.server_name) as tls:
                    tls.settimeout(left())
                    return tls.getpeercert(binary_form=True)
            except ssl.SSLError:
                raise
            except OSError as e:
                last = e
            finally:
                raw.close()
        raise last

    def items(self):
        """Probe with ONE overall deadline of timeout_seconds, name resolution included.

        getaddrinfo cannot be interrupted, so the probe runs in a daemon worker thread and
        the caller stops waiting at the deadline. A resolver that never answers leaves one
        idle thread behind until the process ends (a cron job exits right away).
        """
        where = f"{self.host}:{self.port}"
        box = {}
        deadline = time.monotonic() + self.timeout

        def work():
            try:
                box["der"] = self._probe(deadline)
            except Exception as e:  # reported to the caller below; process-control exceptions pass through
                box["error"] = e

        worker = threading.Thread(target=work, daemon=True, name=f"expiry-probe-{where}")
        worker.start()
        worker.join(max(0.0, deadline - time.monotonic()))
        if worker.is_alive():
            raise ExpiryWatchError(f"tls probe of {where} failed: timed out (overall deadline {self.timeout:g}s)")
        err = box.get("error")
        if isinstance(err, TimeoutError) or isinstance(err, socket.timeout):
            raise ExpiryWatchError(f"tls probe of {where} failed: timed out (overall deadline {self.timeout:g}s)")
        if isinstance(err, (OSError, ssl.SSLError, ValueError)):
            raise ExpiryWatchError(f"tls probe of {where} failed: {err}") from None
        if err is not None:
            raise err
        der = box.get("der")
        if not der:
            raise ExpiryWatchError(f"tls probe of {where} failed: the peer sent no certificate")
        not_after = der_not_after(der)
        return [Item.build(expires=not_after.date(), **self.template)]


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


register_provider("registry", RegistryProvider)
register_provider("tls", TlsProvider)


# --- config -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class RouterConfig:
    url: str
    token_env: str
    timeout_seconds: float


@dataclass(frozen=True)
class Config:
    thresholds: tuple
    daily_below_days: int
    state_file: str
    router: RouterConfig
    routes: dict  # stage ("30", "daily", "expired") -> tuple of channel names
    providers: tuple  # raw provider tables


def check_router_url(url):
    if not isinstance(url, str) or len(url) > 512 or _CONTROL.search(url) or " " in url:
        raise ExpiryWatchError("router.url must be a link")
    p = urllib.parse.urlsplit(url)
    loopback = p.hostname in ("localhost",) or (p.hostname is not None and _is_ip(p.hostname)
                                                and ipaddress.ip_address(p.hostname).is_loopback)
    if not p.hostname or p.username or p.password:
        raise ExpiryWatchError("router.url must have a host and no credentials in it")
    if p.scheme != "https" and not (p.scheme == "http" and loopback):
        raise ExpiryWatchError("router.url must be https (plain http only for localhost)")
    return url


def _int(label, value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ExpiryWatchError(f"{label} must be an integer from {low} to {high}")
    return value


def parse_config(raw):
    if not isinstance(raw, dict):
        raise ExpiryWatchError("config must be a table")
    _only_keys("config", raw, ("watch", "router", "routes", "providers"))
    watch = raw.get("watch", {})
    if not isinstance(watch, dict):
        raise ExpiryWatchError("[watch] must be a table")
    _only_keys("[watch]", watch, ("thresholds_days", "daily_below_days", "state_file"))
    thresholds = watch.get("thresholds_days", [30, 14, 7])
    if not isinstance(thresholds, list) or not 1 <= len(thresholds) <= MAX_THRESHOLDS:
        raise ExpiryWatchError(f"thresholds_days must be a list of 1 to {MAX_THRESHOLDS} whole numbers")
    thresholds = [_int("thresholds_days entry", t, 1, MAX_DAYS) for t in thresholds]
    if len(set(thresholds)) != len(thresholds):
        raise ExpiryWatchError("thresholds_days must not repeat a value")
    daily = _int("daily_below_days", watch.get("daily_below_days", 7), 0, MAX_DAYS)
    state_file = watch.get("state_file", "expiry-watch-state.json")
    state_file = _text("state_file", state_file, 256)

    router = raw.get("router")
    if not isinstance(router, dict):
        raise ExpiryWatchError("[router] is required")
    _only_keys("[router]", router, ("url", "token_env", "timeout_seconds"))
    token_env = router.get("token_env")
    if not isinstance(token_env, str) or not _ENV_NAME.fullmatch(token_env):
        raise ExpiryWatchError("router.token_env must name an environment variable (the name, never the secret)")
    timeout = router.get("timeout_seconds", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise ExpiryWatchError("router.timeout_seconds must be above 0 and at most 60")

    stages = [str(t) for t in thresholds] + ["daily", "expired"]
    routes_raw = raw.get("routes", {})
    if not isinstance(routes_raw, dict):
        raise ExpiryWatchError("[routes] must be a table")
    _only_keys("[routes]", routes_raw, stages)
    routes = {}
    for stage in stages:
        chans = routes_raw.get(stage, ["discord"])
        if (not isinstance(chans, list) or len(chans) > len(KNOWN_CHANNELS)
                or any(c not in KNOWN_CHANNELS for c in chans) or len(set(chans)) != len(chans)):
            raise ExpiryWatchError(f"routes.{stage} must be a list of channels from: {', '.join(KNOWN_CHANNELS)}")
        routes[stage] = tuple(chans)

    providers = raw.get("providers", [])
    if not isinstance(providers, list) or not all(isinstance(p, dict) for p in providers) or len(providers) > 200:
        raise ExpiryWatchError("[[providers]] must be a list of up to 200 tables")
    for p in providers:
        if p.get("type") not in PROVIDER_TYPES:
            raise ExpiryWatchError(f"unknown provider type: {p.get('type')!r} (known: {', '.join(sorted(PROVIDER_TYPES))})")
    return Config(thresholds=tuple(sorted(thresholds, reverse=True)), daily_below_days=daily, state_file=state_file,
                  router=RouterConfig(check_router_url(router.get("url")), token_env, float(timeout)),
                  routes=routes, providers=tuple(providers))


def load_config(path):
    """Load a config by path. The folder is opened once; see Root."""
    folder, leaf = os.path.split(str(path))
    root = Root(folder or ".")
    try:
        return load_config_in(root, leaf)
    finally:
        root.close()


def load_config_in(root, leaf):
    if leaf in ("", ".", ".."):
        raise ExpiryWatchError("config: the path must name a file")
    return parse_config(read_toml(leaf, "config", root))


# --- the decision engine (pure) -----------------------------------------------------------------

@dataclass(frozen=True)
class Notice:
    item: Item
    stage: str  # a threshold in days ("14"), "daily" or "expired"
    days_left: int
    channels: tuple


def _fresh(expires):
    return {"expires": expires.isoformat(), "threshold": None, "daily": None, "expired": False}


def _reconcile(prev, item, days, today, config):
    """The state to trust for this item. The WHOLE entry must be consistent, or none of it
    is used and the item starts over ("nothing sent yet"), so a plausible field can never
    vouch for an invalid one.

    Consistent means: same expiry date as now (a changed date, later or earlier, starts
    over), a threshold that is None or a configured one the item has reached, a daily date
    that is not in the future, and an expired flag only once the expiry date is reached.
    A plausible forged entry cannot be told from a real one; the state file is trusted
    local data, protected by its file mode (see docs/expiry-watch.md).
    """
    fresh = _fresh(item.expires)
    try:
        if not isinstance(prev, dict) or dt.date.fromisoformat(prev["expires"]) != item.expires:
            return fresh
        threshold, daily, expired = prev["threshold"], prev["daily"], prev["expired"]
        threshold_ok = threshold is None or (isinstance(threshold, int) and not isinstance(threshold, bool)
                                             and threshold in config.thresholds and days <= threshold)
        daily_ok = daily is None or (isinstance(daily, str) and dt.date.fromisoformat(daily) <= today)
        expired_ok = isinstance(expired, bool) and (not expired or days <= 0)
    except (KeyError, TypeError, ValueError):
        return fresh
    if not (threshold_ok and daily_ok and expired_ok):
        return fresh
    return {"expires": item.expires.isoformat(), "threshold": threshold, "daily": daily, "expired": expired}


def decide(items, now, config, state):
    """Return (notices, new_state). Pure: no clock, no I/O, `state` is not modified.

    Per item: each threshold fires once (the lowest one already crossed, so a missed run
    does not replay the earlier ones), then one notice per UTC day while days left is at
    or below daily_below_days, then one expired notice. A different expiry date than the one
    last seen (rotated or moved up) and any inconsistent state entry start the item over.
    Items no longer supplied lose their state.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    today = now.astimezone(UTC).date()
    notices, new_state = [], {}
    for item in sorted(items, key=lambda i: i.name):
        days = (item.expires - today).days
        st = _reconcile(state.get(item.name), item, days, today, config)
        stage = None
        if days <= 0:
            if not st["expired"]:
                stage, st["expired"] = "expired", True
        else:
            crossed = [t for t in config.thresholds if days <= t]
            if crossed and (st["threshold"] is None or min(crossed) < st["threshold"]):
                stage, st["threshold"] = str(min(crossed)), min(crossed)
                if days <= config.daily_below_days:
                    st["daily"] = today.isoformat()
            elif days <= config.daily_below_days and st["daily"] != today.isoformat():
                stage, st["daily"] = "daily", today.isoformat()
        if stage:
            notices.append(Notice(item, stage, days, config.routes[stage]))
        new_state[item.name] = st
    return notices, new_state


# --- notifier: notice -> Grafana webhook JSON the n8n router accepts ------------------------------------

def _days_phrase(days):
    if days < 0:
        return f"expired {-days} day{'s' if days != -1 else ''} ago"
    if days == 0:
        return "expires today"
    return f"{days} day{'s' if days != 1 else ''} left"


def build_payload(notice, now):
    """The body the router's Normalize Alert node expects (status, alerts[0].labels/annotations)."""
    item, days = notice.item, notice.days_left
    if notice.stage == "expired":
        severity = "critical"
    elif days <= 14:
        severity = "warning"
    else:
        severity = "info"
    labels = {"alertname": f"Expiry watch: {item.name}"[:200], "severity": severity, "expiry_watch": "true",
              "item": item.name, "kind": item.kind, "stage": notice.stage}
    if "pushover" in notice.channels:
        labels["phone"] = "true"
    phrase = _days_phrase(days)
    description = (f"{item.name} ({item.kind}) {'expired' if days < 0 else 'expires'} on {item.expires.isoformat()}: "
                   f"{phrase}.\nOwner: {item.owner}\nRunbook: {item.runbook}")[:1000]
    summary = f"{item.name} ({item.kind}): {phrase}, date {item.expires.isoformat()}, owner {item.owner}"[:300]
    when = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    fingerprint = hashlib.sha256(f"expiry-watch|{item.name}".encode()).hexdigest()[:32]
    return {"receiver": "expiry-watch", "status": "firing", "alerts": [{
        "status": "firing", "labels": labels,
        "annotations": {"summary": summary, "description": description},
        "startsAt": when, "fingerprint": fingerprint}]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # never replay the bearer to another location


def post_json(url, token, payload, timeout, opener=None):
    check_router_url(url)
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ExpiryWatchError("the router secret is empty or contains characters not allowed in a header")
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    opener = opener or urllib.request.build_opener(_NoRedirect)
    host = urllib.parse.urlsplit(url).hostname
    try:
        with opener.open(req, timeout=timeout) as resp:
            resp.read(65536)
    except urllib.error.HTTPError as e:
        kind = "redirect refused" if 300 <= e.code < 400 else "rejected"
        raise ExpiryWatchError(f"router {host} {kind}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise ExpiryWatchError(f"router {host} unreachable: {getattr(e, 'reason', e)}") from None


# --- state file ----------------------------------------------------------------------------------

def load_state(path, root=None):
    """Load the state file (relative to root when given). A missing file is an empty state.

    Shape and types are checked here; whether the values make sense for an item is decided
    by decide(), which treats an inconsistent entry as "nothing sent yet".
    """
    try:
        data = read_capped(path, "state", root)
    except FileMissing:
        return {}
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ExpiryWatchError(f"state: {path} is not valid JSON: {e}") from None
    if not isinstance(doc, dict) or len(doc) > MAX_ITEMS * 4:
        raise ExpiryWatchError(f"state: {path} has an unexpected shape")
    for name, st in doc.items():
        ok = (isinstance(st, dict) and set(st) == {"expires", "threshold", "daily", "expired"}
              and isinstance(st["expired"], bool)
              and (st["threshold"] is None or (isinstance(st["threshold"], int) and not isinstance(st["threshold"], bool)))
              and isinstance(st["expires"], str) and _ISO_DATE.fullmatch(st["expires"])
              and (st["daily"] is None or (isinstance(st["daily"], str) and _ISO_DATE.fullmatch(st["daily"]))))
        if ok:
            try:
                dt.date.fromisoformat(st["expires"])
                if st["daily"]:
                    dt.date.fromisoformat(st["daily"])
            except ValueError:
                ok = False
        if not ok:
            raise ExpiryWatchError(f"state: {path} has a bad entry for {str(name)[:60]!r}")
    return doc


def save_state(path, state, root=None):
    """Write the state atomically and privately (0600). The temp file is created and renamed
    inside the held directory, so a link retargeted meanwhile cannot redirect the write."""
    dirfd, leaf = _open_parent(path, root)
    tmp = f".expiry-state-{os.getpid()}-{os.urandom(6).hex()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dirfd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fh.fileno(), 0o600)
                json.dump(state, fh, indent=1, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, leaf, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dirfd)
            except OSError:
                pass
            raise
    finally:
        os.close(dirfd)


# --- the runner -------------------------------------------------------------------------------------

def _keep_prior(new_state, state, name):
    """Undo one item's state change because its notice was not delivered."""
    if name in state:
        new_state[name] = state[name]
    else:
        new_state.pop(name, None)


def run(config_path, now, env=None, out=print, err=None, dry_run=False, opener=None):
    """One pass: collect, decide, deliver, save. Returns the process exit code.

    The config file's folder is opened once and held for the whole pass (config, registry,
    CA file, state read and state write), so the pass sees one consistent folder.
    """
    err = err or (lambda m: print(m, file=sys.stderr))
    folder, leaf = os.path.split(str(config_path))
    try:
        root = Root(folder or ".")
    except ExpiryWatchError as e:
        err(f"config error: {e}")
        return 2
    try:
        return _run_pass(root, leaf, now, os.environ if env is None else env, out, err, dry_run, opener)
    finally:
        root.close()


def _run_pass(root, leaf, now, env, out, err, dry_run, opener):
    try:
        config = load_config_in(root, leaf)
        providers = []
        for table in config.providers:
            table = dict(table)
            table["_base_dir"] = root  # injected: providers read their files through this held folder
            providers.append(PROVIDER_TYPES[table["type"]](table))
        state_path = config.state_file
        state = load_state(state_path, root)
    except ExpiryWatchError as e:
        err(f"config error: {e}")
        return 2

    failed = False
    items, seen = [], {}
    for prov in providers:
        label = type(prov).__name__
        try:
            for item in prov.items():
                if item.name in seen:
                    raise ExpiryWatchError(f"duplicate item name across providers: {item.name}")
                seen[item.name] = label
                items.append(item)
        except ExpiryWatchError as e:
            err(f"provider error ({label}): {e}")
            failed = True

    notices, new_state = decide(items, now, config, state)
    if failed:  # an outage must not make the watch forget what it already told you
        for name, st in state.items():
            new_state.setdefault(name, st)

    postable = [n for n in notices if set(n.channels) & set(BUILT_CHANNELS)]
    token = None
    if postable and not dry_run:
        token = env.get(config.router.token_env)
        if not token or not _TOKEN.fullmatch(token):
            err(f"config error: set the environment variable {config.router.token_env} to the router secret")
            return 2

    for n in notices:
        tag = f"{n.item.name} [{n.stage}] {_days_phrase(n.days_left)}"
        skipped = [c for c in n.channels if c not in BUILT_CHANNELS]
        if skipped:
            err(f"warning: channel(s) {', '.join(skipped)} are not built yet; no message sent for them ({tag})")
        if n not in postable:
            out(f"no deliverable channel: {tag}")
            _keep_prior(new_state, state, n.item.name)  # nothing was sent: the notice stays due
            continue
        payload = build_payload(n, now)
        if dry_run:
            out(f"dry run: would post {tag}\n{json.dumps(payload, indent=1)}")
            continue
        try:
            post_json(config.router.url, token, payload, config.router.timeout_seconds, opener)
            out(f"posted: {tag}")
        except ExpiryWatchError as e:
            err(f"delivery error: {tag}: {e}")
            failed = True
            _keep_prior(new_state, state, n.item.name)  # keep the notice due: retry on the next run

    if not dry_run:
        try:
            save_state(state_path, new_state, root)
        except OSError as e:
            err(f"state error: cannot write {state_path}: {e.strerror}")
            return 1
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Credential and key expiry watch")
    ap.add_argument("--config", required=True, help="path to the TOML config (see docs/expiry-watch.example.toml)")
    ap.add_argument("--dry-run", action="store_true", help="print what would be posted; post and save nothing")
    args = ap.parse_args(argv)
    return run(args.config, dt.datetime.now(UTC), dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
