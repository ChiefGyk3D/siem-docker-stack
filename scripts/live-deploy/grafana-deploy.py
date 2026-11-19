#!/usr/bin/env python3
"""Additive Grafana deploy for the update-pending alerts. Runs on the SIEM host
under siem-run, so GRAFANA_WEBHOOK_SECRET is in the environment for the compose
call. It never prints a value.

Changes (nothing existing is overwritten):
  1. New folder grafana/provisioning/alerting with the contact point, the UniFi
     rules and the (paused) pfSense rules. The contact point URL gets the private
     webhook path of the new authenticated n8n router.
  2. New datasource file with two extra InfluxDB datasources carrying the ids the
     rules expect (same databases, no change to the existing datasources).
  3. One pass-through line in the grafana service of the live compose file
     (backup first), then only the grafana container is recreated.

Usage: siem-run python3 -I grafana-deploy.py --stage | --apply

Environment (all optional, the current values are the defaults):
  SIEM_DIR            directory of the live stack and its compose file (default: /opt/siem)
  SIEM_STAGE_DIR      directory holding the staged alerting files, copied from
                      docker/grafana/provisioning/alerting in this repo
                      (default: $HOME/bin/alerting)
  SIEM_CONFIG_DIR     private config directory with the file "router-path"
                      (default: $HOME/.config/doppler-siem)
  GRAFANA_SERVICE     compose service to recreate (default: grafana)
  N8N_WEBHOOK_BASE    base of the contact point URL, up to /webhook/ (default: http://n8n)
  INFLUX_URL          URL the two added datasources use (default: http://influxdb:8086).
                      Set it to the real InfluxDB container address if another stack's
                      service named influxdb makes the name ambiguous (see the runbook).
"""
import datetime
import os
import shutil
import subprocess
import sys

SIEM = os.environ.get("SIEM_DIR", "/opt/siem")
STAGE = os.environ.get("SIEM_STAGE_DIR") or os.path.join(os.path.expanduser("~"), "bin", "alerting")
CONFIG_DIR = os.environ.get("SIEM_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".config", "doppler-siem")
PATH_FILE = os.path.join(CONFIG_DIR, "router-path")
SERVICE = os.environ.get("GRAFANA_SERVICE", "grafana")
WEBHOOK_BASE = os.environ.get("N8N_WEBHOOK_BASE", "http://n8n").rstrip("/")
INFLUX_URL = os.environ.get("INFLUX_URL", "http://influxdb:8086")
ALERT_DIR = SIEM + "/grafana/provisioning/alerting"
DS_FILE = SIEM + "/grafana/provisioning/datasources/alerting-influx.yml"
COMPOSE = SIEM + "/docker-compose.yml"
FILES = ("contact-points.yml", "update-alert-rules-unifi.yml", "update-alert-rules-pfsense.yml",
         "heartbeat-alert-rule.yml")
OLD_URL = "http://n8n/webhook/grafana-alerts"
ANCHOR = "      - GF_SERVER_ROOT_URL="
PASS_LINE = "      - GRAFANA_WEBHOOK_SECRET\n"

DATASOURCES = """apiVersion: 1

# Extra InfluxDB datasources for the update alert rules. They carry fixed ids so
# the provisioned rules can find them. The existing datasources are untouched.
datasources:
  - name: InfluxDB-pfSense-alerts
    uid: influxdb-pfsense
    type: influxdb
    access: proxy
    url: {url}
    database: pfsense
    jsonData:
      httpMode: GET

  - name: InfluxDB-UniFi-alerts
    uid: influxdb-unifi
    type: influxdb
    access: proxy
    url: {url}
    database: unpoller
    jsonData:
      httpMode: GET
"""


# ---- pure logic (importable, no docker, no files) -------------------------------

def datasources_yaml(url=None):
    """Content of the extra-datasources provisioning file."""
    return DATASOURCES.format(url=url or INFLUX_URL)


def valid_router_path(path):
    return path.startswith("grafana-alerts-") and len(path) >= 20


def contact_with_path(contact_text, path, base=None):
    """Point the staged contact point at the private webhook path."""
    if OLD_URL not in contact_text:
        raise ValueError("contact point URL not found in the staged file")
    return contact_text.replace(OLD_URL, (base or WEBHOOK_BASE).rstrip("/") + "/webhook/" + path)


def compose_edit(text):
    """Plan the one-line compose edit. Returns (new_text or None, note).

    None means nothing to do (the line is already there). Refuses, with ValueError,
    when the anchor line is missing or appears more than once."""
    lines = text.splitlines(keepends=True)
    if any(line.rstrip("\n") == PASS_LINE.rstrip("\n") for line in lines):
        return None, "already present"
    hits = [i for i, line in enumerate(lines) if line.startswith(ANCHOR)]
    if len(hits) != 1:
        raise ValueError("expected exactly one GF_SERVER_ROOT_URL line, found %d" % len(hits))
    new = list(lines)
    new.insert(hits[0] + 1, PASS_LINE)
    return "".join(new), "insert after line %d" % (hits[0] + 1)


# ---- command line ----------------------------------------------------------------

def stage():
    with open(PATH_FILE, encoding="utf-8") as handle:
        path = handle.read().strip()
    if not valid_router_path(path):
        sys.exit("router path file looks wrong")
    for name in FILES:
        if not os.path.isfile(os.path.join(STAGE, name)):
            sys.exit("missing staged file: " + name)
    with open(os.path.join(STAGE, "contact-points.yml"), encoding="utf-8") as handle:
        contact = handle.read()
    try:
        return path, contact_with_path(contact, path)
    except ValueError as err:
        sys.exit(str(err))


def compose_plan():
    with open(COMPOSE, encoding="utf-8") as handle:
        text = handle.read()
    try:
        new, note = compose_edit(text)
    except ValueError as err:
        sys.exit(str(err))
    return text, new, note


def main(argv):
    path, contact = stage()
    _old, new_compose, note = compose_plan()
    print("staged files ok; router path length %d; compose: %s" % (len(path), note))
    if argv[:1] == ["--stage"]:
        return 0
    if argv[:1] != ["--apply"]:
        sys.exit(__doc__)
    if not os.environ.get("GRAFANA_WEBHOOK_SECRET"):
        sys.exit("missing environment value: GRAFANA_WEBHOOK_SECRET")

    os.makedirs(ALERT_DIR, exist_ok=True)
    for name in FILES:
        target = os.path.join(ALERT_DIR, name)
        if name == "contact-points.yml":
            data = contact
        else:
            with open(os.path.join(STAGE, name), encoding="utf-8") as handle:
                data = handle.read()
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(data)
        os.chmod(target, 0o644)
    with open(DS_FILE, "w", encoding="utf-8") as handle:
        handle.write(datasources_yaml())
    os.chmod(DS_FILE, 0o644)
    print("provisioning files written")

    if new_compose is not None:
        stamp = datetime.date.today().isoformat()
        shutil.copy2(COMPOSE, COMPOSE + ".bak-" + stamp)
        with open(COMPOSE, "w", encoding="utf-8") as handle:
            handle.write(new_compose)
        print("compose edited, backup saved as docker-compose.yml.bak-" + stamp)

    proc = subprocess.run(
        ["docker", "compose", "-f", COMPOSE, "up", "-d", SERVICE],
        cwd=SIEM, capture_output=True, check=False,
    )
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    for ln in [ln for ln in out.splitlines() if ln.strip()][-8:]:
        print(ln[:160])
    print("compose up exit code:", proc.returncode)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
