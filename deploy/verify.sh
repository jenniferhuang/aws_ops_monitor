#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 [--revision <40-char-sha>] [--wait-seconds <seconds>]" >&2
}

revision=
wait_seconds=0
while (($#)); do
  case "$1" in
    --revision)
      revision=${2:-}
      shift 2
      ;;
    --wait-seconds)
      wait_seconds=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo 'verify.sh must run as root.' >&2
  exit 1
fi
if [[ ${AWS_OPS_LOCK_HELD:-0} != 1 ]]; then
  install -d -o root -g root -m 0755 /run/lock
  exec 9>/run/lock/aws-ops-monitor.lock
  if ! flock -n 9; then
    echo 'Another AWS Ops Monitor operation is active.' >&2
    exit 1
  fi
fi
if [[ -n $revision && ! $revision =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Revision must be an exact lowercase 40-character Git SHA.' >&2
  exit 2
fi
if [[ ! $wait_seconds =~ ^[0-9]+$ || $wait_seconds -gt 600 ]]; then
  echo 'wait-seconds must be an integer between 0 and 600.' >&2
  exit 2
fi

actual_revision=
if [[ -L /opt/aws-ops-monitor/current ]]; then
  actual_revision=$(basename -- "$(readlink -f /opt/aws-ops-monitor/current)")
fi
if [[ ! $actual_revision =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Current release symlink is invalid.' >&2
  exit 1
fi
if [[ -n $revision && $actual_revision != "$revision" ]]; then
  echo "Revision mismatch: expected $revision, found $actual_revision." >&2
  exit 1
fi
release_dir=/opt/aws-ops-monitor/releases/$actual_revision
[[ -f $release_dir/REVISION && -f $release_dir/TREE_SHA256 ]]
[[ $(tr -d '\r\n' <"$release_dir/REVISION") == "$actual_revision" ]]
tree_sha256=$(tr -d '\r\n' <"$release_dir/TREE_SHA256")
[[ $tree_sha256 =~ ^[0-9a-f]{64}$ ]]
[[ $(python3 "$release_dir/deploy/tree-hash.py" "$release_dir") == "$tree_sha256" ]]
cmp -s "$release_dir/deploy/aws-ops-monitor-collector.service" \
  /etc/systemd/system/aws-ops-monitor-collector.service
cmp -s "$release_dir/deploy/aws-ops-monitor-web.service" \
  /etc/systemd/system/aws-ops-monitor-web.service

systemctl is-active --quiet aws-ops-monitor-collector.service
systemctl is-active --quiet aws-ops-monitor-web.service
[[ $(systemctl show -P User aws-ops-monitor-collector.service) == awsops-collector ]]
[[ $(systemctl show -P User aws-ops-monitor-web.service) == awsops-web ]]

if id -nG awsops-web | tr ' ' '\n' | grep -Fxq docker; then
  echo 'Web user must not belong to the Docker group.' >&2
  exit 1
fi
id -nG awsops-collector | tr ' ' '\n' | grep -Fxq docker

for secret in /etc/aws-ops-monitor/xray-user-hash.key /etc/aws-ops-monitor/web-password; do
  [[ -f $secret ]]
  [[ $(stat -c '%a' "$secret") == 600 ]]
done
[[ $(stat -c '%a' /var/lib/aws-ops-monitor/metrics.sqlite3) == 640 ]]

VERIFY_WAIT_SECONDS=$wait_seconds python3 - <<'PY'
import json
import os
from pathlib import Path
import sqlite3
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

wait_seconds = int(os.environ["VERIFY_WAIT_SECONDS"])
database = Path("/var/lib/aws-ops-monitor/metrics.sqlite3")

def newest_sample() -> float:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        row = connection.execute(
            """
            SELECT MAX(observed_at) FROM (
              SELECT observed_at FROM gauge_samples
              UNION ALL SELECT observed_at FROM counter_samples
              UNION ALL SELECT observed_at FROM health_samples
            )
            """
        ).fetchone()
        negative = connection.execute(
            "SELECT COUNT(*) FROM counter_samples WHERE delta_value < 0"
        ).fetchone()[0]
        if negative:
            raise SystemExit("negative counter delta found")
        return float(row[0]) if row and row[0] is not None else 0.0
    finally:
        connection.close()

initial_deadline = time.monotonic() + 60
before = newest_sample()
while before <= 0 and time.monotonic() < initial_deadline:
    # A new database is created before the first host/Xray/network/AWS probe
    # transaction commits.  Give that bounded first cycle time to finish.
    time.sleep(0.5)
    before = newest_sample()
if before <= 0:
    raise SystemExit("monitor database has no samples")
if time.time() - before > 180:
    raise SystemExit("collector sample is stale")

if wait_seconds:
    time.sleep(wait_seconds)
    after = newest_sample()
    if after <= before:
        raise SystemExit("collector did not advance during observation window")

health = Request("http://127.0.0.1:8787/healthz")
with urlopen(health, timeout=3) as response:
    if response.status != 200 or json.load(response) != {"status": "ok"}:
        raise SystemExit("dashboard health response is invalid")

try:
    urlopen(Request("http://127.0.0.1:8787/api/overview"), timeout=3)
except HTTPError as error:
    try:
        if error.code != 401:
            raise SystemExit("dashboard did not require authentication")
    finally:
        error.close()
else:
    raise SystemExit("dashboard API allowed an anonymous request")

username = "monitor"
for line in Path("/etc/aws-ops-monitor/web.env").read_text().splitlines():
    if line.startswith("AWS_OPS_USERNAME="):
        username = line.split("=", 1)[1]
password = Path("/etc/aws-ops-monitor/web-password").read_text().strip()
import base64
credential = base64.b64encode(f"{username}:{password}".encode()).decode()
request = Request(
    "http://127.0.0.1:8787/api/overview",
    headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
)
with urlopen(request, timeout=3) as response:
    payload = json.load(response)
    if response.status != 200 or not payload.get("collected_at"):
        raise SystemExit("authenticated dashboard overview is invalid")
    serialized = json.dumps(payload).lower()
    forbidden = ("privatekey", "password", "credential", "client_uuid", "akia")
    if any(value in serialized for value in forbidden):
        raise SystemExit("dashboard response contains a forbidden field")
PY

python3 - <<'PY'
import subprocess

result = subprocess.run(
    ["ss", "-H", "-lnt"], check=True, capture_output=True, text=True
)
loopback_monitor = False
for line in result.stdout.splitlines():
    fields = line.split()
    if len(fields) < 4:
        continue
    address = fields[3]
    if address.endswith(":8787"):
        if address in {"127.0.0.1:8787", "[::1]:8787"}:
            loopback_monitor = True
        else:
            raise SystemExit("dashboard is listening beyond loopback")
    if address.endswith(":10084") and address not in {
        "127.0.0.1:10084",
        "[::1]:10084",
    }:
        raise SystemExit("Xray API is listening beyond loopback")
    if any(address.endswith(f":{port}") for port in (3000, 9090, 9091, 9100)):
        raise SystemExit("an unapproved monitoring port is listening")
if not loopback_monitor:
    raise SystemExit("loopback dashboard listener is missing")
PY

[[ $(docker inspect --format '{{.State.Running}}' xray) == true ]]
systemctl is-active --quiet aws-ops-monitor-collector.service
systemctl is-active --quiet aws-ops-monitor-web.service

echo "Verified AWS Ops Monitor revision $actual_revision."
