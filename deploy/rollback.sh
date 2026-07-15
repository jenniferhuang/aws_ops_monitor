#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 [--revision <40-char-sha>] [--database-backup <file>] [--state-backup <dir>]" >&2
}

revision=
database_backup=
state_backup=
while (($#)); do
  case "$1" in
    --revision)
      revision=${2:-}
      shift 2
      ;;
    --database-backup)
      database_backup=${2:-}
      shift 2
      ;;
    --state-backup)
      state_backup=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo 'rollback.sh must run as root.' >&2
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
if [[ -z $revision && -s /var/lib/aws-ops-monitor/previous-release ]]; then
  revision=$(tr -d '\r\n' </var/lib/aws-ops-monitor/previous-release)
fi
if [[ ! $revision =~ ^[0-9a-f]{40}$ ]]; then
  echo 'No valid rollback revision is available.' >&2
  exit 2
fi
if [[ -n $state_backup && ( $state_backup != /* || ! -d $state_backup ) ]]; then
  echo 'State backup must be an existing absolute directory.' >&2
  exit 2
fi
if [[ -n $state_backup ]]; then
  for state_file in collector-enabled.txt web-enabled.txt collector-state.txt web-state.txt previous-release-presence.txt; do
    if [[ ! -f $state_backup/$state_file ]]; then
      echo "State backup is missing $state_file." >&2
      exit 2
    fi
  done
  previous_presence=$(tr -d '\r\n' <"$state_backup/previous-release-presence.txt")
  if [[ $previous_presence == present ]]; then
    if [[ ! -f $state_backup/previous-release.txt ]]; then
      echo 'State backup is missing previous-release.txt.' >&2
      exit 2
    fi
    backed_up_previous=$(tr -d '\r\n' <"$state_backup/previous-release.txt")
    if [[ ! $backed_up_previous =~ ^[0-9a-f]{40}$ ]]; then
      echo 'State backup contains an invalid previous release.' >&2
      exit 2
    fi
  elif [[ $previous_presence != absent ]]; then
    echo 'State backup contains an invalid previous-release presence marker.' >&2
    exit 2
  fi
fi

release_dir=/opt/aws-ops-monitor/releases/$revision
if [[ ! -d $release_dir ]]; then
  echo "Rollback release is missing: $release_dir" >&2
  exit 1
fi
if [[ ! -f $release_dir/REVISION || ! -f $release_dir/TREE_SHA256 ]]; then
  echo 'Rollback release is missing its signed metadata.' >&2
  exit 1
fi
[[ $(tr -d '\r\n' <"$release_dir/REVISION") == "$revision" ]]
tree_sha256=$(tr -d '\r\n' <"$release_dir/TREE_SHA256")
[[ $tree_sha256 =~ ^[0-9a-f]{64}$ ]]
[[ $(python3 "$release_dir/deploy/tree-hash.py" "$release_dir") == "$tree_sha256" ]]

prepared_database=
cleanup_prepared() {
  if [[ -n $prepared_database && -e $prepared_database ]]; then
    rm -f -- "$prepared_database"
  fi
}
trap cleanup_prepared EXIT
if [[ -n $database_backup ]]; then
  if [[ $database_backup != /* || ! -f $database_backup ]]; then
    echo 'Database backup must be an existing absolute file.' >&2
    exit 2
  fi
  prepared_database=/var/lib/aws-ops-monitor/.restore.$$.sqlite3
  install -o awsops-collector -g awsops-data -m 0640 \
    "$database_backup" "$prepared_database"
  RESTORE_DATABASE=$prepared_database python3 - <<'PY'
import os
import sqlite3

connection = sqlite3.connect(f"file:{os.environ['RESTORE_DATABASE']}?mode=ro", uri=True)
try:
    result = connection.execute("PRAGMA quick_check").fetchone()
    if not result or result[0] != "ok":
        raise SystemExit("database backup failed PRAGMA quick_check")
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    required = {"gauge_samples", "counter_samples", "counter_cursors", "health_samples"}
    if not required.issubset(tables):
        raise SystemExit("database backup has an incompatible schema")
finally:
    connection.close()
PY
fi

systemctl stop aws-ops-monitor-web.service aws-ops-monitor-collector.service

if [[ -n $prepared_database ]]; then
  rm -f /var/lib/aws-ops-monitor/metrics.sqlite3-wal \
    /var/lib/aws-ops-monitor/metrics.sqlite3-shm
  mv -f -- "$prepared_database" /var/lib/aws-ops-monitor/metrics.sqlite3
  prepared_database=
  chown awsops-collector:awsops-data /var/lib/aws-ops-monitor/metrics.sqlite3
  chmod 0640 /var/lib/aws-ops-monitor/metrics.sqlite3
fi

next_link=/opt/aws-ops-monitor/.rollback.$$
ln -s "$release_dir" "$next_link"
mv -Tf -- "$next_link" /opt/aws-ops-monitor/current
install -o root -g root -m 0644 \
  "$release_dir/deploy/aws-ops-monitor-collector.service" \
  /etc/systemd/system/aws-ops-monitor-collector.service
install -o root -g root -m 0644 \
  "$release_dir/deploy/aws-ops-monitor-web.service" \
  /etc/systemd/system/aws-ops-monitor-web.service
systemctl daemon-reload
if [[ -n $state_backup ]]; then
  if [[ $previous_presence == present ]]; then
    install -o root -g awsops-data -m 0640 \
      "$state_backup/previous-release.txt" \
      /var/lib/aws-ops-monitor/previous-release
  else
    rm -f /var/lib/aws-ops-monitor/previous-release
  fi
  collector_enabled=$(tr -d '\r\n' <"$state_backup/collector-enabled.txt" 2>/dev/null || true)
  web_enabled=$(tr -d '\r\n' <"$state_backup/web-enabled.txt" 2>/dev/null || true)
  collector_state=$(tr -d '\r\n' <"$state_backup/collector-state.txt" 2>/dev/null || true)
  web_state=$(tr -d '\r\n' <"$state_backup/web-state.txt" 2>/dev/null || true)
  if [[ $collector_enabled == enabled ]]; then
    systemctl enable aws-ops-monitor-collector.service >/dev/null
  else
    systemctl disable aws-ops-monitor-collector.service >/dev/null
  fi
  if [[ $web_enabled == enabled ]]; then
    systemctl enable aws-ops-monitor-web.service >/dev/null
  else
    systemctl disable aws-ops-monitor-web.service >/dev/null
  fi
  if [[ $collector_state == active ]]; then
    systemctl start aws-ops-monitor-collector.service
  fi
  if [[ $web_state == active ]]; then
    systemctl start aws-ops-monitor-web.service
  fi
  if [[ $collector_state == active ]]; then
    systemctl is-active --quiet aws-ops-monitor-collector.service
  fi
  if [[ $web_state == active ]]; then
    systemctl is-active --quiet aws-ops-monitor-web.service
  fi
else
  systemctl start aws-ops-monitor-collector.service
  systemctl start aws-ops-monitor-web.service
  systemctl is-active --quiet aws-ops-monitor-collector.service
  systemctl is-active --quiet aws-ops-monitor-web.service
fi
trap - EXIT

echo "Rolled AWS Ops Monitor back to $revision."
