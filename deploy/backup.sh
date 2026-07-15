#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 [--output-root <directory>]" >&2
}

output_root=/var/backups/aws-ops-monitor
while (($#)); do
  case "$1" in
    --output-root)
      output_root=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo 'backup.sh must run as root.' >&2
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
if [[ $output_root != /* ]]; then
  echo 'Backup root must be an absolute path.' >&2
  exit 2
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
install -d -o root -g root -m 0700 "$output_root"
backup_dir=$(mktemp -d "$output_root/predeploy-$timestamp.XXXXXX")
chown root:root "$backup_dir"
chmod 0700 "$backup_dir"

revision=none
if [[ -L /opt/aws-ops-monitor/current ]]; then
  candidate=$(basename -- "$(readlink -f /opt/aws-ops-monitor/current)")
  if [[ $candidate =~ ^[0-9a-f]{40}$ ]]; then
    revision=$candidate
  fi
fi
printf '%s\n' "$revision" >"$backup_dir/monitor-revision.txt"

previous_release=/var/lib/aws-ops-monitor/previous-release
if [[ -f $previous_release && ! -L $previous_release ]]; then
  previous=$(tr -d '\r\n' <"$previous_release")
  if [[ ! $previous =~ ^[0-9a-f]{40}$ ]]; then
    echo 'Existing previous-release pointer is invalid; refusing an incomplete backup.' >&2
    exit 1
  fi
  printf 'present\n' >"$backup_dir/previous-release-presence.txt"
  printf '%s\n' "$previous" >"$backup_dir/previous-release.txt"
else
  printf 'absent\n' >"$backup_dir/previous-release-presence.txt"
fi

if [[ -d /etc/aws-ops-monitor ]]; then
  tar -C /etc -czf "$backup_dir/aws-ops-monitor-config.tar.gz" aws-ops-monitor
  chmod 0600 "$backup_dir/aws-ops-monitor-config.tar.gz"
fi

database=/var/lib/aws-ops-monitor/metrics.sqlite3
if [[ -s $database ]]; then
  BACKUP_SOURCE=$database BACKUP_DEST=$backup_dir/metrics.sqlite3 \
    python3 - <<'PY'
import os
import sqlite3

source = sqlite3.connect(f"file:{os.environ['BACKUP_SOURCE']}?mode=ro", uri=True)
destination = sqlite3.connect(os.environ["BACKUP_DEST"])
try:
    source.backup(destination)
finally:
    destination.close()
    source.close()
PY
  chmod 0600 "$backup_dir/metrics.sqlite3"
fi

# The monitor does not modify Xray. A root-only copy is retained so the
# pre-deploy security/runtime state is still recoverable and auditable.
xray_config=$(docker inspect --format \
  '{{range .Mounts}}{{if eq .Destination "/etc/xray/config.json"}}{{.Source}}{{end}}{{end}}' \
  xray 2>/dev/null || true)
if [[ $xray_config == /* && -f $xray_config ]]; then
  install -o root -g root -m 0600 "$xray_config" "$backup_dir/xray-config.json"
fi

systemctl is-active aws-ops-monitor-collector.service >"$backup_dir/collector-state.txt" 2>&1 || true
systemctl is-active aws-ops-monitor-web.service >"$backup_dir/web-state.txt" 2>&1 || true
systemctl is-enabled aws-ops-monitor-collector.service >"$backup_dir/collector-enabled.txt" 2>&1 || true
systemctl is-enabled aws-ops-monitor-web.service >"$backup_dir/web-enabled.txt" 2>&1 || true
docker inspect --format '{{.State.Status}} {{.RestartCount}} {{.State.OOMKilled}}' \
  xray >"$backup_dir/xray-state.txt" 2>&1 || true
ss -H -lnt >"$backup_dir/listeners.txt"

(
  cd "$backup_dir"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >SHA256SUMS
)
chmod 0600 "$backup_dir"/*

echo "$backup_dir"
