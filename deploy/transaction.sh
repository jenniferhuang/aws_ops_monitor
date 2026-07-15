#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 --revision <sha> --tree-sha256 <sha256> --source <dir> [--observe-seconds <seconds>]" >&2
}

revision=
tree_sha256=
source_dir=
observe_seconds=65
while (($#)); do
  case "$1" in
    --revision)
      revision=${2:-}
      shift 2
      ;;
    --tree-sha256)
      tree_sha256=${2:-}
      shift 2
      ;;
    --source)
      source_dir=${2:-}
      shift 2
      ;;
    --observe-seconds)
      observe_seconds=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo 'transaction.sh must run as root.' >&2
  exit 1
fi
if [[ ! $revision =~ ^[0-9a-f]{40}$ || ! $tree_sha256 =~ ^[0-9a-f]{64}$ ]]; then
  usage
  exit 2
fi
if [[ $source_dir != /* || ! -d $source_dir ]]; then
  echo 'Source must be an existing absolute directory.' >&2
  exit 2
fi
if [[ ! $observe_seconds =~ ^[0-9]+$ || $observe_seconds -lt 30 || $observe_seconds -gt 600 ]]; then
  echo 'observe-seconds must be between 30 and 600.' >&2
  exit 2
fi

install -d -o root -g root -m 0755 /run/lock
exec 9>/run/lock/aws-ops-monitor.lock
if ! flock -n 9; then
  echo 'Another AWS Ops Monitor operation is active.' >&2
  exit 1
fi
export AWS_OPS_LOCK_HELD=1

xray_before=$(docker inspect --format \
  '{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.State.Running}}' xray)
if [[ $xray_before != *'|true' ]]; then
  echo 'Xray is not running; refusing monitor deployment.' >&2
  exit 1
fi

backup_dir=$("$source_dir/deploy/backup.sh")
previous=none
if [[ -L /opt/aws-ops-monitor/current ]]; then
  previous=$(basename -- "$(readlink -f /opt/aws-ops-monitor/current)")
fi

rollback_on_failure() {
  result=$?
  if [[ $result -ne 0 ]]; then
    echo 'Deployment verification failed; rolling back only the monitor.' >&2
    if [[ $previous =~ ^[0-9a-f]{40}$ && -d /opt/aws-ops-monitor/releases/$previous ]]; then
      rollback_args=(--revision "$previous" --state-backup "$backup_dir")
      if [[ -f $backup_dir/metrics.sqlite3 ]]; then
        rollback_args+=(--database-backup "$backup_dir/metrics.sqlite3")
      fi
      if ! "$source_dir/deploy/rollback.sh" "${rollback_args[@]}"; then
        echo 'Monitor rollback failed; forcing both monitor services offline.' >&2
        systemctl disable --now aws-ops-monitor-web.service \
          aws-ops-monitor-collector.service >/dev/null 2>&1 || true
      fi
    else
      systemctl disable --now aws-ops-monitor-web.service \
        aws-ops-monitor-collector.service >/dev/null 2>&1 || true
      rm -f /opt/aws-ops-monitor/current
    fi
  fi
  exit "$result"
}
trap rollback_on_failure EXIT

"$source_dir/deploy/install.sh" \
  --revision "$revision" \
  --tree-sha256 "$tree_sha256" \
  --source "$source_dir"
/opt/aws-ops-monitor/current/deploy/verify.sh \
  --revision "$revision" \
  --wait-seconds "$observe_seconds"

xray_after=$(docker inspect --format \
  '{{.Id}}|{{.State.StartedAt}}|{{.RestartCount}}|{{.State.Running}}' xray)
if [[ $xray_after != "$xray_before" ]]; then
  echo 'Xray identity/start/restart state changed during monitor deployment.' >&2
  exit 1
fi

trap - EXIT
printf 'revision=%s\nbackup=%s\ntree_sha256=%s\nxray_continuity=verified\n' \
  "$revision" "$backup_dir" "$tree_sha256"
