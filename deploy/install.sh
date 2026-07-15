#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 --revision <40-char-sha> --tree-sha256 <sha256> [--source <directory>]" >&2
}

revision=
tree_sha256=
source_dir=
while (($#)); do
  case "$1" in
    --revision)
      revision=${2:-}
      shift 2
      ;;
    --source)
      source_dir=${2:-}
      shift 2
      ;;
    --tree-sha256)
      tree_sha256=${2:-}
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo 'install.sh must run as root.' >&2
  exit 1
fi
if [[ ! $revision =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Revision must be an exact lowercase 40-character Git SHA.' >&2
  exit 2
fi
if [[ ! $tree_sha256 =~ ^[0-9a-f]{64}$ ]]; then
  echo 'Tree checksum must be an exact lowercase SHA-256.' >&2
  exit 2
fi
if [[ -z $source_dir ]]; then
  source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
else
  source_dir=$(cd -- "$source_dir" && pwd -P)
fi
if [[ ! -f $source_dir/pyproject.toml || ! -f $source_dir/src/aws_ops_monitor/__init__.py ]]; then
  echo 'Source directory is not an AWS Ops Monitor release.' >&2
  exit 2
fi

if [[ ${AWS_OPS_LOCK_HELD:-0} != 1 ]]; then
  install -d -o root -g root -m 0755 /run/lock
  exec 9>/run/lock/aws-ops-monitor.lock
  if ! flock -n 9; then
    echo 'Another AWS Ops Monitor operation is active.' >&2
    exit 1
  fi
fi

release_root=/opt/aws-ops-monitor/releases
release_dir=$release_root/$revision
current_link=/opt/aws-ops-monitor/current
state_dir=/var/lib/aws-ops-monitor
config_dir=/etc/aws-ops-monitor
previous_file=$state_dir/previous-release

command -v python3 >/dev/null 2>&1 || {
  echo 'python3 is required.' >&2
  exit 1
}
python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
try:
    import boto3  # noqa: F401
    import botocore  # noqa: F401
except ImportError as error:
    raise SystemExit("boto3 and botocore are required for enabled AWS telemetry") from error
PY
command -v docker >/dev/null 2>&1 || {
  echo 'docker is required for Xray telemetry.' >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo 'openssl is required for local secret generation.' >&2
  exit 1
}
command -v getent >/dev/null 2>&1 || {
  echo 'getent is required for the bounded DNS probe.' >&2
  exit 1
}
command -v ss >/dev/null 2>&1 || {
  echo 'ss is required for listener inventory.' >&2
  exit 1
}
getent group docker >/dev/null || {
  echo 'The Docker group does not exist.' >&2
  exit 1
}

source_hash=$(python3 "$source_dir/deploy/tree-hash.py" "$source_dir")
if [[ $source_hash != "$tree_sha256" ]]; then
  echo 'Source tree checksum does not match the approved artifact.' >&2
  exit 1
fi

getent group awsops-data >/dev/null || groupadd --system awsops-data
if ! id awsops-collector >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin awsops-collector
fi
if ! id awsops-web >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin awsops-web
fi
usermod -a -G awsops-data,docker awsops-collector
usermod -a -G awsops-data awsops-web

install -d -o root -g root -m 0755 /opt/aws-ops-monitor "$release_root"
install -d -o awsops-collector -g awsops-data -m 2750 "$state_dir"
install -d -o root -g root -m 0755 "$config_dir"

if [[ -d $release_dir ]]; then
  [[ -f $release_dir/REVISION && -f $release_dir/TREE_SHA256 ]]
  [[ $(tr -d '\r\n' <"$release_dir/REVISION") == "$revision" ]]
  [[ $(tr -d '\r\n' <"$release_dir/TREE_SHA256") == "$tree_sha256" ]]
  installed_hash=$(python3 "$release_dir/deploy/tree-hash.py" "$release_dir")
  if [[ $installed_hash != "$tree_sha256" ]]; then
    echo 'Existing release directory failed its content checksum.' >&2
    exit 1
  fi
else
  stage_dir=$release_root/.${revision}.stage.$$
  cleanup_stage() {
    rm -rf -- "$stage_dir"
  }
  trap cleanup_stage EXIT
  install -d -o root -g root -m 0755 "$stage_dir"
  tar -C "$source_dir" --exclude=.git --exclude=backups --exclude=releases -cf - . \
    | tar -C "$stage_dir" -xf -
  RELEASE_SOURCE="$stage_dir/src" python3 - <<'PY'
import os
from pathlib import Path

for source in Path(os.environ["RELEASE_SOURCE"]).rglob("*.py"):
    compile(source.read_bytes(), str(source), "exec")
PY
  chown -R root:root "$stage_dir"
  chmod -R go-w "$stage_dir"
  installed_hash=$(python3 "$stage_dir/deploy/tree-hash.py" "$stage_dir")
  if [[ $installed_hash != "$tree_sha256" ]]; then
    echo 'Staged release checksum changed during installation.' >&2
    exit 1
  fi
  printf '%s\n' "$revision" >"$stage_dir/REVISION"
  printf '%s\n' "$tree_sha256" >"$stage_dir/TREE_SHA256"
  chmod 0644 "$stage_dir/REVISION" "$stage_dir/TREE_SHA256"
  mv -- "$stage_dir" "$release_dir"
  trap - EXIT
fi

hash_key=$config_dir/xray-user-hash.key
if [[ ! -e $hash_key ]]; then
  umask 077
  openssl rand -hex 32 >"$hash_key"
fi
chown awsops-collector:awsops-collector "$hash_key"
chmod 0600 "$hash_key"

web_password=$config_dir/web-password
if [[ ! -e $web_password ]]; then
  umask 077
  openssl rand -base64 36 | tr -d '\n' >"$web_password"
  printf '\n' >>"$web_password"
fi
chown awsops-web:awsops-web "$web_password"
chmod 0600 "$web_password"

collector_env=$config_dir/collector.env
if [[ ! -e $collector_env ]]; then
  umask 077
  cat >"$collector_env" <<'EOF'
AWS_OPS_DB_PATH=/var/lib/aws-ops-monitor/metrics.sqlite3
AWS_OPS_DB_FILE_MODE=0640
AWS_OPS_INTERVAL_SECONDS=30
AWS_OPS_RAW_RETENTION_DAYS=7
AWS_OPS_ROLLUP_RETENTION_DAYS=400
AWS_OPS_RETENTION_INTERVAL_SECONDS=3600
AWS_OPS_HOST_ENABLED=true
AWS_OPS_XRAY_ENABLED=true
AWS_OPS_XRAY_CONTAINER=xray
AWS_OPS_XRAY_BINARY=xray
AWS_OPS_XRAY_API_SERVER=127.0.0.1:10084
AWS_OPS_XRAY_TIMEOUT_SECONDS=10
AWS_OPS_XRAY_USER_HASH_KEY_FILE=/etc/aws-ops-monitor/xray-user-hash.key
AWS_OPS_NETWORK_ENABLED=true
AWS_OPS_SS_BINARY=ss
AWS_OPS_NETWORK_TIMEOUT_SECONDS=5
AWS_OPS_EXPECTED_PUBLIC_PORTS=22,80
AWS_OPS_EXPECTED_LOOPBACK_PORTS=8787,10084
AWS_OPS_EXPECTED_PUBLIC_UDP_PORTS=
AWS_OPS_EXPECTED_LOOPBACK_UDP_PORTS=
AWS_OPS_PATH_PROBES_ENABLED=true
AWS_OPS_PROBE_PUBLIC_HOST=v2.hermes-node.com
AWS_OPS_PROBE_PUBLIC_PATH=/302
AWS_OPS_WARP_PROBE_ENABLED=true
AWS_OPS_WARP_PROXY_SERVER=127.0.0.1:1087
AWS_OPS_PROBE_TIMEOUT_SECONDS=8
AWS_OPS_PROBE_INTERVAL_SECONDS=300
AWS_OPS_GETENT_BINARY=getent
AWS_OPS_AWS_ENABLED=true
AWS_OPS_AWS_REGION=ap-southeast-1
AWS_OPS_LIGHTSAIL_INSTANCE=Ubuntu-302
EOF
fi
chown root:root "$collector_env"
chmod 0600 "$collector_env"

web_env=$config_dir/web.env
if [[ ! -e $web_env ]]; then
  umask 077
  cat >"$web_env" <<'EOF'
AWS_OPS_DB_PATH=/var/lib/aws-ops-monitor/metrics.sqlite3
AWS_OPS_USERNAME=monitor
AWS_OPS_PASSWORD_FILE=/etc/aws-ops-monitor/web-password
AWS_OPS_BIND_HOST=127.0.0.1
AWS_OPS_PORT=8787
AWS_OPS_ALLOW_NON_LOOPBACK=false
EOF
fi
chown root:root "$web_env"
chmod 0600 "$web_env"

install -o root -g root -m 0644 \
  "$release_dir/deploy/aws-ops-monitor-collector.service" \
  /etc/systemd/system/aws-ops-monitor-collector.service
install -o root -g root -m 0644 \
  "$release_dir/deploy/aws-ops-monitor-web.service" \
  /etc/systemd/system/aws-ops-monitor-web.service
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify \
    /etc/systemd/system/aws-ops-monitor-collector.service \
    /etc/systemd/system/aws-ops-monitor-web.service
fi

previous=
if [[ -L $current_link ]]; then
  previous=$(basename -- "$(readlink -f -- "$current_link")")
fi
if [[ $previous =~ ^[0-9a-f]{40}$ && $previous != "$revision" ]]; then
  printf '%s\n' "$previous" >"$previous_file"
  chown root:awsops-data "$previous_file"
  chmod 0640 "$previous_file"
fi

next_link=/opt/aws-ops-monitor/.current.$$
ln -s "$release_dir" "$next_link"
mv -Tf -- "$next_link" "$current_link"

systemctl daemon-reload
systemctl enable aws-ops-monitor-collector.service aws-ops-monitor-web.service >/dev/null
systemctl restart aws-ops-monitor-collector.service

database=$state_dir/metrics.sqlite3
for _ in {1..20}; do
  [[ -s $database ]] && break
  sleep 1
done
if [[ ! -s $database ]]; then
  systemctl --no-pager --full status aws-ops-monitor-collector.service >&2 || true
  echo 'Collector did not initialize its database.' >&2
  exit 1
fi
chown awsops-collector:awsops-data "$database" "$database"-* 2>/dev/null || true
chmod 0640 "$database" "$database"-* 2>/dev/null || true

systemctl restart aws-ops-monitor-web.service
systemctl is-active --quiet aws-ops-monitor-collector.service
systemctl is-active --quiet aws-ops-monitor-web.service

echo "Installed AWS Ops Monitor revision $revision."
