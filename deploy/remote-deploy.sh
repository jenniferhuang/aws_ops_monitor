#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: deploy/remote-deploy.sh \
  --host <ssh-host> --key <private-key> --revision <40-char-sha> \
  [--user ubuntu] [--observe-seconds 65]
EOF
}

host=
key=
revision=
remote_user=ubuntu
observe_seconds=65
while (($#)); do
  case "$1" in
    --host)
      host=${2:-}
      shift 2
      ;;
    --key)
      key=${2:-}
      shift 2
      ;;
    --revision)
      revision=${2:-}
      shift 2
      ;;
    --user)
      remote_user=${2:-}
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

if [[ -z $host || -z $key || ! -f $key ]]; then
  usage
  exit 2
fi
if [[ ! $revision =~ ^[0-9a-f]{40}$ ]]; then
  echo 'Revision must be an exact lowercase 40-character Git SHA.' >&2
  exit 2
fi
if [[ ! $remote_user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  echo 'SSH user contains unsupported characters.' >&2
  exit 2
fi
if [[ ! $observe_seconds =~ ^[0-9]+$ || $observe_seconds -lt 30 || $observe_seconds -gt 600 ]]; then
  echo 'observe-seconds must be between 30 and 600.' >&2
  exit 2
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repo_root"
resolved=$(git rev-parse --verify "$revision^{commit}")
if [[ $resolved != "$revision" ]]; then
  echo 'Requested revision is not available locally.' >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$revision" origin/main; then
  echo 'Requested revision is not present on origin/main.' >&2
  exit 1
fi

archive=$(mktemp "${TMPDIR:-/tmp}/aws-ops-monitor.XXXXXX.tar.gz")
cleanup() {
  rm -f -- "$archive"
}
trap cleanup EXIT
git archive --format=tar "$revision" | gzip -9 >"$archive"
archive_sha=$(shasum -a 256 "$archive" | awk '{print $1}')
deployment_id=$(openssl rand -hex 8)

ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o IdentitiesOnly=yes
  -o StrictHostKeyChecking=yes
  -i "$key"
)
target=$remote_user@$host
remote_stage=/tmp/aws-ops-monitor-$revision-$deployment_id
remote_archive=/tmp/aws-ops-monitor-$revision-$deployment_id.tar.gz

ssh "${ssh_options[@]}" "$target" \
  'set -e; command -v python3; python3 -c "import boto3, botocore"; command -v docker; command -v flock; command -v getent; command -v ss; command -v openssl; sudo -n true; test "$(docker inspect --format={{.State.Running}} xray)" = true'

scp "${ssh_options[@]}" "$archive" "$target:$remote_archive"
ssh "${ssh_options[@]}" "$target" bash -s -- \
  "$remote_archive" "$archive_sha" "$remote_stage" "$revision" "$observe_seconds" <<'REMOTE'
set -euo pipefail
archive=$1
expected_sha=$2
stage=$3
revision=$4
observe_seconds=$5

cleanup_remote() {
  rm -f -- "$archive"
  rm -rf -- "$stage"
}
trap cleanup_remote EXIT

actual_sha=$(sha256sum "$archive" | awk '{print $1}')
[[ $actual_sha == "$expected_sha" ]]
rm -rf -- "$stage"
install -d -m 0700 "$stage"
# Git archives commonly encode regular files as 0664 and executables as 0775.
# Normalize through a fixed umask before computing the mode-sensitive tree
# hash; otherwise the SSH user's login umask can produce an artifact that no
# longer matches the root-owned 0644/0755 release installed below.
umask 022
tar --no-same-owner --no-same-permissions -C "$stage" -xzf "$archive"
rm -f -- "$archive"
tree_sha256=$(python3 "$stage/deploy/tree-hash.py" "$stage")
sudo "$stage/deploy/transaction.sh" \
  --revision "$revision" \
  --tree-sha256 "$tree_sha256" \
  --source "$stage" \
  --observe-seconds "$observe_seconds"
trap - EXIT
cleanup_remote
printf 'archive_sha256=%s\n' "$expected_sha"
REMOTE

trap - EXIT
cleanup
