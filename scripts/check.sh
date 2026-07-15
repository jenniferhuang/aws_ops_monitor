#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repo_root"

export PYTHONPATH="$repo_root/src"
bash -n scripts/check.sh deploy/*.sh
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/check.sh deploy/*.sh
fi
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify \
    deploy/aws-ops-monitor-collector.service \
    deploy/aws-ops-monitor-web.service
fi
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
python3 -c 'import tomllib; tomllib.load(open("pyproject.toml", "rb"))'

if command -v node >/dev/null 2>&1; then
  node --check src/aws_ops_monitor/static/app.js
fi

git diff --check
git diff --cached --check

if rg -n --hidden -g '!/.git' -g '!scripts/check.sh' \
  '(BEGIN [A-Z0-9 ]*PRIVATE KEY|A(KIA|SIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|aws_secret_access_key[[:space:]]*=|CLOUDFLARE_API_TOKEN[[:space:]]*=.{16,}|PrivateKey[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{32,})' \
  .; then
  echo 'Potential secret material found; review before continuing.' >&2
  exit 1
fi
