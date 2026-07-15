# Deployment and operations

The monitor is installed directly on the Lightsail VM as two hardened systemd
services. Kubernetes is intentionally not used: the current VM is a
Docker/Xray host with approximately 1 GB RAM, not a K8s cluster.

## Trust split

- `awsops-collector` has Docker-group access and is the sole SQLite writer. It
  has no HTTP listener. Docker-group membership is root-equivalent; this is a
  deliberately isolated risk boundary, not a claim that the collector is
  technically read-only. The web user never receives that membership.
- `awsops-web` can read the monitoring ledger through the `awsops-data` group.
  It has no Docker access and listens only on `127.0.0.1:8787`.
- Both services run an exact release from `/opt/aws-ops-monitor/releases/`.
  `/opt/aws-ops-monitor/current` is the atomic release pointer.
- Generated secrets live under `/etc/aws-ops-monitor` and are never printed by
  deployment or verification scripts.

## Local gate

```bash
./scripts/check.sh
```

Commit and push every green logical change before deployment. Deploy only an
exact 40-character commit present on `origin/main`:

```bash
deploy/remote-deploy.sh \
  --host '<LIGHTSAIL_IP>' \
  --key '/absolute/path/to/LightsailDefaultKey-ap-southeast-1.pem' \
  --revision '<40_CHARACTER_COMMIT>'
```

The wrapper validates SSH/sudo/Docker/Xray, transfers a checksummed Git archive,
creates a root-only remote backup, installs a versioned release, verifies the
private listener/API/data, and observes collection continuity. A failed monitor
verification restores the prior monitor release or disables the first failed
installation. It never restarts or rewrites Xray.

On a failed first installation, generated users, root-only secrets, the release
directory, unit files, and monitoring state may remain for a resumable retry;
both monitor services are disabled and the `current` link is removed, so no
monitor listener remains. Xray is not touched.

## Private website access

Create a local tunnel:

```bash
ssh -N \
  -L 8787:127.0.0.1:8787 \
  -i '/absolute/path/to/LightsailDefaultKey-ap-southeast-1.pem' \
  ubuntu@'<LIGHTSAIL_IP>'
```

Open `http://127.0.0.1:8787`. The username defaults to `monitor`. Retrieve the
generated password only when needed, from an authenticated SSH session:

```bash
sudo cat /etc/aws-ops-monitor/web-password
```

Do not publish port 8787. A future public hostname requires a named Cloudflare
Tunnel plus Cloudflare Access; an anonymous quick tunnel is not approved.

## AWS control-plane metrics

Host/Xray metrics work without AWS account credentials. The production install
enables the read-only Lightsail adapter so a missing permission is visible as
`access_denied` instead of silently hiding the AWS layer. Grant the instance
role the actions documented in `docs/security.md`; after the policy propagates,
restart only the collector.

When `GetInstance` returns `networking.monthlyTransfer`, the adapter records the
nominal per-instance plan allocation with `aws_instance_networking` provenance.
An explicit byte override still requires a source such as
`operator-configured`. The site presents that allocation separately from the
instance's month-to-date `NetworkIn + NetworkOut`; it does not calculate a
percentage or remaining balance. Same-bundle transfer can be pooled across
instances in the region, so neither value is labeled regional pooled billing
utilization or the account bill.

## Collection and retention

The collector samples local host/Xray/listener data every 30 seconds. DNS,
public WebSocket, WARP, and AWS calls are cached for at least five minutes to
avoid turning monitoring into material traffic. Raw samples are retained for
seven days; counter deltas are compacted into hourly rollups retained for 400
days. Counter cursors are preserved across pruning, so resets and future deltas
remain correct.

## Backup and rollback

Create a root-only backup:

```bash
sudo /opt/aws-ops-monitor/current/deploy/backup.sh
```

Roll back the monitor to the recorded prior release:

```bash
sudo /opt/aws-ops-monitor/current/deploy/rollback.sh
```

Optionally pass `--database-backup /absolute/path/metrics.sqlite3`. Rollback
stops only the monitoring services. It does not alter Xray, its clients, its
ports, WARP, DNS, or the Lightsail firewall.

## Verification

```bash
sudo /opt/aws-ops-monitor/current/deploy/verify.sh \
  --revision '<40_CHARACTER_COMMIT>' \
  --wait-seconds 65
```

The verifier checks exact revision, service users, privilege separation,
secret/data modes, non-negative counters, freshness/continuity, anonymous 401,
authenticated overview, secret-field absence, loopback-only dashboard/Xray API,
forbidden observability ports, and Xray running state.
