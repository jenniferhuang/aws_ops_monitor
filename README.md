# AWS Ops Monitor

A small, private operations dashboard for Jennifer's AWS Lightsail/Xray host.
It records whole-host network counters, Xray traffic attribution, resource
health, path probes, and listener drift without exposing a new public
administration endpoint.

The implementation is intentionally lightweight for the current host
(approximately 1 GB RAM): a Python collector, SQLite WAL ledger, read-only
Python web service, and local static assets. Prometheus/Grafana/Loki are not
required on the monitored VM.

## Security model

- The dashboard binds to `127.0.0.1` by default and is reached through an SSH
  local forward.
- The collector has no network listener. Only it may receive the narrowly
  scoped access needed to query the Xray container.
- The web process reads monitoring data but cannot access Docker or modify
  Xray.
- VMess UUIDs, WARP keys, AWS secrets, raw access-log lines, and packet payloads
  are never stored or returned.
- Linux NIC, Xray, and optional AWS control-plane counters overlap. The UI
  compares them but never adds them together.

See [Architecture](docs/architecture.md), [Security](docs/security.md), and
[Metric contract](docs/metric-contract.md).

## What the website monitors

The authenticated dashboard gives one private view of:

- host load/CPU capacity, memory, root-disk capacity, uptime, and collector
  freshness;
- whole-host NIC inbound/outbound bytes, packets, errors, and drops;
- Xray state, restart/OOM signals, and pseudonymous per-user/inbound byte
  counters from its loopback StatsService;
- expected versus unexpected TCP listeners, including a critical warning for
  the existing all-interface HTTP proxy;
- synthetic DNS, Cloudflare WebSocket, and WARP egress path health;
- optional Lightsail instance state, edge-firewall rules, alarms, and
  single-instance month-to-date `NetworkIn`/`NetworkOut` data when the instance
  role is authorized; and
- the nominal per-instance plan allocation, separately and with explicit
  provenance when AWS or the operator supplies it.

The NIC, Xray, and AWS values are overlapping measurements. They are presented
side by side and never summed. This monitor also does not claim exact bytes per
remote destination: that would require a separately reviewed flow-telemetry
design with additional privacy, retention, and cost implications.

## Development and full local gate

Python 3.11 or newer is required. The runtime itself has no third-party Python
dependency; the optional Lightsail adapter uses the AWS SDK already present on
the target host.

```bash
./scripts/check.sh
```

For one local sample with host-only defaults:

```bash
PYTHONPATH=src python3 -m aws_ops_monitor --once
```

## Private deployment and usage

The reviewed release is installed as two hardened systemd services. The
collector is the only database writer and has no HTTP listener; the web process
is read-only, has no Docker access, and binds to `127.0.0.1:8787`.

Deploy only an exact 40-character commit already pushed to `origin/main`:

```bash
deploy/remote-deploy.sh \
  --host '<LIGHTSAIL_IP>' \
  --key '/absolute/path/to/LightsailDefaultKey-ap-southeast-1.pem' \
  --revision '<40_CHARACTER_COMMIT>'
```

Then create an SSH local forward and open `http://127.0.0.1:8787`:

```bash
ssh -N -L 8787:127.0.0.1:8787 \
  -i '/absolute/path/to/LightsailDefaultKey-ap-southeast-1.pem' \
  ubuntu@'<LIGHTSAIL_IP>'
```

The generated username defaults to `monitor`; retrieve its password through
the SSH session with `sudo cat /etc/aws-ops-monitor/web-password`. Never expose
port 8787, the Xray API, Docker socket, or raw metrics publicly. See
[Deployment and operations](deploy/README.md) for backup, verification, and
rollback commands.

Kubernetes is intentionally not part of this deployment. A K8s dashboard would
not monitor this standalone Docker/Xray host by itself, and a cluster plus a
Prometheus/Grafana/Loki stack would consume a disproportionate amount of the
approximately 1 GB VM. The small collector/SQLite/site pattern can be exported
to a larger observability stack later without changing the current security
boundary.

## Current scope and limitation

Host and Xray telemetry can run without AWS account credentials. Authoritative
Lightsail firewall, instance plan allocation, `NetworkIn`/`NetworkOut`, and
alarms require a least-privilege identity for the correct AWS account. Until
then, consumption is labeled **host-measured estimate**. The site does not
claim to show an AWS bill.

Lightsail transfer usage is pooled across same-bundle instances in a region.
Therefore the site shows one instance's month-to-date `NetworkIn + NetworkOut`
and its nominal per-instance plan allocation as separate facts. It never
calculates a utilization percentage or remaining allowance from those values;
neither is, by itself, regional pooled billing utilization or the whole-account
bill. Only outbound excess is billable, even though inbound and outbound both
consume the allowance.

The remote Mac dashboard shown in the source VPN hierarchy is a design
blueprint, not an existing runtime stack. This project provides a reusable
collector/ledger/read-only-site pattern that can be adapted to the Mac after it
is reachable.
