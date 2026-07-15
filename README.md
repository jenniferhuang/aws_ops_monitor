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

## Current scope and limitation

Host and Xray telemetry can run without AWS account credentials. Authoritative
Lightsail firewall, bundle allowance, `NetworkIn`/`NetworkOut`, alarms, and
billing require a least-privilege identity for the correct AWS account. Until
then, consumption is labeled **host-measured estimate**, not an AWS bill.

The remote Mac dashboard shown in the source VPN hierarchy is a design
blueprint, not an existing runtime stack. This project provides a reusable
collector/ledger/read-only-site pattern that can be adapted to the Mac after it
is reachable.
