# Security and exposure policy

## Invariants

1. The dashboard defaults to `127.0.0.1`; a non-loopback bind is rejected
   unless an explicit secure publishing mode is configured and reviewed.
2. Basic authentication is required for monitoring APIs and static pages.
   `/healthz` may return only process health and no operational data.
3. Credentials live in a root-owned or service-owned mode-`0600` environment
   file. They are never committed, logged, returned by APIs, or included in a
   process argument.
4. The collector has no HTTP listener. The web process has no Docker group,
   socket, root, Xray-control, or AWS-write access.
5. Xray API, Docker, SSH, raw metrics, Prometheus/Grafana, and the dashboard are
   never opened as new public ports.
6. Persist only pseudonymous user labels. Never persist VMess UUIDs, WARP
   secrets, raw Xray access-log lines, packet payloads, or complete remote IPs.
7. Every remote change is preceded by a backup and followed by listener,
   service, API, UI, and persistence verification.

## Current live-host findings to track separately

The 2026-07-15 read-only audit found an unauthenticated Xray HTTP/WARP test
proxy bound to all interfaces on port 1087, a permissive host firewall, and no
authoritative Lightsail firewall view. Non-corporate probes timed out, but that
does not prove the account firewall policy. Treat 1087 as potentially exposed;
bind it to loopback or remove it only in a separate backed-up Xray maintenance
change after confirming no client depends on it.

The audit also found credential-bearing Xray and WARP files with mode `0644`, a
mutable Xray `latest` image, no access-log rotation, a pending reboot, and
upgradable packages. These are health/remediation findings, not permission to
silently rotate credentials or alter the VPN protocol while deploying this
monitor.

## Private access

Default operator flow:

```text
ssh -L 8787:127.0.0.1:8787 -i <private-key-path> ubuntu@<instance>
```

Then open `http://127.0.0.1:8787`. A future named Cloudflare Tunnel may publish
the loopback endpoint only when Cloudflare Access authentication is configured.
An unauthenticated quick tunnel is not acceptable for this operations site.

## Least-privilege AWS policy boundary

The optional control-plane adapter needs read operations such as
`lightsail:GetInstance`, `lightsail:GetInstancePortStates`,
`lightsail:GetInstanceMetricData`, and `lightsail:GetAlarmsForResource`.
Billing access is separate. The monitor does not need instance lifecycle,
firewall mutation, key-pair, DNS mutation, or write permissions.
