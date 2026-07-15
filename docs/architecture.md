# Grounded architecture

Baseline: 2026-07-15. Secrets and private client identifiers are deliberately
excluded.

## What exists now

The live AWS host is a Lightsail `t3.micro` in `ap-southeast-1` with two vCPU,
approximately 1 GB RAM, and a 40 GB root disk. One host-networked Xray container
provides a VMess/WebSocket public path and WARP/freedom egress. Xray's
StatsService is loopback-only. No Prometheus, Grafana, Loki, node-exporter, or
cAdvisor service was found during the read-only audit.

The Harbor Market application is a separate workload on Jennifer's remote Mac.
It is published by an outbound Cloudflare connector to a loopback Nginx
frontend. Harbor's PostgreSQL and MinIO remain private and are not dependencies
of the AWS proxy.

```mermaid
flowchart LR
  Client["Client proxy"] -->|"TLS + WebSocket"| CF["Cloudflare edge"]
  CF -->|"origin :80"| Xray["Lightsail Xray<br/>host network"]
  Xray --> Warp["WARP egress"]
  Xray --> Direct["Freedom egress"]
  Xray --> Block["Blocked routes"]
  Xray --> Stats["StatsService<br/>127.0.0.1:10084"]

  Browser["Harbor user"] --> AppEdge["Separate Cloudflare tunnel"]
  AppEdge --> Mac["Remote Mac<br/>loopback Nginx"]
  Mac --> Harbor["Private API + PostgreSQL + MinIO"]

  Xray -.- Separate["No runtime/data dependency"]
  Separate -.- Harbor
```

## Monitor design

The monitored host has limited memory and no swap, so the primary design uses
standard-library Python and SQLite rather than a full observability stack.

```mermaid
flowchart TB
  subgraph VM["Lightsail host"]
    NIC["Linux NIC and /proc counters"] --> Collector
    XR["Xray StatsService"] --> Collector["Non-networked collector"]
    Sock["Listener and path probes"] --> Collector
    Health["Host + Xray health"] --> Collector
    Collector --> Reset["Reset-aware delta engine"]
    Reset --> DB[("SQLite WAL")]
    DB -->|"read only"| API["Read-only API + static UI"]
    API --> Loopback["127.0.0.1:8787"]
  end
  Operator["Operator browser"] -.->|"SSH local forward"| Loopback
  AWS["Optional read-only Lightsail API"] -.-> Collector
```

The collector and site are different trust zones:

| Component | May access | Must not access |
| --- | --- | --- |
| Collector | Host counters, narrow Xray query, writable ledger | Public HTTP, dashboard password, Xray mutation |
| Web/API | Read-only ledger, static assets, loopback socket | Docker, root, Xray API, AWS writes |
| AWS adapter | Read-only Lightsail metrics/status/firewall | Port changes, instance lifecycle, billing mutations |

Docker-group membership is root-equivalent. If querying Xray requires
`docker exec`, only the collector user receives that membership. The web user
must never receive it.

## Network and accounting relationship

```mermaid
flowchart LR
  AWS["AWS NetworkIn/NetworkOut<br/>control-plane aggregate"] --> AWSPanel["AWS panel"]
  NIC["ens5 RX/TX<br/>whole host"] --> HostPanel["Host panel"]
  XR["Xray per-user/inbound<br/>proxied subset"] --> XRPanel["Xray panel"]
  AWSPanel -.- Rule["Compare layers; never sum them"]
  HostPanel -.- Rule
  XRPanel -.- Rule
```

- NIC counters cover Xray, SSH, updates, monitoring, protocol overhead, and all
  other instance traffic.
- Xray counters attribute the proxied subset and reset on Xray restart.
- AWS metrics are the control-plane view and are the correct reconciliation
  layer when account access exists.
- Exact bytes by destination hostname are not available from stock Xray access
  logs. The dashboard promises exact layer totals and connection-path counts,
  not packet-level or hostname-level byte accounting.

## Runtime and rollback pattern

```mermaid
flowchart LR
  Commit["Reviewed exact commit"] --> Test["Unit + integration + browser tests"]
  Test --> Backup["Remote config/data backup"]
  Backup --> Release["Versioned release"]
  Release --> Services["Collector + web systemd units"]
  Services --> Verify["Loopback/API/UI/data continuity"]
  Verify --> Observe["Timed observation"]
  Verify -->|"failure"| Rollback["Previous release + DB backup"]
  Observe -->|"failure"| Rollback
```

Deploying the monitor must not restart or reconfigure Xray. Every release uses
an exact Git commit and keeps a rollback target. The only added listener is on
loopback. A restart test must demonstrate that the ledger continues while
reset-aware counters remain non-negative.

## Reuse for the remote Mac

The same separation can later monitor the Mac, replacing collectors as
follows:

| AWS host | Remote Mac |
| --- | --- |
| `/sys/class/net` | `netstat -ib` interface counters |
| systemd | launchd |
| Docker/Xray health | Colima/Compose/Harbor health |
| Lightsail metrics | Cloudflare Tunnel and Mac metrics |
| Xray stats | Nginx/API/PostgreSQL/MinIO health |

The Mac monitor should also remain loopback/private. It must not publish raw
Harbor API, PostgreSQL, MinIO, Docker, or macOS administration ports.
