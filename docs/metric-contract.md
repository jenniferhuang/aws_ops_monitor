# Metric contract

The monitor keeps measurement layers distinct and attaches provenance,
confidence, and reset identity to counters.

| Layer | Source | Meaning | Reset identity |
| --- | --- | --- | --- |
| Host | Linux interface counters | Whole-instance RX/TX, packets, errors, drops | Kernel boot ID + interface |
| Xray | StatsService | Proxied per-user and inbound traffic | Xray uptime/start identity |
| AWS optional | Lightsail API | Five-minute `NetworkIn`/`NetworkOut` sums | AWS resource + period |

For a monotonic counter `C`:

- if source identity is unchanged and `C_now >= C_previous`, delta is
  `C_now - C_previous`;
- if identity changed or the counter decreased, record a reset and use delta
  zero for that first sample;
- a missing interval is a collection gap, not a zero-traffic interval;
- deltas are never negative.

The UI must label:

- AWS metrics as `AWS verified` only when read from the correct account;
- allowance as `operator configured` or `inferred` when it is not verified;
- NIC month totals as `host-measured estimate`;
- Xray data as an overlapping attributed subset.

Initial retention targets are bounded: short-interval raw samples for seven
days, hourly rollups for thirteen months, and no raw traffic log retention.
The implementation may reduce these windows on disk pressure but must expose a
collection-gap/retention status instead of silently presenting incomplete data.
