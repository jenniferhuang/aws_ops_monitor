# Metric contract

The monitor keeps measurement layers distinct and attaches provenance,
confidence, and reset identity to counters.

| Layer | Source | Meaning | Reset identity |
| --- | --- | --- | --- |
| Host | Linux interface counters | Whole-instance RX/TX, packets, errors, drops | Kernel boot ID + interface |
| Xray | StatsService | Proxied per-user and inbound traffic | Xray uptime/start identity |
| AWS optional | Lightsail API | One instance's five-minute `NetworkIn`/`NetworkOut` sums, aggregated month to date | AWS resource + period |

For a monotonic counter `C`:

- if source identity is unchanged and `C_now >= C_previous`, delta is
  `C_now - C_previous`;
- if identity changed or the counter decreased, record a reset and use delta
  zero for that first sample;
- a missing interval is a collection gap, not a zero-traffic interval;
- deltas are never negative.

The UI must label:

- AWS metrics as `AWS verified` only when read from the correct account;
- nominal per-instance plan allocation with its AWS or operator provenance;
- NIC month totals as `host-measured estimate`;
- Xray data as an overlapping attributed subset.

The AWS transfer panel keeps single-instance month-to-date
`NetworkIn + NetworkOut` separate from the nominal per-instance plan
allocation. The UI must not divide these values, present a utilization
percentage, infer a remaining allowance, or label either value as regional
pooled billing utilization. Same-bundle transfer can be pooled across instances
in a region, and the monitor does not expose whole-account billing data.

Initial retention targets are bounded: short-interval raw samples for seven
days, hourly rollups for thirteen months, and no raw traffic log retention.
The implementation may reduce these windows on disk pressure but must expose a
collection-gap/retention status instead of silently presenting incomplete data.
