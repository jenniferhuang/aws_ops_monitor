"""SQLite persistence with reset-safe monotonic counter deltas."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import sqlite3
import time
from typing import Iterator

from .models import (
    CounterObservation,
    CounterResult,
    GaugeObservation,
    HealthObservation,
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS gauge_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at REAL NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    value REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS gauge_samples_lookup
    ON gauge_samples(source, name, observed_at);

CREATE INDEX IF NOT EXISTS gauge_samples_retention
    ON gauge_samples(observed_at);

CREATE TABLE IF NOT EXISTS counter_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at REAL NOT NULL,
    counter_key TEXT NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    reset_id TEXT NOT NULL,
    raw_value INTEGER NOT NULL CHECK(raw_value >= 0),
    delta_value INTEGER NOT NULL CHECK(delta_value >= 0),
    is_baseline INTEGER NOT NULL CHECK(is_baseline IN (0, 1)),
    is_reset INTEGER NOT NULL CHECK(is_reset IN (0, 1))
);

CREATE INDEX IF NOT EXISTS counter_samples_lookup
    ON counter_samples(counter_key, observed_at);

CREATE INDEX IF NOT EXISTS counter_samples_retention
    ON counter_samples(observed_at);

CREATE TABLE IF NOT EXISTS counter_hourly_rollups (
    bucket_start INTEGER NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    delta_value INTEGER NOT NULL CHECK(delta_value >= 0),
    reset_count INTEGER NOT NULL CHECK(reset_count >= 0),
    PRIMARY KEY (bucket_start, source, name, labels_json)
);

CREATE INDEX IF NOT EXISTS counter_hourly_rollups_lookup
    ON counter_hourly_rollups(source, name, bucket_start);

CREATE TABLE IF NOT EXISTS counter_cursors (
    counter_key TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    reset_id TEXT NOT NULL,
    raw_value INTEGER NOT NULL CHECK(raw_value >= 0),
    observed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS health_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at REAL NOT NULL,
    component TEXT NOT NULL,
    state TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS health_samples_lookup
    ON health_samples(component, observed_at);

CREATE INDEX IF NOT EXISTS health_samples_retention
    ON health_samples(observed_at);
"""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _labels_json(labels: object) -> str:
    return _canonical_json({str(key): str(value) for key, value in dict(labels).items()})


def _counter_key(source: str, name: str, labels_json: str) -> str:
    material = f"{source}\0{name}\0{labels_json}".encode("utf-8")
    return sha256(material).hexdigest()


_VIRTUAL_INTERFACE_PREFIXES = (
    "br-",
    "cni",
    "docker",
    "dummy",
    "flannel",
    "tap",
    "tailscale",
    "tun",
    "veth",
    "virbr",
    "wg",
)

_NETWORK_COUNTER_FIELDS = {
    "network_receive_bytes_total": "rx_bytes",
    "network_receive_packets_total": "rx_packets",
    "network_receive_errors_total": "rx_errors",
    "network_receive_drops_total": "rx_drops",
    "network_transmit_bytes_total": "tx_bytes",
    "network_transmit_packets_total": "tx_packets",
    "network_transmit_errors_total": "tx_errors",
    "network_transmit_drops_total": "tx_drops",
}
_SAFE_XRAY_USER_HASH = re.compile(r"^usr_[0-9a-f]{24}$")


def _is_external_interface(labels: dict[str, object]) -> bool:
    name = str(labels.get("interface", ""))
    return bool(name) and name != "lo" and not name.startswith(_VIRTUAL_INTERFACE_PREFIXES)


def _is_safe_xray_user_hash(value: object) -> bool:
    return isinstance(value, str) and _SAFE_XRAY_USER_HASH.fullmatch(value) is not None


def _cpu_utilization_percent(total_delta: int, idle_delta: int) -> float | None:
    if total_delta <= 0 or idle_delta < 0:
        return None
    busy = max(0, min(total_delta, total_delta - idle_delta))
    return round((busy / total_delta) * 100.0, 2)


def _is_current_aws_snapshot(
    health: dict[str, object] | None,
    gauges: dict[str, tuple[float, float]],
    *,
    now: float,
) -> bool:
    """Return whether month-to-date AWS values are safe to project.

    Old successful gauges remain in SQLite after a later AWS failure, so a
    healthy/degraded, current-month health observation must explicitly vouch
    for every projected AWS usage value.
    """

    if not health or str(health.get("state")) not in {"healthy", "degraded"}:
        return False
    observed_at = health.get("observed_at")
    if not isinstance(observed_at, (int, float)):
        return False
    details = health.get("details")
    if not isinstance(details, dict) or details.get("metric_window") != "current_month_utc":
        return False
    raw_fresh_for = details.get("fresh_for_seconds", 600)
    try:
        maximum_age = float(raw_fresh_for)
    except (TypeError, ValueError):
        return False
    if (
        isinstance(raw_fresh_for, bool)
        or not math.isfinite(maximum_age)
        or not 600.0 <= maximum_age <= 172800.0
    ):
        return False
    if now - float(observed_at) > maximum_age or float(observed_at) - now > 60:
        return False
    current_month = datetime.fromtimestamp(now, UTC).strftime("%Y-%m")
    health_month = datetime.fromtimestamp(float(observed_at), UTC).strftime("%Y-%m")
    if current_month != health_month:
        return False
    # Individual values are separately required to have the exact health
    # timestamp. Older gauges from a prior partial-success poll are harmless.
    del gauges
    return True


def _attested_aws_gauge(
    health: dict[str, object] | None, sample: tuple[float, float] | None
) -> tuple[float, float] | None:
    """Reject a value left behind by an earlier, more complete AWS poll."""

    if health is None or sample is None:
        return None
    observed_at = health.get("observed_at")
    if not isinstance(observed_at, (int, float)):
        return None
    return sample if abs(sample[0] - float(observed_at)) < 0.001 else None


def _is_required_verified_path(item: dict[str, object]) -> bool:
    details = item.get("details")
    if not isinstance(details, dict) or details.get("required") is not True:
        return False
    evidence = str(details.get("evidence", "")).strip().lower()
    return evidence not in {
        "configured",
        "configuration",
        "topology",
        "unavailable",
        "unverified",
    }


def _required_path_effective_state(
    item: dict[str, object], *, now: float
) -> tuple[str, bool]:
    state = str(item.get("state", "unknown"))
    if not _is_required_verified_path(item):
        return state, False
    details = item.get("details")
    assert isinstance(details, dict)
    if str(details.get("evidence", "")).strip().lower() != "synthetic_probe":
        return state, False
    try:
        fresh_for = float(details.get("fresh_for_seconds", 600))
        observed_at = float(item["observed_at"])
    except (KeyError, TypeError, ValueError):
        return "unavailable", True
    if fresh_for <= 0 or now - observed_at > fresh_for or observed_at - now > 60:
        return "unavailable", True
    return state, False


def _first_detail(details: dict[str, object], *names: str) -> object | None:
    for name in names:
        value = details.get(name)
        if isinstance(value, (str, int, float, bool)) and not isinstance(value, bytes):
            return value
    return None


def _aws_service_projection(health: dict[str, object]) -> dict[str, object]:
    """Project only non-sensitive AWS status evidence from health details."""

    raw_details = health.get("details")
    details = raw_details if isinstance(raw_details, dict) else {}
    service: dict[str, object] = {
        "status": str(health.get("state", "unknown")),
        "message": str(health.get("message", "")),
        "checked_at": health.get("observed_at"),
    }
    aliases = {
        "instance_state": ("instance_state", "instance_status", "state"),
        "firewall_open_ports": ("firewall_open_ports", "open_ports", "port_states"),
        "alarm_count": ("alarm_count", "alarms_count", "active_alarm_count"),
        "active_alarm_count": ("active_alarm_count",),
        "indeterminate_alarm_count": ("indeterminate_alarm_count",),
        "unsafe_world_open_rule_count": ("unsafe_world_open_rule_count",),
        "invalid_firewall_rule_count": ("invalid_firewall_rule_count",),
        "cpu_utilization_max_percent": (
            "cpu_utilization_max_percent",
            # Read-only compatibility for snapshots produced before the
            # precise Maximum-statistic contract was introduced.
            "cpu_utilization_percent",
            "cpu_utilization_average",
            "cpu_utilization",
            "cpu_percent",
        ),
        "burst_capacity_min_percent": (
            "burst_capacity_min_percent",
            "burst_capacity_percent",
            "burst_capacity_percentage",
            "cpu_burst_capacity_percent",
        ),
        "burst_capacity_time_minutes": (
            "burst_capacity_time_minutes",
            "burst_capacity_minutes",
            "cpu_burst_capacity_time_minutes",
        ),
        "successful_read_count": ("successful_read_count",),
        "failed_read_count": ("failed_read_count",),
        "metric_window": ("metric_window",),
        "failed_calls": ("failed_calls",),
        "failure_categories": ("failure_categories",),
        "status_check_failed_count": ("status_check_failed_count",),
        "network_metric_window": ("network_metric_window",),
        "operational_metric_window": ("operational_metric_window",),
        "missing_data": ("missing_data",),
        "risk_flags": ("risk_flags",),
    }
    for field, names in aliases.items():
        value = _first_detail(details, *names)
        if value is not None:
            service[field] = value
    return service


def _preferred_xray_scope(scopes: set[str]) -> str | None:
    # These layers overlap. Prefer per-user counters, then inbound, then
    # outbound, instead of summing them and double-counting the same traffic.
    for scope in ("user", "inbound", "outbound"):
        if scope in scopes:
            return scope
    return None


class MetricStore:
    """Durable telemetry store.

    Raw counters are persisted together with derived deltas. The first sample
    establishes a baseline. A reset identity change or a decreasing raw value
    records a reset and emits a zero delta, preventing restart spikes.
    """

    def __init__(self, path: str | Path, *, file_mode: int = 0o600) -> None:
        if file_mode not in {0o600, 0o640}:
            raise ValueError("file_mode must be 0600 or 0640")
        self.path = Path(path).expanduser()
        if self.path.exists() and self.path.is_symlink():
            raise ValueError("database path must not be a symbolic link")
        directory_mode = 0o750 if file_mode == 0o640 else 0o700
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=directory_mode)
        self._connection = sqlite3.connect(
            str(self.path),
            timeout=5.0,
            isolation_level=None,
        )
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                raise RuntimeError("SQLite did not enable WAL journal mode")
            self._connection.execute("PRAGMA synchronous = NORMAL")
            self._connection.executescript(_SCHEMA)
            self.path.chmod(file_mode)
            for suffix in ("-wal", "-shm"):
                companion = Path(f"{self.path}{suffix}")
                if companion.exists():
                    companion.chmod(file_mode)
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> MetricStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def journal_mode(self) -> str:
        return str(self._connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()

    def record_gauge(self, observation: GaugeObservation) -> None:
        self.record_batch(gauges=(observation,))

    def record_counter(self, observation: CounterObservation) -> CounterResult:
        return self.record_batch(counters=(observation,))[0]

    def record_health(self, observation: HealthObservation) -> None:
        self.record_batch(health=(observation,))

    def record_batch(
        self,
        *,
        gauges: Iterable[GaugeObservation] = (),
        counters: Iterable[CounterObservation] = (),
        health: Iterable[HealthObservation] = (),
    ) -> list[CounterResult]:
        gauge_rows = tuple(gauges)
        counter_rows = tuple(counters)
        health_rows = tuple(health)
        results: list[CounterResult] = []

        with self._transaction() as connection:
            for observation in gauge_rows:
                connection.execute(
                    """
                    INSERT INTO gauge_samples
                        (observed_at, source, name, labels_json, value)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        observation.observed_at,
                        observation.source,
                        observation.name,
                        _labels_json(observation.labels),
                        observation.value,
                    ),
                )

            for observation in counter_rows:
                labels_json = _labels_json(observation.labels)
                key = _counter_key(observation.source, observation.name, labels_json)
                cursor = connection.execute(
                    """
                    SELECT reset_id, raw_value, observed_at
                    FROM counter_cursors
                    WHERE counter_key = ?
                    """,
                    (key,),
                ).fetchone()

                is_baseline = cursor is None
                is_reset = False
                delta = 0
                if cursor is not None:
                    prior_time = float(cursor["observed_at"])
                    prior_value = int(cursor["raw_value"])
                    if observation.observed_at < prior_time:
                        raise ValueError("counter observations must be time ordered")
                    if observation.observed_at == prior_time and (
                        observation.value != prior_value
                        or observation.reset_id != str(cursor["reset_id"])
                    ):
                        raise ValueError("conflicting counter observations share a timestamp")
                    is_reset = (
                        observation.reset_id != str(cursor["reset_id"])
                        or observation.value < prior_value
                    )
                    if not is_reset:
                        delta = observation.value - prior_value

                connection.execute(
                    """
                    INSERT INTO counter_samples (
                        observed_at, counter_key, source, name, labels_json,
                        reset_id, raw_value, delta_value, is_baseline, is_reset
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        observation.observed_at,
                        key,
                        observation.source,
                        observation.name,
                        labels_json,
                        observation.reset_id,
                        observation.value,
                        delta,
                        int(is_baseline),
                        int(is_reset),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO counter_cursors (
                        counter_key, source, name, labels_json,
                        reset_id, raw_value, observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(counter_key) DO UPDATE SET
                        reset_id = excluded.reset_id,
                        raw_value = excluded.raw_value,
                        observed_at = excluded.observed_at
                    """,
                    (
                        key,
                        observation.source,
                        observation.name,
                        labels_json,
                        observation.reset_id,
                        observation.value,
                        observation.observed_at,
                    ),
                )
                results.append(
                    CounterResult(
                        source=observation.source,
                        name=observation.name,
                        value=observation.value,
                        delta=delta,
                        reset_id=observation.reset_id,
                        is_baseline=is_baseline,
                        is_reset=is_reset,
                        labels=dict(observation.labels),
                    )
                )

            for observation in health_rows:
                connection.execute(
                    """
                    INSERT INTO health_samples
                        (observed_at, component, state, message, details_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        observation.observed_at,
                        observation.component,
                        observation.state.value,
                        observation.message,
                        _canonical_json(dict(observation.details)),
                    ),
                )
        return results

    def apply_retention(
        self,
        *,
        now: float,
        raw_retention_days: int,
        rollup_retention_days: int,
    ) -> dict[str, int]:
        """Compact old counter deltas and transactionally prune raw history.

        Counter cursors are deliberately not pruned. This preserves reset
        detection and the next delta across compaction and service restarts.
        Repeated calls are idempotent because raw rows are deleted in the same
        transaction that adds their deltas to the hourly rollup.
        """

        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError("now must be a finite Unix timestamp")
        for value, name, minimum, maximum in (
            (raw_retention_days, "raw_retention_days", 1, 30),
            (rollup_retention_days, "rollup_retention_days", 30, 800),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        if rollup_retention_days <= raw_retention_days:
            raise ValueError("rollup retention must be longer than raw retention")

        raw_cutoff = float(now) - raw_retention_days * 86400
        rollup_cutoff = float(now) - rollup_retention_days * 86400
        rollup_delete_before = int(rollup_cutoff // 3600) * 3600
        counts: dict[str, int] = {}
        with self._transaction() as connection:
            counts["counter_rows_compacted"] = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM counter_samples
                    WHERE observed_at < ? AND observed_at >= ?
                    """,
                    (raw_cutoff, rollup_cutoff),
                ).fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO counter_hourly_rollups (
                    bucket_start, source, name, labels_json,
                    delta_value, reset_count
                )
                SELECT CAST(observed_at / 3600 AS INTEGER) * 3600,
                       source, name, labels_json,
                       SUM(delta_value), SUM(is_reset)
                FROM counter_samples
                WHERE observed_at < ? AND observed_at >= ?
                GROUP BY CAST(observed_at / 3600 AS INTEGER),
                         source, name, labels_json
                ON CONFLICT(bucket_start, source, name, labels_json)
                DO UPDATE SET
                    delta_value = delta_value + excluded.delta_value,
                    reset_count = reset_count + excluded.reset_count
                """,
                (raw_cutoff, rollup_cutoff),
            )
            for table, key in (
                ("gauge_samples", "gauge_rows_pruned"),
                ("counter_samples", "counter_rows_pruned"),
                ("health_samples", "health_rows_pruned"),
            ):
                cursor = connection.execute(
                    f"DELETE FROM {table} WHERE observed_at < ?",  # noqa: S608 - fixed table allowlist
                    (raw_cutoff,),
                )
                counts[key] = max(0, int(cursor.rowcount))
            cursor = connection.execute(
                "DELETE FROM counter_hourly_rollups WHERE bucket_start < ?",
                (rollup_delete_before,),
            )
            counts["rollup_rows_pruned"] = max(0, int(cursor.rowcount))
        self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return counts

    def overview(self) -> dict[str, object]:
        """Return the latest safe dashboard summary from persisted metrics.

        Missing or stale AWS data is omitted. Network traffic is restricted to
        external interfaces and overlapping Xray scopes are kept separate.
        """

        collected_at_row = self._connection.execute(
            """
            SELECT MAX(observed_at) AS observed_at
            FROM (
                SELECT observed_at FROM gauge_samples
                UNION ALL SELECT observed_at FROM counter_samples
                UNION ALL SELECT observed_at FROM health_samples
            )
            """
        ).fetchone()
        if collected_at_row is None or collected_at_row["observed_at"] is None:
            return {}
        collected_at = float(collected_at_row["observed_at"])
        projection_now = time.time()
        result: dict[str, object] = {"collected_at": collected_at}

        gauge_rows = self._connection.execute(
            """
            SELECT sample.source, sample.name, sample.observed_at, sample.value
            FROM gauge_samples AS sample
            JOIN (
                SELECT source, name, MAX(id) AS id
                FROM gauge_samples
                GROUP BY source, name
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        all_gauges = {
            (str(row["source"]), str(row["name"])): (
                float(row["observed_at"]),
                float(row["value"]),
            )
            for row in gauge_rows
        }
        gauges = {
            name: value
            for (source, name), (_observed_at, value) in all_gauges.items()
            if source == "host"
        }
        host: dict[str, object] = {}
        if "memory_total_bytes" in gauges:
            memory: dict[str, object] = {
                "total_bytes": int(gauges["memory_total_bytes"])
            }
            if "memory_available_bytes" in gauges:
                memory["used_bytes"] = max(
                    0,
                    int(gauges["memory_total_bytes"] - gauges["memory_available_bytes"]),
                )
            host["memory"] = memory
        if "disk_total_bytes" in gauges:
            disk: dict[str, object] = {"total_bytes": int(gauges["disk_total_bytes"])}
            if "disk_available_bytes" in gauges:
                disk["used_bytes"] = max(
                    0,
                    int(gauges["disk_total_bytes"] - gauges["disk_available_bytes"]),
                )
            host["disk"] = disk
        for metric in ("load_1m", "cpu_count", "uptime_seconds"):
            if metric in gauges:
                value: int | float = gauges[metric]
                if metric == "cpu_count":
                    value = int(value)
                host[metric] = value

        cpu_rows = self._connection.execute(
            """
            SELECT sample.name, sample.observed_at, sample.delta_value,
                   sample.is_baseline, sample.is_reset
            FROM counter_samples AS sample
            JOIN (
                SELECT name, MAX(id) AS id
                FROM counter_samples
                WHERE source = 'host'
                  AND name IN ('cpu_total_jiffies', 'cpu_idle_jiffies')
                GROUP BY name
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        cpu = {str(row["name"]): row for row in cpu_rows}
        total_cpu = cpu.get("cpu_total_jiffies")
        idle_cpu = cpu.get("cpu_idle_jiffies")
        if (
            total_cpu is not None
            and idle_cpu is not None
            and float(total_cpu["observed_at"]) == float(idle_cpu["observed_at"])
            and not bool(total_cpu["is_baseline"])
            and not bool(idle_cpu["is_baseline"])
            and not bool(total_cpu["is_reset"])
            and not bool(idle_cpu["is_reset"])
        ):
            utilization = _cpu_utilization_percent(
                int(total_cpu["delta_value"]), int(idle_cpu["delta_value"])
            )
            if utilization is not None:
                host["cpu_utilization_percent"] = utilization
        if host:
            result["host"] = host

        traffic: dict[str, object] = {}
        network_names = tuple(_NETWORK_COUNTER_FIELDS)
        placeholders = ",".join("?" for _ in network_names)
        window_rows = self._connection.execute(
            f"""
            SELECT name, labels_json, delta_value
            FROM counter_samples
            WHERE source = 'host' AND name IN ({placeholders}) AND observed_at >= ?
            """,  # noqa: S608 - placeholders are generated, not caller controlled
            (*network_names, max(0, collected_at - 86400)),
        ).fetchall()
        host_window = {field: 0 for field in _NETWORK_COUNTER_FIELDS.values()}
        for row in window_rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if isinstance(labels, dict) and _is_external_interface(labels):
                field = _NETWORK_COUNTER_FIELDS.get(str(row["name"]))
                if field:
                    host_window[field] += int(row["delta_value"])

        cursor_rows = self._connection.execute(
            f"""
            SELECT source, name, labels_json, raw_value
            FROM counter_cursors
            WHERE (source = 'host' AND name IN ({placeholders}))
               OR (source = 'xray' AND name = 'traffic_bytes_total')
            """,  # noqa: S608 - placeholders are generated, not caller controlled
            network_names,
        ).fetchall()
        host_totals = {field: 0 for field in _NETWORK_COUNTER_FIELDS.values()}
        xray_by_scope: dict[str, dict[str, int]] = {}
        xray_users: dict[str, dict[str, int]] = {}
        for row in cursor_rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(labels, dict):
                continue
            source = str(row["source"])
            name = str(row["name"])
            value = int(row["raw_value"])
            if source == "host" and _is_external_interface(labels):
                field = _NETWORK_COUNTER_FIELDS.get(name)
                if field:
                    host_totals[field] += value
            elif source == "xray":
                scope = str(labels.get("scope", ""))
                direction = str(labels.get("direction", ""))
                if scope in {"user", "inbound", "outbound"} and direction in {
                    "uplink",
                    "downlink",
                }:
                    scoped = xray_by_scope.setdefault(
                        scope, {"uplink": 0, "downlink": 0}
                    )
                    scoped[direction] += value
                    user_hash = labels.get("user_hash")
                    if scope == "user" and _is_safe_xray_user_hash(user_hash):
                        xray_users.setdefault(
                            str(user_hash), {"uplink_bytes": 0, "downlink_bytes": 0}
                        )[f"{direction}_bytes"] += value
        host_traffic: dict[str, object] = {
            f"{field}_window": value for field, value in host_window.items()
        }
        host_traffic.update(
            {f"{field}_total": value for field, value in host_totals.items()}
        )
        traffic["host"] = host_traffic
        xray_scope = _preferred_xray_scope(set(xray_by_scope))
        if xray_scope is not None:
            xray_traffic: dict[str, object] = {
                "uplink_bytes": xray_by_scope[xray_scope]["uplink"],
                "downlink_bytes": xray_by_scope[xray_scope]["downlink"],
                "counter_scope": xray_scope,
            }
            if xray_users:
                xray_traffic["users"] = [
                    {"user_hash": user_hash, **xray_users[user_hash]}
                    for user_hash in sorted(xray_users)
                ]
            traffic["xray"] = xray_traffic

        health_rows = self._connection.execute(
            """
            SELECT sample.component, sample.state, sample.message,
                   sample.observed_at, sample.details_json
            FROM health_samples AS sample
            JOIN (
                SELECT component, MAX(id) AS id
                FROM health_samples
                GROUP BY component
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        health: dict[str, dict[str, object]] = {}
        for row in health_rows:
            try:
                details = json.loads(str(row["details_json"]))
            except (json.JSONDecodeError, TypeError):
                details = {}
            if not isinstance(details, dict):
                details = {}
            health[str(row["component"])] = {
                "state": str(row["state"]),
                "message": str(row["message"]),
                "observed_at": float(row["observed_at"]),
                "details": details,
            }
        states = {component: str(item["state"]) for component, item in health.items()}
        active_states: list[str] = []
        for component, state in states.items():
            if state == "disabled":
                continue
            if component.startswith("path_") and not _is_required_verified_path(
                health[component]
            ):
                continue
            effective_state, _stale = _required_path_effective_state(
                health[component], now=projection_now
            ) if component.startswith("path_") else (state, False)
            active_states.append(effective_state)
        if "unavailable" in active_states:
            result["status"] = "critical"
        elif any(state not in {"healthy"} for state in active_states):
            result["status"] = "degraded"
        elif active_states:
            result["status"] = "healthy"
        elif states:
            result["status"] = "disabled"

        services: dict[str, object] = {}
        if "xray" in states:
            xray_details = health["xray"].get("details", {})
            xray_service: dict[str, object] = {"status": states["xray"]}
            if isinstance(xray_details, dict):
                for detail, field in (
                    ("container_status", "container_status"),
                    ("restart_count", "restart_count"),
                    ("oom_killed", "oom_killed"),
                ):
                    value = xray_details.get(detail)
                    if isinstance(value, (str, int, bool)):
                        xray_service[field] = value
            services["xray"] = xray_service

        aws_health = health.get("aws")
        aws_details = aws_health.get("details", {}) if aws_health else {}
        if aws_health:
            services["aws"] = _aws_service_projection(aws_health)
        if services:
            result["services"] = services

        paths: list[dict[str, object]] = []
        for component, item in health.items():
            if not component.startswith("path_"):
                continue
            details = item["details"]
            assert isinstance(details, dict)
            effective_state, stale = _required_path_effective_state(
                item, now=projection_now
            )
            paths.append(
                {
                    "id": component.removeprefix("path_"),
                    "name": str(details.get("name", component.removeprefix("path_"))),
                    "direction": str(details.get("direction", "observed")),
                    "route": [
                        hop.strip()
                        for hop in str(details.get("route", "")).split(">")
                        if hop.strip()
                    ][:8],
                    "status": "stale"
                    if stale
                    else str(details.get("status", effective_state)),
                    "evidence": str(details.get("evidence", "unavailable")),
                    "required": bool(details.get("required", False)),
                    "stale": stale,
                    "message": str(item["message"]),
                    "checked_at": float(item["observed_at"]),
                }
            )
        if paths:
            result["paths"] = sorted(paths, key=lambda path: str(path["id"]))
        alerts: list[dict[str, object]] = []
        for component, item in health.items():
            if component.startswith("path_") and _is_required_verified_path(item):
                state, stale = _required_path_effective_state(
                    item, now=projection_now
                )
                if state not in {"healthy", "disabled"}:
                    details = item.get("details", {})
                    assert isinstance(details, dict)
                    alerts.append(
                        {
                            "severity": "critical" if state == "unavailable" else "warning",
                            "title": f"{details.get('name', component)} failed",
                            "message": (
                                "Required synthetic path evidence is stale."
                                if stale
                                else str(item.get("message", ""))
                            ),
                            "timestamp": item.get("observed_at"),
                        }
                    )

        network_details = health.get("network_exposure", {}).get("details", {})
        if isinstance(network_details, dict):
            unexpected = str(network_details.get("unexpected_public_ports", ""))
            if unexpected:
                result["status"] = "critical"
                alerts.append(
                    {
                        "severity": "critical",
                        "title": "Unexpected public listener",
                        "message": f"Unexpected public ports: {unexpected}.",
                    }
                )

        fault_delta = sum(
            host_window[field]
            for field in ("rx_errors", "rx_drops", "tx_errors", "tx_drops")
        )
        if fault_delta:
            if result.get("status") == "healthy":
                result["status"] = "degraded"
            alerts.append(
                {
                    "severity": "warning",
                    "title": "Network interface faults increased",
                    "message": (
                        "External-interface errors/drops increased by "
                        f"{fault_delta} in the last 24 hours."
                    ),
                }
            )

        aws_gauges = {
            name: sample
            for (source, name), sample in all_gauges.items()
            if source == "aws"
        }
        if _is_current_aws_snapshot(
            aws_health if isinstance(aws_health, dict) else None,
            aws_gauges,
            now=projection_now,
        ):
            aws_traffic: dict[str, object] = {}
            for metric, field in (
                ("network_in_month_bytes", "network_in_month_bytes"),
                ("network_out_month_bytes", "network_out_month_bytes"),
                ("transfer_used_month_bytes", "transfer_used_bytes"),
            ):
                sample = _attested_aws_gauge(
                    aws_health if isinstance(aws_health, dict) else None,
                    aws_gauges.get(metric),
                )
                if sample is not None:
                    aws_traffic[field] = int(sample[1])
            if any(field in aws_traffic for field in (
                "network_in_month_bytes",
                "network_out_month_bytes",
                "transfer_used_bytes",
            )):
                aws_traffic["usage_source"] = "lightsail_read_only"
            provenance = (
                str(
                    aws_details.get("plan_allocation_provenance")
                    or aws_details.get("allowance_provenance")
                )
                if isinstance(aws_details, dict)
                and (
                    aws_details.get("plan_allocation_provenance")
                    or aws_details.get("allowance_provenance")
                )
                else None
            )
            plan_allocation = _attested_aws_gauge(
                aws_health if isinstance(aws_health, dict) else None,
                aws_gauges.get("transfer_plan_allocation_bytes")
                or aws_gauges.get("transfer_allowance_bytes"),
            )
            if plan_allocation is not None and provenance:
                aws_traffic["plan_allocation_bytes"] = int(plan_allocation[1])
                aws_traffic["plan_allocation_source"] = provenance
            if aws_traffic:
                traffic["aws"] = aws_traffic

        result["traffic"] = traffic
        if alerts:
            result["alerts"] = alerts
        return result

    def series(self, *, since_unix: int, limit: int) -> list[dict[str, int]]:
        """Return ascending one-minute delta buckets for dashboard charts."""

        if isinstance(since_unix, bool) or not isinstance(since_unix, int):
            raise ValueError("since_unix must be an integer Unix timestamp")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
        rows = self._connection.execute(
            """
            SELECT observed_at, source, name, labels_json, delta_value
            FROM (
                SELECT observed_at, source, name, labels_json, delta_value
                FROM counter_samples
                WHERE observed_at >= ?
                UNION ALL
                SELECT bucket_start AS observed_at,
                       source, name, labels_json, delta_value
                FROM counter_hourly_rollups
                WHERE bucket_start >= CAST(? / 3600 AS INTEGER) * 3600
            )
            WHERE (source = 'host' AND name IN (
                       'network_receive_bytes_total',
                       'network_transmit_bytes_total'
                   ))
               OR (source = 'xray' AND name = 'traffic_bytes_total')
            ORDER BY observed_at
            """,
            (since_unix, since_unix),
        ).fetchall()
        buckets: dict[int, dict[str, int]] = {}
        xray_buckets: dict[tuple[str, int], dict[str, int]] = {}
        xray_scopes: set[str] = set()
        for row in rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(labels, dict):
                continue
            bucket = int(float(row["observed_at"]) // 60) * 60
            source = str(row["source"])
            name = str(row["name"])
            delta = int(row["delta_value"])
            if source == "host":
                if not _is_external_interface(labels):
                    continue
                point = buckets.setdefault(bucket, {"timestamp": bucket})
                field = (
                    "host_rx_bytes"
                    if name == "network_receive_bytes_total"
                    else "host_tx_bytes"
                )
                point[field] = point.get(field, 0) + delta
                continue
            scope = str(labels.get("scope", ""))
            direction = str(labels.get("direction", ""))
            if scope not in {"user", "inbound", "outbound"} or direction not in {
                "uplink",
                "downlink",
            }:
                continue
            xray_scopes.add(scope)
            xray_point = xray_buckets.setdefault(
                (scope, bucket), {"uplink": 0, "downlink": 0}
            )
            xray_point[direction] += delta

        preferred_scope = _preferred_xray_scope(xray_scopes)
        if preferred_scope is not None:
            for (scope, bucket), values in xray_buckets.items():
                if scope != preferred_scope:
                    continue
                point = buckets.setdefault(bucket, {"timestamp": bucket})
                point["xray_up_bytes"] = values["uplink"]
                point["xray_down_bytes"] = values["downlink"]

        points = [buckets[key] for key in sorted(buckets)]
        return points[-limit:]

    def fetch_counter_samples(
        self, source: str, name: str
    ) -> list[dict[str, object]]:
        rows = self._connection.execute(
            """
            SELECT observed_at, source, name, labels_json, reset_id,
                   raw_value, delta_value, is_baseline, is_reset
            FROM counter_samples
            WHERE source = ? AND name = ?
            ORDER BY id
            """,
            (source, name),
        ).fetchall()
        return [
            {
                "observed_at": float(row["observed_at"]),
                "source": str(row["source"]),
                "name": str(row["name"]),
                "labels": json.loads(str(row["labels_json"])),
                "reset_id": str(row["reset_id"]),
                "value": int(row["raw_value"]),
                "delta": int(row["delta_value"]),
                "is_baseline": bool(row["is_baseline"]),
                "is_reset": bool(row["is_reset"]),
            }
            for row in rows
        ]

    def fetch_health_samples(self, component: str) -> list[dict[str, object]]:
        rows = self._connection.execute(
            """
            SELECT observed_at, component, state, message, details_json
            FROM health_samples
            WHERE component = ?
            ORDER BY id
            """,
            (component,),
        ).fetchall()
        return [
            {
                "observed_at": float(row["observed_at"]),
                "component": str(row["component"]),
                "state": str(row["state"]),
                "message": str(row["message"]),
                "details": json.loads(str(row["details_json"])),
            }
            for row in rows
        ]
