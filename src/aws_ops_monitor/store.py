"""SQLite persistence with reset-safe monotonic counter deltas."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
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


def _is_external_interface(labels: dict[str, object]) -> bool:
    name = str(labels.get("interface", ""))
    return bool(name) and name != "lo" and not name.startswith(_VIRTUAL_INTERFACE_PREFIXES)


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

    def overview(self) -> dict[str, object]:
        """Return the latest safe dashboard summary from persisted metrics.

        Missing AWS control-plane or service data is omitted. The method uses
        only observed health states and never turns missing data into a
        synthetic healthy state.
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
        result: dict[str, object] = {"collected_at": collected_at}

        gauge_rows = self._connection.execute(
            """
            SELECT sample.name, sample.value
            FROM gauge_samples AS sample
            JOIN (
                SELECT name, MAX(id) AS id
                FROM gauge_samples
                WHERE source = 'host'
                GROUP BY name
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        gauges = {str(row["name"]): float(row["value"]) for row in gauge_rows}
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
        if host:
            result["host"] = host

        traffic: dict[str, object] = {}
        points = self.series(since_unix=max(0, int(collected_at - 86400)), limit=2000)
        host_traffic: dict[str, int] = {}
        rx_window = sum(int(point.get("host_rx_bytes", 0)) for point in points)
        tx_window = sum(int(point.get("host_tx_bytes", 0)) for point in points)
        if rx_window or tx_window:
            host_traffic.update(
                {"rx_bytes_window": rx_window, "tx_bytes_window": tx_window}
            )

        cursor_rows = self._connection.execute(
            """
            SELECT source, name, labels_json, raw_value
            FROM counter_cursors
            WHERE (source = 'host' AND name IN (
                       'network_receive_bytes_total',
                       'network_transmit_bytes_total'
                   ))
               OR (source = 'xray' AND name = 'traffic_bytes_total')
            """
        ).fetchall()
        host_totals = {
            "network_receive_bytes_total": 0,
            "network_transmit_bytes_total": 0,
        }
        xray_by_scope: dict[str, dict[str, int]] = {}
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
                host_totals[name] += value
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
        if any(host_totals.values()):
            host_traffic.update(
                {
                    "rx_bytes_total": host_totals["network_receive_bytes_total"],
                    "tx_bytes_total": host_totals["network_transmit_bytes_total"],
                }
            )
        if host_traffic:
            traffic["host"] = host_traffic
        xray_scope = _preferred_xray_scope(set(xray_by_scope))
        if xray_scope is not None:
            traffic["xray"] = {
                "uplink_bytes": xray_by_scope[xray_scope]["uplink"],
                "downlink_bytes": xray_by_scope[xray_scope]["downlink"],
                "counter_scope": xray_scope,
            }
        if traffic:
            result["traffic"] = traffic

        health_rows = self._connection.execute(
            """
            SELECT sample.component, sample.state
            FROM health_samples AS sample
            JOIN (
                SELECT component, MAX(id) AS id
                FROM health_samples
                GROUP BY component
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        states = {str(row["component"]): str(row["state"]) for row in health_rows}
        active_states = [state for state in states.values() if state != "disabled"]
        if active_states:
            rank = {"healthy": 0, "degraded": 1, "unavailable": 2}
            result["status"] = max(active_states, key=lambda state: rank.get(state, 3))
        elif states:
            result["status"] = "disabled"
        if "xray" in states:
            result["services"] = {"xray": {"status": states["xray"]}}
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
            FROM counter_samples
            WHERE observed_at >= ?
              AND (
                    (source = 'host' AND name IN (
                        'network_receive_bytes_total',
                        'network_transmit_bytes_total'
                    ))
                 OR (source = 'xray' AND name = 'traffic_bytes_total')
              )
            ORDER BY observed_at, id
            """,
            (since_unix,),
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
