"""Loopback-only, read-only HTTP dashboard for AWS Ops Monitor.

The web process intentionally has no collector or Docker privileges.  A caller
injects a repository that implements ``overview()`` and ``series()``; the
small adapter below also recognises a few equivalent method names so the web
layer can stay decoupled from the SQLite writer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import socket
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import parse_qs, quote, urlsplit

from .store import (
    _NETWORK_COUNTER_FIELDS,
    _attested_aws_gauge,
    _aws_service_projection,
    _cpu_utilization_percent,
    _is_current_aws_snapshot,
    _is_external_interface,
    _is_required_verified_path,
    _is_safe_xray_user_hash,
    _required_path_effective_state,
)

LOGGER = logging.getLogger(__name__)

_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
_SENSITIVE_KEY_PARTS = {
    "accesskey",
    "authorization",
    "credential",
    "password",
    "privatekey",
    "secret",
    "token",
    "uuid",
}
_IP_KEY_PARTS = {"clientip", "ip", "publicip", "remoteip", "sourceip"}
_UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
_IPV4_RE = re.compile(
    r"(?<![0-9])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9])"
)
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:A3T|AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}\b")
_KEY_PART_RE = re.compile(r"[^a-z0-9]+")


class Repository(Protocol):
    """Minimum read-only repository contract used by the HTTP layer."""

    def overview(self) -> Mapping[str, Any]: ...

    def series(self, *, since_unix: int, limit: int) -> Sequence[Mapping[str, Any]]: ...


class RepositoryUnavailable(RuntimeError):
    """Raised when a current snapshot cannot be read."""


class RepositoryAdapter:
    """Adapt common store method names without granting the web tier writes."""

    def __init__(self, repository: object) -> None:
        self._repository = repository

    def overview(self) -> Mapping[str, Any]:
        value = self._call(("overview", "get_overview", "latest_overview"))
        if not isinstance(value, Mapping):
            raise RepositoryUnavailable("overview is not a mapping")
        return value

    def series(self, *, since_unix: int, limit: int) -> Sequence[Mapping[str, Any]]:
        value = self._call(
            ("series", "get_series", "read_series"), since_unix=since_unix, limit=limit
        )
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise RepositoryUnavailable("series is not a sequence")
        return value

    def _call(self, names: tuple[str, ...], **kwargs: Any) -> Any:
        for name in names:
            method = getattr(self._repository, name, None)
            if callable(method):
                return method(**kwargs)
        raise RepositoryUnavailable(f"repository has no {names[0]} reader")


class UnavailableRepository:
    """Fail visibly when the collector/store has not been wired in yet."""

    def overview(self) -> Mapping[str, Any]:
        raise RepositoryUnavailable("collector/store unavailable")

    def series(self, *, since_unix: int, limit: int) -> Sequence[Mapping[str, Any]]:
        del since_unix, limit
        raise RepositoryUnavailable("collector/store unavailable")


class ReadOnlySQLiteRepository:
    """Build dashboard projections from the collector database, without writes.

    Connections use SQLite URI ``mode=ro`` and ``query_only``.  The dashboard
    process therefore neither creates the database/schema nor advances WAL
    state; the separately privileged collector remains the only writer.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def overview(self) -> Mapping[str, Any]:
        now = time.time()
        with closing(self._connect()) as connection:
            gauges = self._latest_gauges(connection)
            health = self._latest_health(connection)
            host_window = self._host_window(connection, now - 86400)
            host_totals = self._host_totals(connection)
            xray_totals = self._xray_totals(connection)
            cpu_utilization = self._cpu_utilization(connection)

        latest_time = max(
            [row["observed_at"] for row in health.values()]
            + [item[0] for item in gauges.values()]
            + [0.0]
        )
        alerts: list[dict[str, object]] = []
        overall = _overall_health(health, now=now)
        if latest_time <= 0:
            overall = "unknown"
            alerts.append(
                {
                    "severity": "warning",
                    "title": "No monitoring samples",
                    "message": "The collector has not written a readable snapshot.",
                }
            )
        elif now - latest_time > 300:
            overall = "critical"
            alerts.append(
                {
                    "severity": "critical",
                    "title": "Collector data is stale",
                    "message": "The newest stored sample is more than five minutes old.",
                    "timestamp": latest_time,
                }
            )
        network_health = health.get("network_exposure", {})
        network_details = network_health.get("details", {})
        unexpected_public = (
            str(network_details.get("unexpected_public_ports", ""))
            if isinstance(network_details, Mapping)
            else ""
        )
        if unexpected_public:
            overall = "critical"
            alerts.append(
                {
                    "severity": "critical",
                    "title": "Unexpected public listener",
                    "message": f"Unexpected public ports: {unexpected_public}.",
                    "timestamp": network_health.get("observed_at"),
                }
            )
        for component, item in health.items():
            if component.startswith("path_"):
                details = item.get("details", {})
                effective_state, stale = _required_path_effective_state(
                    dict(item), now=now
                )
                if _is_required_verified_path(dict(item)) and effective_state not in {
                    "healthy",
                    "disabled",
                }:
                    alerts.append(
                        {
                            "severity": (
                                "critical"
                                if effective_state == "unavailable"
                                else "warning"
                            ),
                            "title": f"{details.get('name', 'Required path')} failed",
                            "message": (
                                "Required synthetic path evidence is stale."
                                if stale
                                else item["message"]
                            ),
                            "timestamp": item["observed_at"],
                        }
                    )
                continue
            if (
                component == "network_exposure" and unexpected_public
                or item["state"] in {"healthy", "disabled"}
            ):
                continue
            if item["state"] != "healthy":
                severity = "critical" if item["state"] == "unavailable" else "warning"
                alerts.append(
                    {
                        "severity": severity,
                        "title": f"{component.title()} is {item['state']}",
                        "message": item["message"],
                        "timestamp": item["observed_at"],
                    }
                )
        if "aws" not in health or health.get("aws", {}).get("state") == "disabled":
            alerts.append(
                {
                    "severity": "info",
                    "title": "AWS control-plane metrics unavailable",
                    "message": "Host traffic is an estimate until least-privilege AWS read access is configured.",
                }
            )

        fault_delta = sum(
            host_window[field]
            for field in ("rx_errors", "rx_drops", "tx_errors", "tx_drops")
        )
        if fault_delta:
            if overall == "healthy":
                overall = "degraded"
            alerts.append(
                {
                    "severity": "warning",
                    "title": "Network interface faults increased",
                    "message": (
                        "External-interface errors/drops increased by "
                        f"{fault_delta} in the last 24 hours."
                    ),
                    "timestamp": latest_time,
                }
            )

        memory_total = _gauge_value(gauges, "host", "memory_total_bytes")
        memory_available = _gauge_value(gauges, "host", "memory_available_bytes")
        disk_total = _gauge_value(gauges, "host", "disk_total_bytes")
        disk_available = _gauge_value(gauges, "host", "disk_available_bytes")
        host: dict[str, object] = {
            "uptime_seconds": _gauge_value(gauges, "host", "uptime_seconds"),
            "load_1m": _gauge_value(gauges, "host", "load_1m"),
            "cpu_count": _gauge_value(gauges, "host", "cpu_count"),
            "cpu_utilization_percent": cpu_utilization,
            "memory": {
                "total_bytes": memory_total,
                "used_bytes": _used_bytes(memory_total, memory_available),
            },
            "disk": {
                "total_bytes": disk_total,
                "used_bytes": _used_bytes(disk_total, disk_available),
            },
        }
        xray_health = health.get("xray", {})
        xray_details = xray_health.get("details", {})
        aws_health = health.get("aws", {})
        aws_details = aws_health.get("details", {})
        aws_gauges = {
            name: sample
            for (source, name), sample in gauges.items()
            if source == "aws"
        }
        aws_traffic: dict[str, object] = {}
        if _is_current_aws_snapshot(
            dict(aws_health) if isinstance(aws_health, Mapping) else None,
            aws_gauges,
            now=now,
        ):
            for metric, field in (
                ("network_in_month_bytes", "network_in_month_bytes"),
                ("network_out_month_bytes", "network_out_month_bytes"),
                ("transfer_used_month_bytes", "transfer_used_bytes"),
            ):
                sample = _attested_aws_gauge(
                    dict(aws_health) if isinstance(aws_health, Mapping) else None,
                    aws_gauges.get(metric),
                )
                if sample is not None:
                    aws_traffic[field] = int(sample[1])
            if any(
                field in aws_traffic
                for field in (
                    "network_in_month_bytes",
                    "network_out_month_bytes",
                    "transfer_used_bytes",
                )
            ):
                aws_traffic["usage_source"] = "lightsail_read_only"
            plan_allocation_provenance = (
                str(
                    aws_details.get("plan_allocation_provenance")
                    or aws_details.get("allowance_provenance")
                )
                if isinstance(aws_details, Mapping)
                and (
                    aws_details.get("plan_allocation_provenance")
                    or aws_details.get("allowance_provenance")
                )
                else None
            )
            plan_allocation = _attested_aws_gauge(
                dict(aws_health) if isinstance(aws_health, Mapping) else None,
                aws_gauges.get("transfer_plan_allocation_bytes")
                or aws_gauges.get("transfer_allowance_bytes"),
            )
            if plan_allocation is not None and plan_allocation_provenance:
                aws_traffic["plan_allocation_bytes"] = int(plan_allocation[1])
                aws_traffic["plan_allocation_source"] = plan_allocation_provenance
        paths = _path_projection(health, now=now)
        host_traffic: dict[str, object] = {
            f"{field}_window": value for field, value in host_window.items()
        }
        host_traffic.update(
            {f"{field}_total": value for field, value in host_totals.items()}
        )
        xray_traffic: dict[str, object] = {
            "uplink_bytes": xray_totals["uplink"],
            "downlink_bytes": xray_totals["downlink"],
        }
        users = xray_totals.get("users")
        if isinstance(users, list) and users:
            xray_traffic["users"] = users
        traffic: dict[str, object] = {
            "host": host_traffic,
            "xray": xray_traffic,
        }
        if aws_traffic:
            traffic["aws"] = aws_traffic

        services: dict[str, object] = {
            "xray": {
                "status": xray_health.get("state", "unknown"),
                "container_status": xray_details.get("container_status")
                if isinstance(xray_details, Mapping)
                else None,
                "restart_count": xray_details.get("restart_count")
                if isinstance(xray_details, Mapping)
                else None,
                "oom_killed": xray_details.get("oom_killed")
                if isinstance(xray_details, Mapping)
                else None,
            }
        }
        if isinstance(aws_health, Mapping) and aws_health:
            services["aws"] = _aws_service_projection(dict(aws_health))

        return {
            "status": overall,
            "collected_at": latest_time or None,
            "host": host,
            "traffic": traffic,
            "services": services,
            "paths": paths,
            "alerts": alerts,
        }

    def series(self, *, since_unix: int, limit: int) -> Sequence[Mapping[str, Any]]:
        now = int(time.time())
        bucket_seconds = max(1, math.ceil(max(1, now - since_unix) / limit))
        with closing(self._connect()) as connection:
            host_rows = connection.execute(
                """
                SELECT observed_at, name, labels_json, delta_value
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
                WHERE source = 'host'
                  AND name IN ('network_receive_bytes_total', 'network_transmit_bytes_total')
                ORDER BY observed_at ASC
                """,
                (since_unix, since_unix),
            ).fetchall()
            xray_scope = self._preferred_xray_scope(connection)
            xray_rows: list[sqlite3.Row] = []
            if xray_scope:
                xray_rows = connection.execute(
                    """
                    SELECT CAST((observed_at - ?) / ? AS INTEGER) AS bucket,
                           MIN(observed_at) AS observed_at,
                           SUM(CASE WHEN json_extract(labels_json, '$.direction') = 'uplink'
                                    THEN delta_value ELSE 0 END) AS uplink,
                           SUM(CASE WHEN json_extract(labels_json, '$.direction') = 'downlink'
                                    THEN delta_value ELSE 0 END) AS downlink
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
                    WHERE source = 'xray'
                      AND name = 'traffic_bytes_total'
                      AND json_extract(labels_json, '$.scope') = ?
                    GROUP BY bucket
                    ORDER BY bucket ASC
                    LIMIT ?
                    """,
                    (
                        since_unix,
                        bucket_seconds,
                        since_unix,
                        since_unix,
                        xray_scope,
                        limit,
                    ),
                ).fetchall()

        points: dict[int, dict[str, object]] = {}
        for row in host_rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(labels, dict) or not _is_external_interface(labels):
                continue
            observed_at = float(row["observed_at"])
            bucket = int((observed_at - since_unix) // bucket_seconds)
            point = points.setdefault(
                bucket,
                {
                    "timestamp": observed_at,
                    "host_rx_bytes": 0,
                    "host_tx_bytes": 0,
                    "xray_up_bytes": 0,
                    "xray_down_bytes": 0,
                },
            )
            point["timestamp"] = min(float(point["timestamp"]), observed_at)
            field = (
                "host_rx_bytes"
                if str(row["name"]) == "network_receive_bytes_total"
                else "host_tx_bytes"
            )
            point[field] = int(point[field]) + int(row["delta_value"])
        for row in xray_rows:
            bucket = int(row["bucket"])
            point = points.setdefault(
                bucket,
                {
                    "timestamp": float(row["observed_at"]),
                    "host_rx_bytes": 0,
                    "host_tx_bytes": 0,
                    "xray_up_bytes": 0,
                    "xray_down_bytes": 0,
                },
            )
            point["timestamp"] = min(float(point["timestamp"]), float(row["observed_at"]))
            point["xray_up_bytes"] = int(row["uplink"] or 0)
            point["xray_down_bytes"] = int(row["downlink"] or 0)
        return [points[bucket] for bucket in sorted(points)][-limit:]

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file() or self.path.is_symlink():
            raise RepositoryUnavailable("monitor database is unavailable")
        uri = f"file:{quote(str(self.path.resolve()), safe='/')}?mode=ro"
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=2.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 2000")
            return connection
        except sqlite3.Error as error:
            if connection is not None:
                connection.close()
            raise RepositoryUnavailable("monitor database is unavailable") from error

    @staticmethod
    def _latest_gauges(connection: sqlite3.Connection) -> dict[tuple[str, str], tuple[float, float]]:
        rows = connection.execute(
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
        return {
            (str(row["source"]), str(row["name"])): (
                float(row["observed_at"]),
                float(row["value"]),
            )
            for row in rows
        }

    @staticmethod
    def _latest_health(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
        rows = connection.execute(
            """
            SELECT sample.observed_at, sample.component, sample.state,
                   sample.message, sample.details_json
            FROM health_samples AS sample
            JOIN (
                SELECT component, MAX(id) AS id
                FROM health_samples
                GROUP BY component
            ) AS latest ON latest.id = sample.id
            """
        ).fetchall()
        result: dict[str, dict[str, object]] = {}
        for row in rows:
            try:
                details = json.loads(str(row["details_json"]))
            except (json.JSONDecodeError, TypeError):
                details = {}
            if not isinstance(details, Mapping):
                details = {}
            result[str(row["component"])] = {
                "observed_at": float(row["observed_at"]),
                "state": str(row["state"]),
                "message": str(row["message"]),
                "details": dict(details),
            }
        return result

    @staticmethod
    def _host_window(connection: sqlite3.Connection, since: float) -> dict[str, int]:
        names = tuple(_NETWORK_COUNTER_FIELDS)
        placeholders = ",".join("?" for _ in names)
        rows = connection.execute(
            f"""
            SELECT name, labels_json, delta_value
            FROM counter_samples
            WHERE source = 'host'
              AND name IN ({placeholders})
              AND observed_at >= ?
            """,  # noqa: S608 - placeholders are generated, not caller controlled
            (*names, since),
        ).fetchall()
        values = {field: 0 for field in _NETWORK_COUNTER_FIELDS.values()}
        for row in rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(labels, dict) or not _is_external_interface(labels):
                continue
            field = _NETWORK_COUNTER_FIELDS.get(str(row["name"]))
            if field:
                values[field] += int(row["delta_value"])
        return values

    @staticmethod
    def _host_totals(connection: sqlite3.Connection) -> dict[str, int]:
        names = tuple(_NETWORK_COUNTER_FIELDS)
        placeholders = ",".join("?" for _ in names)
        rows = connection.execute(
            f"""
            SELECT name, labels_json, raw_value
            FROM counter_cursors
            WHERE source = 'host'
              AND name IN ({placeholders})
            """,  # noqa: S608 - placeholders are generated, not caller controlled
            names,
        ).fetchall()
        values = {field: 0 for field in _NETWORK_COUNTER_FIELDS.values()}
        for row in rows:
            try:
                labels = json.loads(str(row["labels_json"]))
            except json.JSONDecodeError:
                continue
            if not isinstance(labels, dict) or not _is_external_interface(labels):
                continue
            field = _NETWORK_COUNTER_FIELDS.get(str(row["name"]))
            if field:
                values[field] += int(row["raw_value"])
        return values

    def _xray_totals(self, connection: sqlite3.Connection) -> dict[str, object]:
        scope = self._preferred_xray_scope(connection)
        if not scope:
            return {"uplink": 0, "downlink": 0, "users": []}
        rows = connection.execute(
            """
            SELECT json_extract(labels_json, '$.direction') AS direction,
                   SUM(raw_value) AS value
            FROM counter_cursors
            WHERE source = 'xray'
              AND name = 'traffic_bytes_total'
              AND json_extract(labels_json, '$.scope') = ?
            GROUP BY direction
            """,
            (scope,),
        ).fetchall()
        values = {str(row["direction"]): int(row["value"] or 0) for row in rows}
        users: list[dict[str, object]] = []
        if scope == "user":
            user_rows = connection.execute(
                """
                SELECT labels_json, raw_value
                FROM counter_cursors
                WHERE source = 'xray'
                  AND name = 'traffic_bytes_total'
                  AND json_extract(labels_json, '$.scope') = 'user'
                """
            ).fetchall()
            by_user: dict[str, dict[str, int]] = {}
            for row in user_rows:
                try:
                    labels = json.loads(str(row["labels_json"]))
                except json.JSONDecodeError:
                    continue
                if not isinstance(labels, dict):
                    continue
                user_hash = labels.get("user_hash")
                direction = str(labels.get("direction", ""))
                if not _is_safe_xray_user_hash(user_hash) or direction not in {
                    "uplink",
                    "downlink",
                }:
                    continue
                user = by_user.setdefault(
                    str(user_hash), {"uplink_bytes": 0, "downlink_bytes": 0}
                )
                user[f"{direction}_bytes"] += int(row["raw_value"])
            users = [
                {"user_hash": user_hash, **by_user[user_hash]}
                for user_hash in sorted(by_user)
            ]
        return {
            "uplink": values.get("uplink", 0),
            "downlink": values.get("downlink", 0),
            "users": users,
        }

    @staticmethod
    def _cpu_utilization(connection: sqlite3.Connection) -> float | None:
        rows = connection.execute(
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
        values = {str(row["name"]): row for row in rows}
        total = values.get("cpu_total_jiffies")
        idle = values.get("cpu_idle_jiffies")
        if (
            total is None
            or idle is None
            or float(total["observed_at"]) != float(idle["observed_at"])
            or bool(total["is_baseline"])
            or bool(idle["is_baseline"])
            or bool(total["is_reset"])
            or bool(idle["is_reset"])
        ):
            return None
        return _cpu_utilization_percent(
            int(total["delta_value"]), int(idle["delta_value"])
        )

    @staticmethod
    def _preferred_xray_scope(connection: sqlite3.Connection) -> str | None:
        rows = connection.execute(
            """
            SELECT DISTINCT json_extract(labels_json, '$.scope') AS scope
            FROM counter_cursors
            WHERE source = 'xray' AND name = 'traffic_bytes_total'
            """
        ).fetchall()
        scopes = {str(row["scope"]) for row in rows if row["scope"] is not None}
        for candidate in ("user", "inbound", "outbound"):
            if candidate in scopes:
                return candidate
        return None

@dataclass(frozen=True, slots=True)
class WebConfig:
    username: str
    password: str
    bind_host: str = "127.0.0.1"
    port: int = 8787
    allow_non_loopback: bool = False
    database_path: Path | None = None

    def __post_init__(self) -> None:
        if not self.username or not self.password:
            raise ValueError("dashboard Basic Auth username and password are required")
        if (
            ":" in self.username
            or len(self.username) > 128
            or any(ord(character) < 32 for character in self.username)
        ):
            raise ValueError("dashboard Basic Auth username is invalid")
        if len(self.password) > 4096 or any(ord(character) < 32 for character in self.password):
            raise ValueError("dashboard Basic Auth password is invalid")
        if not (0 <= self.port <= 65535):
            raise ValueError("dashboard port must be between 0 and 65535")
        if not self.allow_non_loopback and not _is_loopback_bind(self.bind_host):
            raise ValueError(
                "refusing non-loopback dashboard bind; use a private tunnel or set "
                "the explicit secure override"
            )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> WebConfig:
        values = os.environ if env is None else env
        password = values.get("AWS_OPS_PASSWORD", "")
        password_file = values.get("AWS_OPS_PASSWORD_FILE", "")
        if password and password_file:
            raise ValueError("set only one of AWS_OPS_PASSWORD and AWS_OPS_PASSWORD_FILE")
        if password_file:
            password = _read_private_password_file(Path(password_file))
        return cls(
            username=values.get("AWS_OPS_USERNAME", ""),
            password=password,
            bind_host=values.get("AWS_OPS_BIND_HOST", "127.0.0.1"),
            port=_parse_port(values.get("AWS_OPS_PORT", "8787")),
            allow_non_loopback=_parse_bool(values.get("AWS_OPS_ALLOW_NON_LOOPBACK", "false")),
            database_path=Path(
                values.get("AWS_OPS_DB_PATH", str(_default_database_path()))
            ).expanduser(),
        )


class MonitorHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        config: WebConfig,
        repository: RepositoryAdapter,
    ) -> None:
        self.config = config
        self.repository = repository
        super().__init__(server_address, handler_class)

    def handle_error(self, request: object, client_address: object) -> None:
        """Keep handler failures generic and omit client addresses from logs."""

        del request, client_address
        LOGGER.warning("dashboard request handler failed", exc_info=False)


class MonitorHTTPServerV6(MonitorHTTPServer):
    address_family = socket.AF_INET6


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve a fixed static bundle and two authenticated JSON endpoints."""

    server: MonitorHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "AWSOpsMonitor"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        request = urlsplit(self.path)
        if request.path == "/healthz":
            self._send_json(
                HTTPStatus.OK,
                {"status": "ok"},
                authenticated=False,
            )
            return

        if not self._is_authenticated():
            self._send_unauthorized()
            return

        if request.path == "/api/overview":
            self._send_overview()
            return
        if request.path == "/api/series":
            self._send_series(request.query)
            return
        static = _STATIC_FILES.get(request.path)
        if static is not None:
            self._send_static(*static)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        request = urlsplit(self.path)
        if request.path != "/healthz" and not self._is_authenticated():
            self._send_unauthorized(head_only=True)
            return
        if request.path == "/healthz":
            self._send_bytes(HTTPStatus.OK, b"", "application/json; charset=utf-8")
            return
        static = _STATIC_FILES.get(request.path)
        if static is not None:
            payload = _static_bytes(static[0])
            self._send_bytes(HTTPStatus.OK, payload, static[1], head_only=True)
            return
        self._send_bytes(
            HTTPStatus.NOT_FOUND,
            b"",
            "application/json; charset=utf-8",
            head_only=True,
        )

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_TRACE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def do_CONNECT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._method_not_allowed()

    def log_message(self, format: str, *args: object) -> None:
        # Do not put client addresses, query strings, or Authorization values in logs.
        del format, args

    def _send_overview(self) -> None:
        try:
            overview = self.server.repository.overview()
        except Exception:
            LOGGER.warning("monitor repository overview unavailable", exc_info=False)
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "status": "unknown",
                    "error": "collector_store_unavailable",
                    "message": "No current monitoring snapshot is available.",
                },
            )
            return
        self._send_json(HTTPStatus.OK, _scrub(overview))

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method_not_allowed"})

    def _send_series(self, raw_query: str) -> None:
        try:
            hours, limit = _series_options(raw_query)
        except ValueError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_query", "message": str(error)})
            return
        since_unix = int((datetime.now(UTC) - timedelta(hours=hours)).timestamp())
        try:
            series = self.server.repository.series(since_unix=since_unix, limit=limit)
        except Exception:
            LOGGER.warning("monitor repository series unavailable", exc_info=False)
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "status": "unknown",
                    "error": "collector_store_unavailable",
                    "message": "No monitoring history is available.",
                },
            )
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "hours": hours,
                "limit": limit,
                "points": _scrub(list(series)),
            },
        )

    def _send_static(self, filename: str, content_type: str) -> None:
        try:
            payload = _static_bytes(filename)
        except (FileNotFoundError, OSError):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._send_bytes(HTTPStatus.OK, payload, content_type)

    def _is_authenticated(self) -> bool:
        header = self.headers.get("Authorization", "")
        if len(header) > 4096 or not header.startswith("Basic "):
            return False
        encoded = header[6:].strip()
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return False
        try:
            username, password = decoded.decode("utf-8").split(":", 1)
        except (UnicodeDecodeError, ValueError):
            return False
        expected_user = self.server.config.username.encode("utf-8")
        expected_password = self.server.config.password.encode("utf-8")
        username_matches = hmac.compare_digest(username.encode("utf-8"), expected_user)
        password_matches = hmac.compare_digest(password.encode("utf-8"), expected_password)
        return username_matches & password_matches

    def _send_unauthorized(self, *, head_only: bool = False) -> None:
        body = b'{"error":"authentication_required"}'
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="AWS Ops Monitor", charset="UTF-8"')
        self._security_headers(authenticated=False)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: object,
        *,
        authenticated: bool = True,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            authenticated=authenticated,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        payload: bytes,
        content_type: str,
        *,
        authenticated: bool = True,
        head_only: bool = False,
    ) -> None:
        self.send_response(status)
        self._security_headers(authenticated=authenticated)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if not head_only:
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                # Browsers routinely cancel in-flight refreshes when a tab is
                # closed or reloaded. This is not a service failure and must
                # not fall through to socketserver's address-bearing traceback.
                self.close_connection = True

    def _security_headers(self, *, authenticated: bool) -> None:
        del authenticated  # Reserved for a stricter authenticated CSP if needed.
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Security-Policy", _content_security_policy())
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")


def create_server(config: WebConfig, repository: object | None = None) -> MonitorHTTPServer:
    """Create, but do not start, the loopback dashboard server."""

    if repository is None and config.database_path is not None:
        repository = ReadOnlySQLiteRepository(config.database_path)
    adapted = RepositoryAdapter(repository if repository is not None else UnavailableRepository())
    server_type: type[MonitorHTTPServer] = (
        MonitorHTTPServerV6 if ":" in config.bind_host else MonitorHTTPServer
    )
    return server_type(
        (config.bind_host, config.port),
        DashboardHandler,
        config=config,
        repository=adapted,
    )


def serve(config: WebConfig, repository: object | None = None) -> None:
    """Serve until interrupted; callers should inject the read-only store."""

    server = create_server(config, repository)
    LOGGER.info("AWS Ops Monitor dashboard listening on a private loopback socket")
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def main(argv: Sequence[str] | None = None, repository: object | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the private AWS Ops Monitor dashboard")
    parser.add_argument("--check-config", action="store_true", help="validate settings and exit")
    args = parser.parse_args(argv)
    try:
        config = WebConfig.from_env()
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.check_config:
        return 0
    serve(config, repository)
    return 0


def _parse_port(raw: str) -> int:
    try:
        return int(raw)
    except ValueError as error:
        raise ValueError("AWS_OPS_PORT must be an integer") from error


def _parse_bool(raw: str) -> bool:
    normalised = raw.strip().lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError("AWS_OPS_ALLOW_NON_LOOPBACK must be true or false")


def _read_private_password_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("AWS_OPS_PASSWORD_FILE must be a regular, non-symbolic file")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ValueError("AWS_OPS_PASSWORD_FILE must not be accessible by group or others")
    value = path.read_text(encoding="utf-8").strip("\r\n")
    if not value:
        raise ValueError("AWS_OPS_PASSWORD_FILE is empty")
    return value


def _is_loopback_bind(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if host.lower() != "localhost":
        return False
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False
    return bool(addresses) and all(ipaddress.ip_address(address).is_loopback for address in addresses)


def _default_database_path() -> Path:
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "aws-ops-monitor" / "metrics.sqlite3"


def _gauge_value(
    gauges: Mapping[tuple[str, str], tuple[float, float]], source: str, name: str
) -> float | None:
    sample = gauges.get((source, name))
    return sample[1] if sample is not None else None


def _used_bytes(total: float | None, available: float | None) -> float | None:
    if total is None or available is None:
        return None
    return max(0.0, total - available)


def _path_projection(
    health: Mapping[str, Mapping[str, object]],
    *,
    now: float,
) -> list[dict[str, object]]:
    paths: list[dict[str, object]] = []
    for component, item in health.items():
        if not component.startswith("path_"):
            continue
        raw_details = item.get("details", {})
        details = raw_details if isinstance(raw_details, Mapping) else {}
        effective_state, stale = _required_path_effective_state(dict(item), now=now)
        route = [
            hop.strip()
            for hop in str(details.get("route", "")).split(">")
            if hop.strip()
        ][:8]
        paths.append(
            {
                "id": component.removeprefix("path_"),
                "name": str(details.get("name", component.removeprefix("path_"))),
                "direction": str(details.get("direction", "observed")),
                "route": route,
                "status": "stale"
                if stale
                else str(details.get("status", effective_state)),
                "evidence": str(details.get("evidence", "unavailable")),
                "required": details.get("required") is True,
                "stale": stale,
                "message": str(item.get("message", "")),
                "checked_at": item.get("observed_at"),
            }
        )
    order = {
        "cloudflare_xray": 0,
        "xray_egress": 1,
        "ssh": 2,
        "stats_service": 3,
        "private_dashboard": 4,
    }
    paths.sort(key=lambda item: order.get(str(item["id"]), 100))
    return paths


def _overall_health(
    health: Mapping[str, Mapping[str, object]], *, now: float
) -> str:
    active: dict[str, str] = {}
    for component, item in health.items():
        state = str(item.get("state", "unknown"))
        if state == "disabled":
            continue
        if component.startswith("path_"):
            if not _is_required_verified_path(dict(item)):
                continue
            state, _stale = _required_path_effective_state(dict(item), now=now)
        active[component] = state
    if not active:
        return "unknown"
    states = set(active.values())
    if "unavailable" in states:
        return "critical"
    if states & {"degraded", "disabled", "unknown"}:
        return "degraded"
    if states == {"healthy"}:
        return "healthy"
    return "unknown"


def _series_options(raw_query: str) -> tuple[int, int]:
    values = parse_qs(raw_query, keep_blank_values=True, strict_parsing=False)
    if set(values) - {"hours", "limit"}:
        raise ValueError("only hours and limit are supported")
    try:
        hours = int(values.get("hours", ["24"])[0])
        limit = int(values.get("limit", ["1000"])[0])
    except (TypeError, ValueError) as error:
        raise ValueError("hours and limit must be integers") from error
    if not 1 <= hours <= 24 * 90:
        raise ValueError("hours must be between 1 and 2160")
    if not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")
    return hours, limit


def _static_bytes(filename: str) -> bytes:
    resource = files("aws_ops_monitor").joinpath("static", filename)
    return resource.read_bytes()


def _content_security_policy() -> str:
    return (
        "default-src 'self'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'"
    )


def _normalise_key(key: object) -> set[str]:
    value = str(key).lower()
    compact = "".join(_KEY_PART_RE.split(value))
    parts = {part for part in _KEY_PART_RE.split(value) if part}
    parts.add(compact)
    return parts


def _scrub(value: Any, key: object | None = None) -> Any:
    """Remove secrets, raw addresses, and UUIDs from data returned to the UI."""

    if key is not None:
        key_parts = _normalise_key(key)
        if key_parts & _SENSITIVE_KEY_PARTS or key_parts & _IP_KEY_PARTS:
            return "[redacted]"
    if isinstance(value, Mapping):
        return {str(child_key): _scrub(child_value, child_key) for child_key, child_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(item) for item in value]
    if isinstance(value, str):
        try:
            if ipaddress.ip_address(value).version in {4, 6}:
                return "[redacted-ip]"
        except ValueError:
            pass
        scrubbed = _UUID_RE.sub("[redacted-id]", value)
        scrubbed = _IPV4_RE.sub("[redacted-ip]", scrubbed)
        scrubbed = _AWS_ACCESS_KEY_RE.sub("[redacted-key]", scrubbed)
        return scrubbed
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


if __name__ == "__main__":  # pragma: no cover - exercised through the installed CLI
    raise SystemExit(main())
