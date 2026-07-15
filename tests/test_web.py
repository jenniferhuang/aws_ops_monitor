from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aws_ops_monitor.models import (  # noqa: E402
    CounterObservation,
    GaugeObservation,
    HealthObservation,
    HealthState,
)
from aws_ops_monitor.store import MetricStore  # noqa: E402
from aws_ops_monitor.web import (  # noqa: E402
    DashboardHandler,
    ReadOnlySQLiteRepository,
    WebConfig,
    create_server,
)


class FakeRepository:
    def __init__(self) -> None:
        self.series_request: tuple[int, int] | None = None

    def overview(self) -> dict[str, object]:
        fake_access_key = "A" + "KIA" + "ABCDEFGHIJKLMNOP"
        return {
            "status": "healthy",
            "collected_at": "2026-07-15T02:00:00Z",
            "public_ip": "203.0.113.10",
            "nested": {
                "client_uuid": "123e4567-e89b-42d3-a456-426614174000",
                "credential": "do-not-return",
                "message": "connected to 198.51.100.20",
                "aws_key": fake_access_key,
            },
            "traffic": {"host": {"rx_bytes_window": 1024, "tx_bytes_window": 2048}},
        }

    def series(self, *, since_unix: int, limit: int) -> list[dict[str, int]]:
        self.series_request = (since_unix, limit)
        return [{"timestamp": since_unix, "host_rx_bytes": 10, "host_tx_bytes": 20}]


class FailingRepository:
    def overview(self) -> dict[str, object]:
        raise RuntimeError("database path and secret must not leak")

    def series(self, *, since_unix: int, limit: int) -> list[dict[str, int]]:
        del since_unix, limit
        raise RuntimeError("database path and secret must not leak")


class RunningServer:
    def __init__(self, repository: object | None = None) -> None:
        self.config = WebConfig(username="monitor", password="s3cure:pass", port=0)
        self.server = create_server(self.config, repository or FakeRepository())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> RunningServer:
        self.thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    @property
    def authorization(self) -> str:
        encoded = base64.b64encode(b"monitor:s3cure:pass").decode("ascii")
        return f"Basic {encoded}"

    def request(
        self,
        path: str,
        *,
        authenticated: bool = False,
        method: str = "GET",
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {"Authorization": self.authorization} if authenticated else {}
        request = Request(self.base_url + path, headers=headers, method=method)
        try:
            with urlopen(request, timeout=2) as response:  # noqa: S310 - loopback test server
                return response.status, dict(response.headers.items()), response.read()
        except HTTPError as error:
            status = error.code
            response_headers = dict(error.headers.items())
            body = error.read()
            error.close()
            return status, response_headers, body


class WebConfigTests(unittest.TestCase):
    def test_credentials_are_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "required"):
            WebConfig(username="", password="")

    def test_non_loopback_bind_is_rejected_by_default(self) -> None:
        with self.assertRaisesRegex(ValueError, "refusing non-loopback"):
            WebConfig(username="monitor", password="password", bind_host="0.0.0.0")

    def test_non_loopback_requires_explicit_override(self) -> None:
        config = WebConfig(
            username="monitor",
            password="password",
            bind_host="0.0.0.0",
            allow_non_loopback=True,
        )
        self.assertTrue(config.allow_non_loopback)

    def test_basic_auth_values_are_bounded_and_unambiguous(self) -> None:
        with self.assertRaisesRegex(ValueError, "username is invalid"):
            WebConfig(username="bad:name", password="password")
        with self.assertRaisesRegex(ValueError, "password is invalid"):
            WebConfig(username="monitor", password="bad\npassword")

    def test_password_file_must_be_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "dashboard-password"
            password_file.write_text("file-secret\n", encoding="utf-8")
            password_file.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "group or others"):
                WebConfig.from_env(
                    {
                        "AWS_OPS_USERNAME": "monitor",
                        "AWS_OPS_PASSWORD_FILE": str(password_file),
                    }
                )
            password_file.chmod(0o600)
            config = WebConfig.from_env(
                {
                    "AWS_OPS_USERNAME": "monitor",
                    "AWS_OPS_PASSWORD_FILE": str(password_file),
                }
            )
            self.assertEqual(config.password, "file-secret")
            with self.assertRaisesRegex(ValueError, "only one"):
                WebConfig.from_env(
                    {
                        "AWS_OPS_USERNAME": "monitor",
                        "AWS_OPS_PASSWORD": "direct-secret",
                        "AWS_OPS_PASSWORD_FILE": str(password_file),
                    }
                )


class DashboardHTTPTests(unittest.TestCase):
    def test_health_is_unauthenticated_and_minimal(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"status": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

    def test_dashboard_and_api_require_basic_auth(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request("/")
            api_status, _, api_body = running.request("/api/overview")
        self.assertEqual(status, 401)
        self.assertIn("Basic realm=", headers["WWW-Authenticate"])
        self.assertEqual(json.loads(body)["error"], "authentication_required")
        self.assertEqual(api_status, 401)
        self.assertEqual(json.loads(api_body)["error"], "authentication_required")

    def test_wrong_basic_auth_is_rejected(self) -> None:
        with RunningServer() as running:
            request = Request(
                running.base_url + "/api/overview",
                headers={"Authorization": "Basic " + base64.b64encode(b"monitor:wrong").decode()},
            )
            with self.assertRaises(HTTPError) as context:
                urlopen(request, timeout=2)  # noqa: S310 - loopback test server
        self.assertEqual(context.exception.code, 401)
        context.exception.close()

    def test_cancelled_response_and_handler_errors_do_not_log_client_addresses(
        self,
    ) -> None:
        handler = object.__new__(DashboardHandler)
        handler.send_response = lambda _status: None
        handler.send_header = lambda _name, _value: None
        handler.end_headers = lambda: None
        handler._security_headers = lambda **_kwargs: None

        def cancelled_write(_payload: bytes) -> None:
            raise BrokenPipeError

        handler.wfile = SimpleNamespace(write=cancelled_write)
        handler.close_connection = False
        handler._send_bytes(HTTPStatus.OK, b"payload", "text/plain")
        self.assertTrue(handler.close_connection)

        with RunningServer() as running:
            with self.assertLogs("aws_ops_monitor.web", level="WARNING") as captured:
                running.server.handle_error(None, ("198.51.100.77", 12345))
        rendered = "\n".join(captured.output)
        self.assertIn("dashboard request handler failed", rendered)
        self.assertNotIn("198.51.100.77", rendered)

    def test_static_bundle_is_local_and_authenticated(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request("/", authenticated=True)
            css_status, _, css = running.request("/styles.css", authenticated=True)
            js_status, _, javascript = running.request("/app.js", authenticated=True)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b'AWS Ops Monitor', body)
        for element_id in (
            b'id="cpu-bar"',
            b'id="nic-faults"',
            b'id="aws-status"',
            b'id="xray-users"',
        ):
            self.assertIn(element_id, body)
        self.assertNotIn(b"https://", body)
        self.assertEqual(css_status, 200)
        self.assertIn(b"@media (max-width: 620px)", css)
        self.assertEqual(js_status, 200)
        self.assertNotIn(b"innerHTML", javascript)
        self.assertIn(b"plan_allocation_source", javascript)
        self.assertIn(b"usage_source", javascript)
        self.assertIn(b"AWS instance MTD transfer", body)
        self.assertIn(b"Not regional pooled billing utilization.", body)
        self.assertIn(
            b"Single-instance month-to-date NetworkIn + NetworkOut", javascript
        )
        transfer_renderer = javascript.split(
            b"function renderInstanceTransfer", 1
        )[1].split(b"function renderResources", 1)[0]
        for forbidden_calculation in (
            b"%",
            b"* 100",
            b"/ allowance",
            b"/ planAllocation",
            b"toFixed",
        ):
            self.assertNotIn(forbidden_calculation, transfer_renderer)
        self.assertNotIn(b"remaining allowance", body.lower())

    def test_overview_scrubs_addresses_identifiers_and_secrets(self) -> None:
        with RunningServer(FakeRepository()) as running:
            status, _, body = running.request("/api/overview", authenticated=True)
        text = body.decode("utf-8")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "healthy")
        self.assertEqual(payload["public_ip"], "[redacted]")
        self.assertNotIn("203.0.113.10", text)
        self.assertNotIn("198.51.100.20", text)
        self.assertNotIn("123e4567-e89b-42d3-a456-426614174000", text)
        self.assertNotIn("do-not-return", text)
        self.assertNotIn("A" + "KIA" + "ABCDEFGHIJKLMNOP", text)

    def test_series_validates_query_and_passes_bounded_options(self) -> None:
        repository = FakeRepository()
        with RunningServer(repository) as running:
            status, _, body = running.request(
                "/api/series?hours=7&limit=25", authenticated=True
            )
            bad_status, _, bad_body = running.request(
                "/api/series?hours=9999", authenticated=True
            )
            unknown_status, _, _ = running.request(
                "/api/series?hours=1&raw_ips=1", authenticated=True
            )
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["hours"], 7)
        self.assertEqual(payload["limit"], 25)
        self.assertEqual(len(payload["points"]), 1)
        self.assertIsNotNone(repository.series_request)
        self.assertEqual(repository.series_request[1], 25)
        self.assertEqual(bad_status, 400)
        self.assertEqual(json.loads(bad_body)["error"], "invalid_query")
        self.assertEqual(unknown_status, 400)

    def test_repository_failures_are_generic_and_explicit(self) -> None:
        with RunningServer(FailingRepository()) as running:
            status, _, body = running.request("/api/overview", authenticated=True)
            series_status, _, series_body = running.request(
                "/api/series", authenticated=True
            )
        self.assertEqual(status, 503)
        self.assertEqual(series_status, 503)
        self.assertEqual(json.loads(body)["status"], "unknown")
        self.assertEqual(json.loads(body)["error"], "collector_store_unavailable")
        self.assertNotIn(b"database path", body)
        self.assertNotIn(b"database path", series_body)

    def test_head_does_not_send_body(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request("/", authenticated=True, method="HEAD")
        self.assertEqual(status, 200)
        self.assertGreater(int(headers["Content-Length"]), 0)
        self.assertEqual(body, b"")

    def test_mutating_methods_are_rejected_with_security_headers(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request(
                "/api/overview", authenticated=True, method="POST"
            )
        self.assertEqual(status, 405)
        self.assertEqual(json.loads(body)["error"], "method_not_allowed")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Python", headers["Server"])


class ReadOnlySQLiteRepositoryTests(unittest.TestCase):
    def test_repository_closes_every_read_connection(self) -> None:
        class TrackedConnection:
            def __init__(self, connection: sqlite3.Connection) -> None:
                self.connection = connection
                self.closed = False

            def __getattr__(self, name: str) -> object:
                return getattr(self.connection, name)

            def __enter__(self) -> TrackedConnection:
                return self

            def __exit__(self, *args: object) -> bool | None:
                # sqlite3.Connection.__exit__ commits or rolls back, but does
                # not close. Preserve that behavior so this catches the
                # easy-to-miss lifecycle mistake.
                return self.connection.__exit__(*args)

            def close(self) -> None:
                self.closed = True
                self.connection.close()

        class TrackingRepository(ReadOnlySQLiteRepository):
            def __init__(self, path: Path) -> None:
                super().__init__(path)
                self.connections: list[TrackedConnection] = []

            def _connect(self) -> object:
                connection = TrackedConnection(super()._connect())
                self.connections.append(connection)
                return connection

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database):
                pass
            repository = TrackingRepository(database)

            repository.overview()
            repository.series(since_unix=int(time.time()) - 60, limit=100)

        self.assertEqual(len(repository.connections), 2)
        self.assertTrue(all(connection.closed for connection in repository.connections))

    def test_projects_store_data_without_double_counting_xray_scopes(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                for offset, receive, transmit, up, down in (
                    (0, 1_000, 2_000, 3_000, 4_000),
                    (30, 1_250, 2_500, 3_300, 4_600),
                ):
                    observed_at = now + offset
                    store.record_batch(
                        gauges=(
                            GaugeObservation(observed_at, "host", "uptime_seconds", 100 + offset),
                            GaugeObservation(observed_at, "host", "load_1m", 0.2),
                            GaugeObservation(observed_at, "host", "memory_total_bytes", 1_000),
                            GaugeObservation(observed_at, "host", "memory_available_bytes", 400),
                            GaugeObservation(observed_at, "host", "disk_total_bytes", 10_000),
                            GaugeObservation(observed_at, "host", "disk_available_bytes", 8_000),
                        ),
                        counters=(
                            CounterObservation(
                                observed_at,
                                "host",
                                "network_receive_bytes_total",
                                receive,
                                "boot-a",
                                {"interface": "ens5"},
                            ),
                            CounterObservation(
                                observed_at,
                                "host",
                                "network_transmit_bytes_total",
                                transmit,
                                "boot-a",
                                {"interface": "ens5"},
                            ),
                            CounterObservation(
                                observed_at,
                                "xray",
                                "traffic_bytes_total",
                                up,
                                "xray-a",
                                {"scope": "user", "direction": "uplink", "user_hash": "usr_safe"},
                            ),
                            CounterObservation(
                                observed_at,
                                "xray",
                                "traffic_bytes_total",
                                down,
                                "xray-a",
                                {"scope": "user", "direction": "downlink", "user_hash": "usr_safe"},
                            ),
                            # An overlapping inbound counter must not be added to user traffic.
                            CounterObservation(
                                observed_at,
                                "xray",
                                "traffic_bytes_total",
                                down * 2,
                                "xray-a",
                                {"scope": "inbound", "direction": "downlink", "tag": "vpn"},
                            ),
                        ),
                        health=(
                            HealthObservation(observed_at, "host", HealthState.HEALTHY, "host ok"),
                            HealthObservation(
                                observed_at,
                                "xray",
                                HealthState.HEALTHY,
                                "xray ok",
                                {
                                    "container_status": "running",
                                    "restart_count": 2,
                                    "oom_killed": False,
                                },
                            ),
                        ),
                    )

            repository = ReadOnlySQLiteRepository(database)
            overview = repository.overview()
            points = repository.series(since_unix=int(now - 1), limit=100)

        self.assertEqual(overview["status"], "healthy")
        self.assertEqual(overview["host"]["memory"]["used_bytes"], 600)
        self.assertEqual(overview["traffic"]["host"]["rx_bytes_window"], 250)
        self.assertEqual(overview["traffic"]["host"]["tx_bytes_window"], 500)
        self.assertEqual(overview["traffic"]["xray"]["uplink_bytes"], 3_300)
        self.assertEqual(overview["traffic"]["xray"]["downlink_bytes"], 4_600)
        self.assertEqual(overview["services"]["xray"]["container_status"], "running")
        self.assertEqual(overview["services"]["xray"]["restart_count"], 2)
        self.assertFalse(overview["services"]["xray"]["oom_killed"])
        self.assertEqual(sum(point["host_rx_bytes"] for point in points), 250)
        self.assertEqual(sum(point["xray_down_bytes"] for point in points), 600)

    def test_missing_database_fails_closed(self) -> None:
        repository = ReadOnlySQLiteRepository("/definitely/not/a/monitor.sqlite3")
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            repository.overview()

    def test_projection_filters_virtual_nics_and_exposes_operational_evidence(self) -> None:
        now = time.time()
        safe_user = "usr_abcdef0123456789abcdef01"
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                for observed_at, factor in ((now - 30, 1), (now, 2)):
                    counters = [
                        CounterObservation(
                            observed_at,
                            "host",
                            "cpu_total_jiffies",
                            1_000 + (factor - 1) * 200,
                            "boot-a",
                        ),
                        CounterObservation(
                            observed_at,
                            "host",
                            "cpu_idle_jiffies",
                            400 + (factor - 1) * 50,
                            "boot-a",
                        ),
                    ]
                    for interface, scale in (
                        ("ens5", 1),
                        ("br-deadbeef", 100),
                        ("veth1234", 100),
                        ("wg0", 100),
                    ):
                        for name, value in (
                            ("network_receive_bytes_total", 100 * factor * scale),
                            ("network_transmit_bytes_total", 200 * factor * scale),
                            ("network_receive_packets_total", 10 * factor * scale),
                            ("network_transmit_packets_total", 20 * factor * scale),
                            ("network_receive_errors_total", factor - 1),
                            ("network_receive_drops_total", 0),
                            ("network_transmit_errors_total", 0),
                            ("network_transmit_drops_total", 0),
                        ):
                            counters.append(
                                CounterObservation(
                                    observed_at,
                                    "host",
                                    name,
                                    value,
                                    "boot-a",
                                    {"interface": interface},
                                )
                            )
                    counters.extend(
                        (
                            CounterObservation(
                                observed_at,
                                "xray",
                                "traffic_bytes_total",
                                50 * factor,
                                "xray-a",
                                {
                                    "scope": "user",
                                    "direction": "uplink",
                                    "user_hash": safe_user,
                                },
                            ),
                            CounterObservation(
                                observed_at,
                                "xray",
                                "traffic_bytes_total",
                                80 * factor,
                                "xray-a",
                                {
                                    "scope": "user",
                                    "direction": "downlink",
                                    "user_hash": safe_user,
                                },
                            ),
                        )
                    )
                    store.record_batch(counters=counters)

                store.record_batch(
                    gauges=(
                        GaugeObservation(now, "host", "cpu_count", 2),
                        GaugeObservation(now, "aws", "network_in_month_bytes", 123),
                        GaugeObservation(
                            now, "aws", "transfer_plan_allocation_bytes", 1_000
                        ),
                    ),
                    health=(
                        HealthObservation(now, "host", HealthState.HEALTHY, "host ok"),
                        HealthObservation(
                            now,
                            "xray",
                            HealthState.HEALTHY,
                            "xray ok",
                            {
                                "container_status": "running",
                                "restart_count": 4,
                                "oom_killed": False,
                            },
                        ),
                        HealthObservation(
                            now,
                            "aws",
                            HealthState.HEALTHY,
                            "AWS ok",
                            {
                                "metric_window": "current_month_utc",
                                "metric_period_seconds": 300,
                                "instance_state": "running",
                                "firewall_open_ports": "22/tcp,80/tcp",
                                "alarm_count": 2,
                                "active_alarm_count": 1,
                                "cpu_utilization_max_percent": 14.0,
                                "burst_capacity_min_percent": 91.0,
                                "plan_allocation_provenance": (
                                    "operator_bundle_configuration"
                                ),
                            },
                        ),
                        HealthObservation(
                            now,
                            "path_listener",
                            HealthState.UNAVAILABLE,
                            "required listener missing",
                            {
                                "name": "Required listener",
                                "required": True,
                                "evidence": "local_listener",
                            },
                        ),
                        HealthObservation(
                            now,
                            "path_optional",
                            HealthState.UNAVAILABLE,
                            "optional check failed",
                            {
                                "name": "Optional check",
                                "required": False,
                                "evidence": "synthetic_probe",
                            },
                        ),
                    ),
                )

            repository = ReadOnlySQLiteRepository(database)
            overview = repository.overview()
            points = repository.series(since_unix=int(now - 60), limit=100)

        self.assertEqual(overview["status"], "critical")
        self.assertEqual(overview["host"]["cpu_utilization_percent"], 75.0)
        host = overview["traffic"]["host"]
        self.assertEqual(host["rx_bytes_window"], 100)
        self.assertEqual(host["tx_bytes_total"], 400)
        self.assertEqual(host["rx_packets_window"], 10)
        self.assertEqual(host["rx_errors_window"], 1)
        self.assertEqual(sum(point["host_rx_bytes"] for point in points), 100)
        self.assertEqual(
            overview["traffic"]["xray"]["users"],
            [{"user_hash": safe_user, "uplink_bytes": 100, "downlink_bytes": 160}],
        )
        self.assertEqual(overview["services"]["xray"]["restart_count"], 4)
        aws = overview["services"]["aws"]
        self.assertEqual(aws["instance_state"], "running")
        self.assertEqual(aws["firewall_open_ports"], "22/tcp,80/tcp")
        self.assertEqual(aws["active_alarm_count"], 1)
        self.assertEqual(aws["cpu_utilization_max_percent"], 14.0)
        self.assertEqual(aws["burst_capacity_min_percent"], 91.0)
        aws_traffic = overview["traffic"]["aws"]
        self.assertEqual(aws_traffic["network_in_month_bytes"], 123)
        self.assertNotIn("network_out_month_bytes", aws_traffic)
        self.assertEqual(aws_traffic["usage_source"], "lightsail_read_only")
        self.assertEqual(
            aws_traffic["plan_allocation_source"], "operator_bundle_configuration"
        )
        titles = {alert["title"] for alert in overview["alerts"]}
        self.assertIn("Required listener failed", titles)
        self.assertNotIn("Optional check failed", titles)
        self.assertIn("Network interface faults increased", titles)

    def test_aws_traffic_is_hidden_for_unavailable_stale_or_wrong_month_health(self) -> None:
        now = time.time()
        cases = (
            (now, HealthState.UNAVAILABLE, "current_month_utc"),
            (now - 2_000, HealthState.HEALTHY, "current_month_utc"),
            (now - 40 * 86400, HealthState.HEALTHY, "current_month_utc"),
            (now, HealthState.HEALTHY, "previous_month"),
        )
        for observed_at, state, metric_window in cases:
            with self.subTest(state=state.value, observed_at=observed_at, window=metric_window):
                with tempfile.TemporaryDirectory() as directory:
                    database = Path(directory) / "metrics.sqlite3"
                    with MetricStore(database) as store:
                        store.record_batch(
                            gauges=(
                                GaugeObservation(
                                    observed_at,
                                    "aws",
                                    "network_in_month_bytes",
                                    123,
                                ),
                            ),
                            health=(
                                HealthObservation(
                                    observed_at,
                                    "aws",
                                    state,
                                    "AWS state",
                                    {
                                        "metric_window": metric_window,
                                        "metric_period_seconds": 300,
                                    },
                                ),
                            ),
                        )
                    overview = ReadOnlySQLiteRepository(database).overview()
                self.assertNotIn("aws", overview["traffic"])

    def test_stale_required_probe_overrides_fresh_global_snapshot(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                store.record_batch(
                    health=(
                        HealthObservation(
                            now, "host", HealthState.HEALTHY, "fresh host"
                        ),
                        HealthObservation(
                            now - 601,
                            "path_cloudflare_xray",
                            HealthState.HEALTHY,
                            "probe was healthy",
                            {
                                "name": "Public Xray WebSocket",
                                "required": True,
                                "evidence": "synthetic_probe",
                                "fresh_for_seconds": 600,
                                "status": "verified",
                            },
                        ),
                    )
                )
            overview = ReadOnlySQLiteRepository(database).overview()

        self.assertEqual(overview["status"], "critical")
        path = next(
            path for path in overview["paths"] if path["id"] == "cloudflare_xray"
        )
        self.assertTrue(path["stale"])
        self.assertEqual(path["status"], "stale")
        self.assertIn(
            "Required synthetic path evidence is stale.",
            {alert["message"] for alert in overview["alerts"]},
        )


if __name__ == "__main__":
    unittest.main()
