from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
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
from aws_ops_monitor.web import ReadOnlySQLiteRepository, WebConfig, create_server  # noqa: E402


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

    def test_static_bundle_is_local_and_authenticated(self) -> None:
        with RunningServer() as running:
            status, headers, body = running.request("/", authenticated=True)
            css_status, _, css = running.request("/styles.css", authenticated=True)
            js_status, _, javascript = running.request("/app.js", authenticated=True)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b'AWS Ops Monitor', body)
        self.assertNotIn(b"https://", body)
        self.assertEqual(css_status, 200)
        self.assertIn(b"@media (max-width: 620px)", css)
        self.assertEqual(js_status, 200)
        self.assertNotIn(b"innerHTML", javascript)

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
                            HealthObservation(observed_at, "xray", HealthState.HEALTHY, "xray ok"),
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
        self.assertEqual(sum(point["host_rx_bytes"] for point in points), 250)
        self.assertEqual(sum(point["xray_down_bytes"] for point in points), 600)

    def test_missing_database_fails_closed(self) -> None:
        repository = ReadOnlySQLiteRepository("/definitely/not/a/monitor.sqlite3")
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            repository.overview()


if __name__ == "__main__":
    unittest.main()
