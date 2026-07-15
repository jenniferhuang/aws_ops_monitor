from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest

from aws_ops_monitor.models import (
    CounterObservation,
    GaugeObservation,
    HealthObservation,
    HealthState,
)
from aws_ops_monitor.store import MetricStore
from aws_ops_monitor.web import ReadOnlySQLiteRepository


class StoreTests(unittest.TestCase):
    def test_wal_permissions_health_and_counter_cursor_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.sqlite3"
            with MetricStore(path) as store:
                self.assertEqual(store.journal_mode(), "wal")
                store.record_gauge(GaugeObservation(1.0, "host", "load_1m", 0.25))
                store.record_health(
                    HealthObservation(
                        1.0,
                        "host",
                        HealthState.HEALTHY,
                        "host metrics collected",
                        {"interface_count": 2},
                    )
                )
                first = store.record_counter(
                    CounterObservation(
                        1.0,
                        "host",
                        "network_receive_bytes_total",
                        100,
                        "boot:one",
                        {"interface": "eth0"},
                    )
                )
                self.assertTrue(first.is_baseline)
                self.assertEqual(first.delta, 0)

            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with MetricStore(path) as reopened:
                second = reopened.record_counter(
                    CounterObservation(
                        2.0,
                        "host",
                        "network_receive_bytes_total",
                        145,
                        "boot:one",
                        {"interface": "eth0"},
                    )
                )
                self.assertFalse(second.is_baseline)
                self.assertFalse(second.is_reset)
                self.assertEqual(second.delta, 45)
                health = reopened.fetch_health_samples("host")
                self.assertEqual(health[0]["state"], "healthy")
                self.assertEqual(health[0]["details"], {"interface_count": 2})

    def test_out_of_order_counter_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            observation = CounterObservation(5.0, "host", "packets", 10, "boot:one")
            store.record_counter(observation)
            with self.assertRaisesRegex(ValueError, "time ordered"):
                store.record_counter(
                    CounterObservation(4.0, "host", "packets", 11, "boot:one")
                )
            samples = store.fetch_counter_samples("host", "packets")
            self.assertEqual(len(samples), 1)

    def test_group_read_mode_is_explicitly_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.sqlite3"
            with MetricStore(path, file_mode=0o640):
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o640)

    def test_overview_and_series_avoid_virtual_and_overlapping_xray_counters(self) -> None:
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            store.record_batch(
                gauges=(
                    GaugeObservation(61, "host", "memory_total_bytes", 1000),
                    GaugeObservation(61, "host", "memory_available_bytes", 400),
                    GaugeObservation(61, "host", "disk_total_bytes", 2000),
                    GaugeObservation(61, "host", "disk_available_bytes", 500),
                    GaugeObservation(61, "host", "load_1m", 0.5),
                    GaugeObservation(61, "host", "cpu_count", 2),
                    GaugeObservation(61, "host", "uptime_seconds", 100),
                ),
                health=(
                    HealthObservation(61, "host", HealthState.HEALTHY, "ok"),
                    HealthObservation(61, "xray", HealthState.DEGRADED, "partial"),
                ),
            )

            def counter(
                at: float,
                source: str,
                name: str,
                value: int,
                labels: dict[str, str],
            ) -> CounterObservation:
                return CounterObservation(at, source, name, value, "reset:one", labels)

            for at, rx, tx, xray_up, xray_down in (
                (1, 100, 200, 10, 20),
                (61, 150, 260, 15, 30),
            ):
                store.record_batch(
                    counters=(
                        counter(
                            at,
                            "host",
                            "network_receive_bytes_total",
                            rx,
                            {"interface": "eth0"},
                        ),
                        counter(
                            at,
                            "host",
                            "network_transmit_bytes_total",
                            tx,
                            {"interface": "eth0"},
                        ),
                        counter(
                            at,
                            "host",
                            "network_receive_bytes_total",
                            rx * 10,
                            {"interface": "lo"},
                        ),
                        counter(
                            at,
                            "xray",
                            "traffic_bytes_total",
                            xray_up,
                            {
                                "scope": "user",
                                "direction": "uplink",
                                "user_hash": "usr_abc",
                            },
                        ),
                        counter(
                            at,
                            "xray",
                            "traffic_bytes_total",
                            xray_down,
                            {
                                "scope": "user",
                                "direction": "downlink",
                                "user_hash": "usr_abc",
                            },
                        ),
                        counter(
                            at,
                            "xray",
                            "traffic_bytes_total",
                            xray_up,
                            {
                                "scope": "inbound",
                                "direction": "uplink",
                                "tag": "proxy",
                            },
                        ),
                    )
                )

            overview = store.overview()
            self.assertEqual(overview["status"], "degraded")
            self.assertEqual(overview["host"]["memory"]["used_bytes"], 600)
            self.assertEqual(overview["host"]["disk"]["used_bytes"], 1500)
            self.assertEqual(overview["host"]["cpu_count"], 2)
            self.assertEqual(overview["traffic"]["host"]["rx_bytes_window"], 50)
            self.assertEqual(overview["traffic"]["host"]["tx_bytes_window"], 60)
            self.assertEqual(overview["traffic"]["host"]["rx_bytes_total"], 150)
            self.assertEqual(overview["traffic"]["xray"]["uplink_bytes"], 15)
            self.assertEqual(overview["traffic"]["xray"]["downlink_bytes"], 30)
            self.assertEqual(overview["traffic"]["xray"]["counter_scope"], "user")

            points = store.series(since_unix=0, limit=10)
            latest = points[-1]
            self.assertEqual(latest["timestamp"], 60)
            self.assertEqual(latest["host_rx_bytes"], 50)
            self.assertEqual(latest["host_tx_bytes"], 60)
            self.assertEqual(latest["xray_up_bytes"], 5)
            self.assertEqual(latest["xray_down_bytes"], 10)

    def test_overview_projects_cpu_nic_faults_users_and_required_paths(self) -> None:
        now = time.time()
        safe_user = "usr_0123456789abcdef01234567"
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            for observed_at, cpu_total, cpu_idle, multiplier in (
                (now - 30, 1_000, 400, 1),
                (now, 1_200, 450, 2),
            ):
                counters = [
                    CounterObservation(
                        observed_at, "host", "cpu_total_jiffies", cpu_total, "boot-a"
                    ),
                    CounterObservation(
                        observed_at, "host", "cpu_idle_jiffies", cpu_idle, "boot-a"
                    ),
                ]
                for interface, scale in (("ens5", 1), ("docker0", 100), ("tailscale0", 100)):
                    for name, value in (
                        ("network_receive_bytes_total", 100 * multiplier * scale),
                        ("network_transmit_bytes_total", 200 * multiplier * scale),
                        ("network_receive_packets_total", 10 * multiplier * scale),
                        ("network_transmit_packets_total", 20 * multiplier * scale),
                        ("network_receive_errors_total", multiplier - 1),
                        ("network_receive_drops_total", multiplier - 1),
                        ("network_transmit_errors_total", 0),
                        ("network_transmit_drops_total", multiplier - 1),
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
                            300 * multiplier,
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
                            400 * multiplier,
                            "xray-a",
                            {
                                "scope": "user",
                                "direction": "downlink",
                                "user_hash": safe_user,
                            },
                        ),
                        CounterObservation(
                            observed_at,
                            "xray",
                            "traffic_bytes_total",
                            999 * multiplier,
                            "xray-a",
                            {
                                "scope": "user",
                                "direction": "uplink",
                                "user_hash": "123e4567-e89b-42d3-a456-426614174000",
                            },
                        ),
                    )
                )
                store.record_batch(counters=counters)

            store.record_batch(
                gauges=(GaugeObservation(now, "host", "cpu_count", 2),),
                health=(
                    HealthObservation(now, "host", HealthState.HEALTHY, "host ok"),
                    HealthObservation(
                        now,
                        "xray",
                        HealthState.HEALTHY,
                        "xray ok",
                        {
                            "container_status": "running",
                            "restart_count": 3,
                            "oom_killed": False,
                        },
                    ),
                    HealthObservation(
                        now,
                        "path_required",
                        HealthState.UNAVAILABLE,
                        "listener missing",
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
                        "optional probe failed",
                        {
                            "name": "Optional probe",
                            "required": False,
                            "evidence": "synthetic_probe",
                        },
                    ),
                    HealthObservation(
                        now,
                        "path_unverified",
                        HealthState.UNAVAILABLE,
                        "diagram only",
                        {
                            "name": "Unverified path",
                            "required": True,
                            "evidence": "topology",
                        },
                    ),
                ),
            )

            overview = store.overview()

        self.assertEqual(overview["status"], "critical")
        self.assertEqual(overview["host"]["cpu_utilization_percent"], 75.0)
        host = overview["traffic"]["host"]
        self.assertEqual(host["rx_bytes_window"], 100)
        self.assertEqual(host["tx_bytes_window"], 200)
        self.assertEqual(host["rx_packets_window"], 10)
        self.assertEqual(host["tx_packets_total"], 40)
        self.assertEqual(host["rx_errors_window"], 1)
        self.assertEqual(host["rx_drops_window"], 1)
        self.assertEqual(host["tx_drops_window"], 1)
        users = overview["traffic"]["xray"]["users"]
        self.assertEqual(users, [{"user_hash": safe_user, "uplink_bytes": 600, "downlink_bytes": 800}])
        self.assertEqual(overview["services"]["xray"]["restart_count"], 3)
        titles = {alert["title"] for alert in overview["alerts"]}
        self.assertIn("Required listener failed", titles)
        self.assertIn("Network interface faults increased", titles)
        self.assertNotIn("Optional probe failed", titles)
        self.assertNotIn("Unverified path failed", titles)

    def test_optional_or_unverified_path_failure_does_not_change_overall_health(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            store.record_batch(
                health=(
                    HealthObservation(now, "host", HealthState.HEALTHY, "ok"),
                    HealthObservation(
                        now,
                        "path_optional",
                        HealthState.UNAVAILABLE,
                        "not required",
                        {"required": False, "evidence": "synthetic_probe"},
                    ),
                    HealthObservation(
                        now,
                        "path_unverified",
                        HealthState.UNAVAILABLE,
                        "not verified",
                        {"required": True, "evidence": "unverified"},
                    ),
                )
            )
            overview = store.overview()
        self.assertEqual(overview["status"], "healthy")
        self.assertNotIn("alerts", overview)

    def test_stale_required_synthetic_path_is_critical_while_host_is_fresh(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            store.record_batch(
                health=(
                    HealthObservation(now, "host", HealthState.HEALTHY, "fresh host"),
                    HealthObservation(
                        now - 700,
                        "path_required_probe",
                        HealthState.HEALTHY,
                        "probe was healthy",
                        {
                            "name": "Required synthetic probe",
                            "required": True,
                            "evidence": "synthetic_probe",
                            "fresh_for_seconds": 600,
                            "status": "verified",
                        },
                    ),
                    HealthObservation(
                        now - 700,
                        "path_optional_probe",
                        HealthState.HEALTHY,
                        "optional probe was healthy",
                        {
                            "name": "Optional synthetic probe",
                            "required": False,
                            "evidence": "synthetic_probe",
                            "fresh_for_seconds": 600,
                        },
                    ),
                )
            )
            overview = store.overview()

        self.assertEqual(overview["status"], "critical")
        required = next(
            path for path in overview["paths"] if path["id"] == "required_probe"
        )
        optional = next(
            path for path in overview["paths"] if path["id"] == "optional_probe"
        )
        self.assertTrue(required["stale"])
        self.assertEqual(required["status"], "stale")
        self.assertFalse(optional["stale"])
        self.assertIn(
            "Required synthetic path evidence is stale.",
            {alert["message"] for alert in overview["alerts"]},
        )

    def test_generic_required_path_flag_controls_health_without_type_hardcoding(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            store.record_batch(
                health=(
                    HealthObservation(now, "host", HealthState.HEALTHY, "ok"),
                    HealthObservation(
                        now,
                        "path_future_probe_type",
                        HealthState.UNAVAILABLE,
                        "required path failed",
                        {"name": "Future probe", "required": True},
                    ),
                )
            )
            overview = store.overview()
        self.assertEqual(overview["status"], "critical")
        self.assertIn("Future probe failed", {item["title"] for item in overview["alerts"]})

    def test_aws_usage_requires_current_attested_health_and_keeps_sources_separate(self) -> None:
        now = time.time()
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            store.record_batch(
                gauges=(
                    GaugeObservation(now - 60, "aws", "network_in_month_bytes", 111),
                    GaugeObservation(now - 60, "aws", "transfer_used_month_bytes", 333),
                    GaugeObservation(now, "aws", "network_out_month_bytes", 222),
                    GaugeObservation(
                        now, "aws", "transfer_plan_allocation_bytes", 1_000
                    ),
                ),
                health=(
                    HealthObservation(now, "host", HealthState.HEALTHY, "ok"),
                    HealthObservation(
                        now,
                        "aws",
                        HealthState.DEGRADED,
                        "partial AWS telemetry",
                        {
                            "metric_window": "current_month_utc",
                            "metric_period_seconds": 300,
                            "instance_state": "running",
                            "firewall_open_ports": "22/tcp,80/tcp",
                            "active_alarm_count": 1,
                            "cpu_utilization_max_percent": 12.5,
                            "burst_capacity_min_percent": 88.0,
                            "plan_allocation_provenance": (
                                "operator_bundle_configuration"
                            ),
                        },
                    ),
                ),
            )
            overview = store.overview()
            aws = overview["traffic"]["aws"]
            self.assertNotIn("network_in_month_bytes", aws)
            self.assertNotIn("transfer_used_bytes", aws)
            self.assertEqual(aws["network_out_month_bytes"], 222)
            self.assertEqual(aws["usage_source"], "lightsail_read_only")
            self.assertEqual(aws["plan_allocation_bytes"], 1_000)
            self.assertEqual(
                aws["plan_allocation_source"], "operator_bundle_configuration"
            )
            self.assertNotIn("source", aws)
            service = overview["services"]["aws"]
            self.assertEqual(service["instance_state"], "running")
            self.assertEqual(service["active_alarm_count"], 1)
            self.assertEqual(service["cpu_utilization_max_percent"], 12.5)
            self.assertEqual(service["burst_capacity_min_percent"], 88.0)

            store.record_health(
                HealthObservation(
                    now + 1,
                    "aws",
                    HealthState.UNAVAILABLE,
                    "AWS unavailable",
                    {"metric_window": "current_month_utc"},
                )
            )
            unavailable = store.overview()
        self.assertNotIn("aws", unavailable["traffic"])

    def test_retention_rolls_counters_hourly_prunes_raw_and_preserves_cursor(self) -> None:
        now = time.time()
        old = now - 2 * 86400
        recent = now - 60
        labels = {"interface": "ens5"}
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                for observed_at, value in (
                    (old, 100),
                    (old + 60, 150),
                    (recent, 200),
                ):
                    store.record_counter(
                        CounterObservation(
                            observed_at,
                            "host",
                            "network_receive_bytes_total",
                            value,
                            "boot:one",
                            labels,
                        )
                    )
                store.record_batch(
                    gauges=(
                        GaugeObservation(old, "host", "load_1m", 0.1),
                        GaugeObservation(recent, "host", "load_1m", 0.2),
                    ),
                    health=(
                        HealthObservation(old, "host", HealthState.HEALTHY, "old"),
                        HealthObservation(
                            recent, "host", HealthState.HEALTHY, "recent"
                        ),
                    ),
                )

                counts = store.apply_retention(
                    now=now,
                    raw_retention_days=1,
                    rollup_retention_days=30,
                )
                self.assertEqual(counts["counter_rows_compacted"], 2)
                self.assertEqual(counts["counter_rows_pruned"], 2)
                self.assertEqual(counts["gauge_rows_pruned"], 1)
                self.assertEqual(counts["health_rows_pruned"], 1)
                raw = store.fetch_counter_samples(
                    "host", "network_receive_bytes_total"
                )
                self.assertEqual([sample["delta"] for sample in raw], [50])
                writer_points = store.series(
                    since_unix=int(now - 3 * 86400), limit=1000
                )
                self.assertEqual(
                    sum(point.get("host_rx_bytes", 0) for point in writer_points),
                    100,
                )

                repeated = store.apply_retention(
                    now=now,
                    raw_retention_days=1,
                    rollup_retention_days=30,
                )
                self.assertEqual(repeated["counter_rows_compacted"], 0)
                self.assertEqual(
                    sum(
                        point.get("host_rx_bytes", 0)
                        for point in store.series(
                            since_unix=int(now - 3 * 86400), limit=1000
                        )
                    ),
                    100,
                )

                next_result = store.record_counter(
                    CounterObservation(
                        now,
                        "host",
                        "network_receive_bytes_total",
                        225,
                        "boot:one",
                        labels,
                    )
                )
                self.assertEqual(next_result.delta, 25)
                self.assertFalse(next_result.is_baseline)
                self.assertEqual(
                    [sample["message"] for sample in store.fetch_health_samples("host")],
                    ["recent"],
                )

            reader_points = ReadOnlySQLiteRepository(database).series(
                since_unix=int(now - 3 * 86400), limit=1000
            )
            self.assertEqual(
                sum(int(point.get("host_rx_bytes", 0)) for point in reader_points),
                125,
            )

            with MetricStore(database) as store:
                expired = store.apply_retention(
                    now=now + 31 * 86400,
                    raw_retention_days=1,
                    rollup_retention_days=30,
                )
                self.assertGreaterEqual(expired["rollup_rows_pruned"], 1)
                self.assertEqual(
                    store.fetch_counter_samples(
                        "host", "network_receive_bytes_total"
                    ),
                    [],
                )

    def test_retention_arguments_are_strictly_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            with self.assertRaisesRegex(ValueError, "finite"):
                store.apply_retention(
                    now=float("nan"),
                    raw_retention_days=7,
                    rollup_retention_days=400,
                )
            with self.assertRaisesRegex(ValueError, "raw_retention_days"):
                store.apply_retention(
                    now=1.0,
                    raw_retention_days=0,
                    rollup_retention_days=400,
                )


if __name__ == "__main__":
    unittest.main()
