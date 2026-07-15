from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from aws_ops_monitor.models import (
    CounterObservation,
    GaugeObservation,
    HealthObservation,
    HealthState,
)
from aws_ops_monitor.store import MetricStore


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


if __name__ == "__main__":
    unittest.main()
