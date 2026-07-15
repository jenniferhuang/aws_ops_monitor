from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aws_ops_monitor.collector import Collector
from aws_ops_monitor.config import Config
from aws_ops_monitor.store import MetricStore


class Clock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FailingRetentionStore(MetricStore):
    def apply_retention(self, **_kwargs: object) -> dict[str, int]:
        raise RuntimeError("private database failure detail")


def disabled_config(database: Path) -> Config:
    return Config(
        database_path=database,
        host_enabled=False,
        xray_enabled=False,
        network_enabled=False,
        path_probes_enabled=False,
        aws_enabled=False,
    )


class CollectorRetentionTests(unittest.TestCase):
    def test_retention_runs_immediately_then_only_once_per_interval(self) -> None:
        wall = Clock(10_000.0)
        monotonic = Clock(500.0)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            config = disabled_config(database)
            with MetricStore(database) as store:
                collector = Collector(
                    config,
                    store,
                    clock=wall,
                    monotonic=monotonic,
                )
                collector.collect_once()
                self.assertEqual(len(store.fetch_health_samples("retention")), 1)
                monotonic.value += config.retention_prune_interval_seconds - 1
                collector.collect_once()
                self.assertEqual(len(store.fetch_health_samples("retention")), 1)
                monotonic.value += 1
                collector.collect_once()
                retention = store.fetch_health_samples("retention")
                self.assertEqual(len(retention), 2)
                self.assertTrue(all(item["state"] == "healthy" for item in retention))
                self.assertEqual(
                    retention[-1]["details"]["rollup_retention_days"],
                    config.rollup_retention_days,
                )

    def test_retention_failure_becomes_sanitized_health_not_daemon_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with FailingRetentionStore(database) as store:
                result = Collector(
                    disabled_config(database),
                    store,
                    clock=lambda: 10_000.0,
                    monotonic=lambda: 500.0,
                ).collect_once()
                self.assertEqual(result.gauge_count, 0)
                retention = store.fetch_health_samples("retention")
            self.assertEqual(retention[0]["state"], "unavailable")
            self.assertNotIn("private database failure detail", repr(retention))


if __name__ == "__main__":
    unittest.main()
