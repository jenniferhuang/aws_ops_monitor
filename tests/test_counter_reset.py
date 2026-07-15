from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aws_ops_monitor.models import CounterObservation
from aws_ops_monitor.store import MetricStore


class CounterResetTests(unittest.TestCase):
    def test_identity_change_and_unannounced_decrease_emit_zero_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory, MetricStore(
            Path(directory) / "metrics.sqlite3"
        ) as store:
            def observe(at: float, value: int, reset_id: str):
                return store.record_counter(
                    CounterObservation(
                        at,
                        "xray",
                        "traffic_bytes_total",
                        value,
                        reset_id,
                        {"scope": "outbound", "tag": "WARP", "direction": "uplink"},
                    )
                )

            self.assertTrue(observe(1, 100, "container:a").is_baseline)
            self.assertEqual(observe(2, 130, "container:a").delta, 30)

            identity_reset = observe(3, 7, "container:b")
            self.assertTrue(identity_reset.is_reset)
            self.assertEqual(identity_reset.delta, 0)
            self.assertEqual(observe(4, 12, "container:b").delta, 5)

            hidden_reset = observe(5, 2, "container:b")
            self.assertTrue(hidden_reset.is_reset)
            self.assertEqual(hidden_reset.delta, 0)
            self.assertEqual(observe(6, 9, "container:b").delta, 7)

            samples = store.fetch_counter_samples("xray", "traffic_bytes_total")
            self.assertEqual([sample["delta"] for sample in samples], [0, 30, 0, 5, 0, 7])
            self.assertEqual(
                [sample["is_reset"] for sample in samples],
                [False, False, True, False, True, False],
            )


if __name__ == "__main__":
    unittest.main()
