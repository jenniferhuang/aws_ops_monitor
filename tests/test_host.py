from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from aws_ops_monitor.collectors.host import (
    HostCollector,
    parse_cpu_stat,
    parse_loadavg,
    parse_meminfo,
    parse_proc_net_dev,
    parse_uptime,
)
from aws_ops_monitor.models import HealthState


NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
    lo: 100 2 0 0 0 0 0 0 100 2 0 0 0 0 0 0
  eth0: 4096 32 1 2 0 0 0 0 8192 64 3 4 0 0 0 0
"""


class HostParserTests(unittest.TestCase):
    def test_proc_parsers(self) -> None:
        self.assertEqual(parse_uptime("123.5 10.0\n"), 123.5)
        self.assertEqual(parse_loadavg("0.10 0.20 0.30 1/100 42\n"), (0.1, 0.2, 0.3))
        self.assertEqual(
            parse_cpu_stat("cpu  10 2 3 40 5 1 1 0 8 9\n"),
            (62, 45),
        )
        total, available = parse_meminfo(
            "MemTotal: 1000 kB\nMemAvailable: 400 kB\n"
        )
        self.assertEqual(total, 1_024_000)
        self.assertEqual(available, 409_600)
        interfaces = parse_proc_net_dev(NET_DEV)
        eth0 = next(item for item in interfaces if item.name == "eth0")
        self.assertEqual(eth0.receive_bytes, 4096)
        self.assertEqual(eth0.receive_drops, 2)
        self.assertEqual(eth0.transmit_bytes, 8192)
        self.assertEqual(eth0.transmit_drops, 4)

    def test_collects_healthy_snapshot_with_opaque_boot_identity(self) -> None:
        raw_boot_id = "11111111-2222-4333-8444-555555555555"
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            (proc / "net").mkdir(parents=True)
            (proc / "sys" / "kernel" / "random").mkdir(parents=True)
            (proc / "uptime").write_text("123.5 10.0\n")
            (proc / "loadavg").write_text("0.10 0.20 0.30 1/100 42\n")
            (proc / "stat").write_text("cpu  10 2 3 40 5 1 1 0\n")
            (proc / "meminfo").write_text(
                "MemTotal: 1000 kB\nMemAvailable: 400 kB\n"
            )
            (proc / "net" / "dev").write_text(NET_DEV)
            (proc / "sys" / "kernel" / "random" / "boot_id").write_text(
                raw_boot_id
            )

            stat = SimpleNamespace(
                f_frsize=4096,
                f_bsize=4096,
                f_blocks=1000,
                f_bavail=250,
            )
            snapshot = HostCollector(
                proc_root=proc,
                root_path=directory,
                clock=lambda: 1000.0,
                hostname=lambda: "lightsail-host",
                cpu_count=lambda: 2,
                statvfs=lambda _path: stat,
            ).collect()

        self.assertEqual(snapshot.health.state, HealthState.HEALTHY)
        self.assertEqual(snapshot.memory_total_bytes, 1_024_000)
        self.assertEqual(snapshot.disk_total_bytes, 4_096_000)
        self.assertEqual(snapshot.disk_available_bytes, 1_024_000)
        self.assertEqual(snapshot.cpu_count, 2)
        self.assertNotIn(raw_boot_id, snapshot.reset_id)
        self.assertRegex(snapshot.reset_id, r"^host-boot:[0-9a-f]{24}$")
        self.assertEqual(len(snapshot.interfaces), 2)


if __name__ == "__main__":
    unittest.main()
