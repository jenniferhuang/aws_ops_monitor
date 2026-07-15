from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest

from aws_ops_monitor.collectors.network import (
    CommandResult,
    NetworkCollector,
    parse_ss_listeners,
)
from aws_ops_monitor.models import HealthState
from aws_ops_monitor.store import MetricStore
from aws_ops_monitor.web import ReadOnlySQLiteRepository


SS_OUTPUT = """
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 4096 *:80 *:*
tcp LISTEN 0 4096 0.0.0.0:1087 0.0.0.0:*
tcp LISTEN 0 4096 127.0.0.1:10084 0.0.0.0:*
tcp LISTEN 0 4096 [::1]:8787 [::]:*
udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*
udp UNCONN 0 0 0.0.0.0:9999 0.0.0.0:*
udp UNCONN 0 0 [fe80::1]:5353 [::]:*
"""


class ListenerParserTests(unittest.TestCase):
    def test_parser_returns_only_port_transport_and_exposure(self) -> None:
        listeners = parse_ss_listeners(SS_OUTPUT)
        self.assertIn(
            ("tcp", 1087, "public"),
            {(item.transport, item.port, item.exposure) for item in listeners},
        )
        self.assertIn(
            ("tcp", 10084, "loopback"),
            {(item.transport, item.port, item.exposure) for item in listeners},
        )
        self.assertIn(
            ("udp", 5353, "link_local"),
            {(item.transport, item.port, item.exposure) for item in listeners},
        )
        serialized = repr(listeners)
        self.assertNotIn("127.0.0.1", serialized)
        self.assertNotIn("0.0.0.0", serialized)

    def test_malformed_and_non_numeric_endpoints_are_ignored(self) -> None:
        payload = "tcp LISTEN 0 1 private-value:service peer:*\ninvalid"
        self.assertEqual(parse_ss_listeners(payload), ())

    def test_tcp_only_ss_shape_without_netid_is_supported(self) -> None:
        payload = "LISTEN 0 4096 0.0.0.0:1087 0.0.0.0:*"
        listeners = parse_ss_listeners(payload)
        self.assertEqual(
            [(item.transport, item.port, item.exposure) for item in listeners],
            [("tcp", 1087, "public")],
        )


class NetworkCollectorTests(unittest.TestCase):
    def test_fixed_tcp_inventory_and_unexpected_1087_alert(self) -> None:
        commands: list[tuple[str, ...]] = []

        def runner(command, timeout):
            commands.append(tuple(command))
            self.assertEqual(timeout, 4.0)
            return CommandResult(0, SS_OUTPUT)

        snapshot = NetworkCollector(
            timeout_seconds=4.0,
            runner=runner,
            clock=lambda: 55.0,
        ).collect()

        self.assertEqual(commands, [("ss", "-H", "-lntu")])
        exposure = snapshot.health[0]
        self.assertEqual(exposure.component, "network_exposure")
        self.assertEqual(exposure.state, HealthState.DEGRADED)
        self.assertEqual(
            exposure.details["unexpected_public_ports"], "1087/tcp,9999/udp"
        )
        self.assertNotIn("68/udp", str(exposure.details["unexpected_public_ports"]))
        self.assertEqual(exposure.details["link_local_listener_count"], 1)
        paths = {item.component: item for item in snapshot.health[1:]}
        self.assertEqual(paths["path_xray_listener"].state, HealthState.HEALTHY)
        self.assertEqual(paths["path_warp_proxy_listener"].state, HealthState.DEGRADED)
        self.assertEqual(
            paths["path_warp_proxy_listener"].details["status"], "wrong_exposure"
        )
        self.assertEqual(paths["path_stats_service"].state, HealthState.HEALTHY)
        self.assertEqual(paths["path_private_dashboard"].state, HealthState.HEALTHY)
        self.assertNotIn("0.0.0.0", repr(snapshot))

    def test_command_failure_is_generic_and_does_not_retain_output(self) -> None:
        secret = "198.51.100.72 private-token"

        def runner(_command, _timeout):
            return CommandResult(9, secret)

        snapshot = NetworkCollector(runner=runner, clock=lambda: 1.0).collect()
        self.assertEqual(snapshot.health[0].state, HealthState.UNAVAILABLE)
        self.assertNotIn(secret, repr(snapshot))

    def test_missing_configured_tcp_and_udp_listeners_degrade_policy(self) -> None:
        snapshot = NetworkCollector(
            expected_public_ports=(22, 443),
            expected_loopback_ports=(8787,),
            expected_public_udp_ports=(51820,),
            runner=lambda _command, _timeout: CommandResult(
                0,
                "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n",
            ),
            clock=lambda: 1.0,
        ).collect()
        exposure = snapshot.health[0]
        self.assertEqual(exposure.state, HealthState.DEGRADED)
        self.assertEqual(
            exposure.details["missing_expected_ports"],
            "443/tcp,51820/udp,8787/tcp",
        )


class NetworkProjectionTests(unittest.TestCase):
    def test_dashboard_projects_paths_and_critical_listener_without_addresses(
        self,
    ) -> None:
        now = time.time()
        snapshot = NetworkCollector(
            runner=lambda _command, _timeout: CommandResult(0, SS_OUTPUT),
            clock=lambda: now,
        ).collect()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "metrics.sqlite3"
            with MetricStore(database) as store:
                store.record_batch(health=snapshot.health)
            overview = ReadOnlySQLiteRepository(database).overview()

        payload = json.dumps(overview)
        self.assertEqual(overview["status"], "critical")
        self.assertEqual(len(overview["paths"]), 5)
        self.assertEqual(overview["alerts"][0]["severity"], "critical")
        self.assertIn("1087/tcp", overview["alerts"][0]["message"])
        self.assertIn("9999/udp", overview["alerts"][0]["message"])
        self.assertNotIn("127.0.0.1", payload)
        self.assertNotIn("0.0.0.0", payload)


if __name__ == "__main__":
    unittest.main()
