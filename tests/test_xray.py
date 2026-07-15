from __future__ import annotations

import json
import unittest

from aws_ops_monitor.collectors.xray import (
    CommandResult,
    XrayCollector,
    XrayStatsParseError,
    parse_xray_stats,
)
from aws_ops_monitor.models import HealthState


HASH_KEY = b"test-only-private-hash-key"


class XrayParserTests(unittest.TestCase):
    def test_json_parser_hashes_users_and_preserves_safe_route_tags(self) -> None:
        email = "person@example.com"
        uuid = "123e4567-e89b-42d3-a456-426614174000"
        payload = json.dumps(
            {
                "stat": [
                    {"name": f"user>>>{email}>>>traffic>>>uplink", "value": "120"},
                    {"name": f"user>>>{uuid}>>>traffic>>>downlink", "value": 80},
                    {"name": "outbound>>>WARP>>>traffic>>>uplink", "value": 75},
                    {"name": f"inbound>>>{uuid}>>>traffic>>>downlink", "value": 20},
                    {"name": "ignored>>>raw>>>metric>>>name", "value": 99},
                ]
            }
        )
        counters = parse_xray_stats(payload, HASH_KEY)
        serialized = repr(counters)
        self.assertNotIn(email, serialized)
        self.assertNotIn(uuid, serialized)
        self.assertEqual(len(counters), 4)
        users = [counter for counter in counters if counter.scope == "user"]
        self.assertTrue(all(counter.identity_label == "user_hash" for counter in users))
        self.assertTrue(all(counter.identity_value.startswith("usr_") for counter in users))
        warp = next(counter for counter in counters if counter.scope == "outbound")
        self.assertEqual(warp.identity_value, "WARP")
        inbound = next(counter for counter in counters if counter.scope == "inbound")
        self.assertTrue(inbound.identity_value.startswith("tag_"))

    def test_text_parser_and_empty_json(self) -> None:
        payload = """
stat: <
  name: "outbound>>>freedom>>>traffic>>>downlink"
  value: 2048
>
stat: <
  name: "user>>>private-user>>>traffic>>>uplink"
  value: 1024
>
"""
        counters = parse_xray_stats(payload, HASH_KEY)
        self.assertEqual({counter.value for counter in counters}, {1024, 2048})
        self.assertNotIn("private-user", repr(counters))
        self.assertEqual(parse_xray_stats('{"stat": []}', HASH_KEY), ())

    def test_invalid_payload_error_does_not_echo_payload(self) -> None:
        raw_secret = "person@example.com"
        with self.assertRaises(XrayStatsParseError) as raised:
            parse_xray_stats(f"not-json {raw_secret}", HASH_KEY)
        self.assertNotIn(raw_secret, str(raised.exception))


class XrayCollectorTests(unittest.TestCase):
    def test_uses_fixed_docker_commands_and_opaque_reset_identity(self) -> None:
        commands: list[tuple[str, ...]] = []

        def runner(command, _timeout):
            commands.append(tuple(command))
            if command[1] == "inspect":
                return CommandResult(0, "raw-container-id|2026-07-15T00:00:00Z\n")
            return CommandResult(
                0,
                '{"stat":[{"name":"user>>>person@example.com>>>traffic>>>uplink","value":"7"}]}',
            )

        snapshot = XrayCollector(
            hash_key=HASH_KEY,
            runner=runner,
            clock=lambda: 55.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.HEALTHY)
        self.assertRegex(snapshot.reset_id, r"^xray-container:[0-9a-f]{24}$")
        self.assertNotIn("raw-container-id", snapshot.reset_id)
        self.assertNotIn("person@example.com", repr(snapshot))
        self.assertEqual(commands[0][0:2], ("docker", "inspect"))
        self.assertEqual(
            commands[1],
            (
                "docker",
                "exec",
                "xray",
                "xray",
                "api",
                "statsquery",
                "--server=127.0.0.1:10084",
                "--pattern=",
                "--reset=false",
            ),
        )

    def test_command_failure_does_not_surface_stderr(self) -> None:
        raw_secret = "person@example.com"

        def runner(command, _timeout):
            if command[1] == "inspect":
                return CommandResult(0, "container|start")
            return CommandResult(9, "", f"failed for {raw_secret}")

        snapshot = XrayCollector(hash_key=HASH_KEY, runner=runner).collect()
        self.assertEqual(snapshot.health.state, HealthState.UNAVAILABLE)
        self.assertNotIn(raw_secret, repr(snapshot.health))
        self.assertEqual(snapshot.health.details["command_exit"], 9)


if __name__ == "__main__":
    unittest.main()
