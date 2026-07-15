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
    def test_json_parser_hashes_users_and_every_route_tag(self) -> None:
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
        self.assertTrue(warp.identity_value.startswith("tag_"))
        self.assertNotIn("WARP", warp.identity_value)
        inbound = next(counter for counter in counters if counter.scope == "inbound")
        self.assertTrue(inbound.identity_value.startswith("tag_"))

    def test_route_tags_never_persist_email_uuid_v7_or_secret_text(self) -> None:
        raw_tags = (
            "jennifer@example.com",
            "018f1f6c-5c6d-7a2b-8c9d-123456789abc",
            "private-token-value",
        )
        counters = parse_xray_stats(
            json.dumps(
                {
                    "stat": [
                        {
                            "name": f"outbound>>>{tag}>>>traffic>>>uplink",
                            "value": index + 1,
                        }
                        for index, tag in enumerate(raw_tags)
                    ]
                }
            ),
            HASH_KEY,
        )
        serialized = repr(counters)
        self.assertTrue(all(counter.identity_value.startswith("tag_") for counter in counters))
        for raw_tag in raw_tags:
            self.assertNotIn(raw_tag, serialized)

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
                return CommandResult(
                    0,
                    "raw-container-id|2026-07-15T00:00:00Z|running|3|false\n",
                )
            return CommandResult(
                0,
                '{"stat":[{"name":"user>>>person@example.com>>>traffic>>>uplink","value":"7"}]}',
            )

        snapshot = XrayCollector(
            hash_key=HASH_KEY,
            runner=runner,
            clock=lambda: 55.0,
        ).collect()
        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        self.assertRegex(snapshot.reset_id, r"^xray-container:[0-9a-f]{24}$")
        self.assertNotIn("raw-container-id", snapshot.reset_id)
        self.assertNotIn("person@example.com", repr(snapshot))
        self.assertEqual(snapshot.health.details["container_status"], "running")
        self.assertEqual(snapshot.health.details["restart_count"], 3)
        self.assertFalse(snapshot.health.details["oom_killed"])
        self.assertEqual(commands[0][0:2], ("docker", "inspect"))
        self.assertIn("{{.RestartCount}}", commands[0][2])
        self.assertIn("{{.State.OOMKilled}}", commands[0][2])
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
                return CommandResult(0, "container|start|running|0|false")
            return CommandResult(9, "", f"failed for {raw_secret}")

        snapshot = XrayCollector(hash_key=HASH_KEY, runner=runner).collect()
        self.assertEqual(snapshot.health.state, HealthState.UNAVAILABLE)
        self.assertNotIn(raw_secret, repr(snapshot.health))
        self.assertEqual(snapshot.health.details["command_exit"], 9)

    def test_oom_and_non_running_container_health_are_exposed_without_raw_state(self) -> None:
        def runner(command, _timeout):
            if command[1] == "inspect":
                return CommandResult(0, "private-id|start|running|4|true")
            return CommandResult(0, '{"stat":[]}')

        snapshot = XrayCollector(hash_key=HASH_KEY, runner=runner).collect()
        self.assertEqual(snapshot.health.state, HealthState.DEGRADED)
        self.assertTrue(snapshot.health.details["oom_killed"])
        self.assertEqual(snapshot.health.details["restart_count"], 4)
        self.assertNotIn("private-id", repr(snapshot))

        def stopped_runner(command, _timeout):
            if command[1] == "inspect":
                return CommandResult(0, "private-id|start|exited|0|false")
            return CommandResult(0, '{"stat":[]}')

        stopped = XrayCollector(hash_key=HASH_KEY, runner=stopped_runner).collect()
        self.assertEqual(stopped.health.state, HealthState.UNAVAILABLE)
        self.assertEqual(stopped.health.details["container_status"], "exited")


if __name__ == "__main__":
    unittest.main()
