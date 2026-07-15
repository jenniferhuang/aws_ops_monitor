from __future__ import annotations

import unittest

from aws_ops_monitor.collectors.probes import (
    DNSResult,
    PathProbeCollector,
    ProbeResult,
    _valid_websocket_upgrade,
)
from aws_ops_monitor.models import HealthState


class Clock:
    def __init__(self, value: float = 1000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class PathProbeCollectorTests(unittest.TestCase):
    def test_websocket_response_requires_upgrade_headers_and_accept_digest(self) -> None:
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        valid = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: keep-alive, Upgrade\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        )
        self.assertTrue(_valid_websocket_upgrade(valid, key))
        for invalid in (
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            valid.replace(b"Upgrade: websocket", b"Upgrade: h2c"),
            valid.replace(b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", b"invalid"),
            valid.replace(
                b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                b"S3PplmbItXAq9KygZZHzrBk+XoO=",
            ),
            valid.replace(b"HTTP/1.1", b"NOTHTTP/1.1"),
            valid.removesuffix(b"\r\n\r\n"),
        ):
            with self.subTest(invalid=invalid[:32]):
                self.assertFalse(_valid_websocket_upgrade(invalid, key))

    def test_verified_results_are_privacy_safe_and_cached_for_five_minutes(self) -> None:
        monotonic = Clock()
        resolver_calls: list[tuple[str, str, float]] = []
        websocket_calls: list[tuple[str, str, tuple[str, ...], float]] = []
        warp_calls: list[tuple[str, float]] = []

        def resolver(binary: str, hostname: str, timeout: float) -> DNSResult:
            resolver_calls.append((binary, hostname, timeout))
            return DNSResult(True, ("1.1.1.1",), "resolved", 12)

        def websocket(hostname, path, addresses, timeout):
            websocket_calls.append((hostname, path, tuple(addresses), timeout))
            return ProbeResult(True, "upgrade_accepted", 35, 101)

        def warp(proxy, timeout):
            warp_calls.append((proxy, timeout))
            return ProbeResult(True, "trace_marker_observed", 42, 200, True)

        collector = PathProbeCollector(
            public_hostname="v2.hermes-node.com",
            public_path="/302",
            warp_enabled=True,
            warp_proxy_server="127.0.0.1:1087",
            resolver=resolver,
            websocket_prober=websocket,
            warp_prober=warp,
            clock=lambda: 55.0,
            monotonic=monotonic,
        )
        health = collector.collect()
        self.assertEqual({item.state for item in health}, {HealthState.HEALTHY})
        self.assertEqual(len(resolver_calls), 1)
        self.assertEqual(websocket_calls[0][1], "/302")
        self.assertEqual(warp_calls, [("127.0.0.1:1087", 8.0)])
        serialized = repr(health)
        self.assertNotIn("1.1.1.1", serialized)
        self.assertNotIn("127.0.0.1", serialized)
        self.assertEqual(health[1].details["http_status"], 101)
        self.assertTrue(health[2].details["trace_marker"])
        self.assertTrue(all(item.details["required"] for item in health))

        monotonic.value += 299
        self.assertEqual(collector.collect(), ())
        self.assertEqual(len(resolver_calls), 1)
        monotonic.value += 1
        self.assertEqual(len(collector.collect()), 3)
        self.assertEqual(len(resolver_calls), 2)

    def test_dns_failure_skips_websocket_and_raw_failures_are_not_stored(self) -> None:
        raw_secret = "198.51.100.7 private-token"
        websocket_calls = 0

        def websocket(_hostname, _path, _addresses, _timeout):
            nonlocal websocket_calls
            websocket_calls += 1
            return ProbeResult(True, "upgrade_accepted", 1, 101)

        collector = PathProbeCollector(
            public_hostname="v2.hermes-node.com",
            public_path="/302",
            warp_enabled=False,
            warp_proxy_server="127.0.0.1:1087",
            resolver=lambda *_args: DNSResult(False, (), raw_secret, 3),
            websocket_prober=websocket,
            clock=lambda: 55.0,
            monotonic=lambda: 1000.0,
        )
        health = collector.collect()
        self.assertEqual(websocket_calls, 0)
        self.assertEqual(health[0].state, HealthState.UNAVAILABLE)
        self.assertEqual(health[1].details["reason"], "dns_unavailable")
        self.assertEqual(health[2].state, HealthState.DISABLED)
        self.assertFalse(health[2].details["required"])
        self.assertNotIn(raw_secret, repr(health))

    def test_resolver_private_answer_is_never_probed_or_persisted(self) -> None:
        calls = 0

        def websocket(*_args):
            nonlocal calls
            calls += 1
            return ProbeResult(True, "upgrade_accepted", 1, 101)

        collector = PathProbeCollector(
            public_hostname="v2.hermes-node.com",
            public_path="/302",
            warp_enabled=False,
            warp_proxy_server="127.0.0.1:1087",
            resolver=lambda *_args: DNSResult(True, ("127.0.0.1",), "resolved", 1),
            websocket_prober=websocket,
            clock=lambda: 55.0,
            monotonic=lambda: 1000.0,
        )
        health = collector.collect()
        self.assertEqual(calls, 0)
        self.assertEqual(health[0].state, HealthState.UNAVAILABLE)
        self.assertNotIn("127.0.0.1", repr(health))


if __name__ == "__main__":
    unittest.main()
