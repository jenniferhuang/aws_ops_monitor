"""Privacy-safe listener inventory and static access-path evidence.

The collector executes one fixed ``ss`` command without a shell. It parses bind
addresses only long enough to classify each listener as loopback or public;
addresses and process metadata never enter a model, database row, or log.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import ipaddress
import subprocess
import time

from ..models import (
    HealthObservation,
    HealthState,
    ListenerObservation,
    NetworkSnapshot,
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""


Runner = Callable[[Sequence[str], float], CommandResult]


def _run_command(command: Sequence[str], timeout: float) -> CommandResult:
    """Run a fixed argument vector and intentionally discard stderr."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed validated argv, no shell
            tuple(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return CommandResult(-1)
    return CommandResult(completed.returncode, completed.stdout)


def parse_ss_listeners(payload: str) -> tuple[ListenerObservation, ...]:
    """Parse ``ss`` listener output without retaining an address.

    A bind to any non-loopback address is classified as public because it is
    reachable from at least the instance network namespace. Whether the AWS
    firewall permits Internet ingress is a separate control-plane layer.
    """

    listeners: set[tuple[str, int, str]] = set()
    for line in payload.splitlines()[:4096]:
        fields = line.split()
        if len(fields) >= 5 and fields[0].lower() in {"tcp", "udp"}:
            transport = fields[0].lower()
            endpoint = fields[4]
        elif len(fields) >= 4 and fields[0].upper() == "LISTEN":
            # A TCP-only ``ss -lnt`` invocation omits the Netid column.
            transport = "tcp"
            endpoint = fields[3]
        elif len(fields) >= 4 and fields[0].upper() == "UNCONN":
            transport = "udp"
            endpoint = fields[3]
        else:
            continue
        parsed = _classify_endpoint(endpoint)
        if parsed is None:
            continue
        port, exposure = parsed
        listeners.add((transport, port, exposure))
    return tuple(
        ListenerObservation(transport, port, exposure)
        for transport, port, exposure in sorted(
            listeners, key=lambda item: (item[2], item[1], item[0])
        )
    )


def _classify_endpoint(endpoint: str) -> tuple[int, str] | None:
    address, separator, raw_port = endpoint.rpartition(":")
    if not separator or not raw_port.isascii() or not raw_port.isdecimal():
        return None
    port = int(raw_port)
    if not 1 <= port <= 65535:
        return None
    address = address.strip("[]")
    if "%" in address:
        address = address.split("%", 1)[0]
    if address.lower() == "localhost":
        return port, "loopback"
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        return port, "public"
    if parsed_address.is_loopback:
        return port, "loopback"
    if parsed_address.is_link_local:
        return port, "link_local"
    return port, "public"


def _listener_text(listeners: Sequence[ListenerObservation], *, limit: int = 32) -> str:
    values = [f"{item.port}/{item.transport}" for item in listeners]
    if len(values) > limit:
        values = [*values[:limit], "more"]
    return ",".join(values)


class NetworkCollector:
    """Collect listener exposure drift and five privacy-safe access paths."""

    def __init__(
        self,
        *,
        ss_binary: str = "ss",
        expected_public_ports: Sequence[int] = (22, 80),
        expected_loopback_ports: Sequence[int] = (8787, 10084),
        expected_public_udp_ports: Sequence[int] = (),
        expected_loopback_udp_ports: Sequence[int] = (),
        timeout_seconds: float = 5.0,
        runner: Runner = _run_command,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ss_binary = ss_binary
        self._expected_public_ports = frozenset(expected_public_ports)
        self._expected_loopback_ports = frozenset(expected_loopback_ports)
        self._expected_public_udp_ports = frozenset(expected_public_udp_ports)
        self._expected_loopback_udp_ports = frozenset(expected_loopback_udp_ports)
        self._timeout_seconds = timeout_seconds
        self._runner = runner
        self._clock = clock

    def collect(self) -> NetworkSnapshot:
        observed_at = self._clock()
        command = (self._ss_binary, "-H", "-lntu")
        result = self._runner(command, self._timeout_seconds)
        if result.returncode != 0:
            unavailable = HealthObservation(
                observed_at,
                "network_exposure",
                HealthState.UNAVAILABLE,
                "listener inventory unavailable",
                {"command_exit": result.returncode},
            )
            return NetworkSnapshot(
                observed_at,
                (),
                (unavailable, *self._path_health(observed_at, ())),
            )

        listeners = parse_ss_listeners(result.stdout)
        public = tuple(item for item in listeners if item.exposure == "public")
        loopback = tuple(item for item in listeners if item.exposure == "loopback")
        link_local = tuple(item for item in listeners if item.exposure == "link_local")
        unexpected = tuple(
            item
            for item in public
            if (
                (
                    item.transport == "tcp"
                    and item.port not in self._expected_public_ports
                )
                or (
                    item.transport == "udp"
                    and item.port not in self._expected_public_udp_ports
                    and item.port not in {68, 546}
                )
            )
        )
        expected_public = tuple(
            ListenerObservation("tcp", port, "public")
            for port in sorted(self._expected_public_ports)
        ) + tuple(
            ListenerObservation("udp", port, "public")
            for port in sorted(self._expected_public_udp_ports)
        )
        expected_loopback = tuple(
            ListenerObservation("tcp", port, "loopback")
            for port in sorted(self._expected_loopback_ports)
        ) + tuple(
            ListenerObservation("udp", port, "loopback")
            for port in sorted(self._expected_loopback_udp_ports)
        )
        observed_keys = {
            (item.transport, item.port, item.exposure) for item in listeners
        }
        missing = tuple(
            item
            for item in (*expected_public, *expected_loopback)
            if (item.transport, item.port, item.exposure) not in observed_keys
        )
        exposure_state = (
            HealthState.DEGRADED if unexpected or missing else HealthState.HEALTHY
        )
        exposure_message = (
            "unexpected public listener detected"
            if unexpected
            else "required listener is missing or has the wrong exposure"
            if missing
            else "listener exposure matches the configured public-port policy"
        )
        exposure = HealthObservation(
            observed_at,
            "network_exposure",
            exposure_state,
            exposure_message,
            {
                "public_listener_count": len(public),
                "loopback_listener_count": len(loopback),
                "link_local_listener_count": len(link_local),
                "public_ports": _listener_text(public),
                "loopback_ports": _listener_text(loopback),
                "expected_public_ports": _listener_text(expected_public),
                "expected_loopback_ports": _listener_text(expected_loopback),
                "unexpected_public_ports": _listener_text(unexpected),
                "missing_expected_ports": _listener_text(missing),
                "expected_loopback_port_count": len(self._expected_loopback_ports),
                "expected_loopback_udp_port_count": len(
                    self._expected_loopback_udp_ports
                ),
                "udp_exemptions": "68/udp,546/udp,link-local",
            },
        )
        return NetworkSnapshot(
            observed_at,
            listeners,
            (exposure, *self._path_health(observed_at, listeners)),
        )

    @staticmethod
    def _path_health(
        observed_at: float, listeners: Sequence[ListenerObservation]
    ) -> tuple[HealthObservation, ...]:
        observed = {
            (listener.transport, listener.port, listener.exposure)
            for listener in listeners
        }

        def listener_path(
            component: str,
            name: str,
            direction: str,
            route: str,
            key: tuple[str, int, str],
        ) -> HealthObservation:
            present = key in observed
            wrong_exposure = any(
                transport == key[0] and port == key[1]
                for transport, port, _exposure in observed
            )
            state = (
                HealthState.HEALTHY
                if present
                else HealthState.DEGRADED
                if wrong_exposure
                else HealthState.UNAVAILABLE
            )
            return HealthObservation(
                observed_at,
                component,
                state,
                "required listener observed"
                if present
                else "required listener has an unsafe or unexpected exposure"
                if wrong_exposure
                else "required listener not observed",
                {
                    "name": name,
                    "direction": direction,
                    "route": route,
                    "status": (
                        "observed"
                        if present
                        else "wrong_exposure"
                        if wrong_exposure
                        else "missing"
                    ),
                    "evidence": "local_listener",
                    "required": True,
                },
            )

        return (
            listener_path(
                "path_xray_listener",
                "Xray public listener",
                "inbound local evidence",
                "Network namespace>Xray listener",
                ("tcp", 80, "public"),
            ),
            listener_path(
                "path_warp_proxy_listener",
                "Local WARP proxy",
                "internal local evidence",
                "Xray>loopback WARP HTTP proxy",
                ("tcp", 1087, "loopback"),
            ),
            listener_path(
                "path_ssh",
                "Administrative SSH",
                "inbound",
                "Operator>Lightsail firewall>SSH",
                ("tcp", 22, "public"),
            ),
            listener_path(
                "path_stats_service",
                "Xray StatsService",
                "internal",
                "Collector>loopback StatsService",
                ("tcp", 10084, "loopback"),
            ),
            listener_path(
                "path_private_dashboard",
                "Private monitoring dashboard",
                "inbound through SSH tunnel",
                "Operator>SSH tunnel>loopback dashboard",
                ("tcp", 8787, "loopback"),
            ),
        )
