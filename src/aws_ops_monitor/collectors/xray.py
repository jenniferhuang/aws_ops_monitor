"""Read Xray traffic counters through a narrowly scoped Docker command."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import re
import subprocess
import time

from ..models import HealthObservation, HealthState, XraySnapshot, XrayTrafficCounter


MAX_STATS_OUTPUT_BYTES = 2 * 1024 * 1024
_TEXT_STAT = re.compile(
    r'name:\s*"(?P<name>(?:\\.|[^"\\])*)".*?value:\s*(?P<value>[0-9]+)',
    re.DOTALL,
)
_CONTAINER_STATES = frozenset(
    {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
)


class XrayStatsParseError(ValueError):
    """Safe parse failure that never contains raw Xray output."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], float], CommandResult]


@dataclass(frozen=True, slots=True)
class ContainerState:
    inspect_ok: bool
    reset_material: str = "inspect-unavailable"
    status: str = "unknown"
    restart_count: int | None = None
    oom_killed: bool | None = None


def _run_command(command: Sequence[str], timeout: float) -> CommandResult:
    result = subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return CommandResult(result.returncode, result.stdout, result.stderr)


def _pseudonym(prefix: str, hash_key: bytes, raw: str) -> str:
    digest = hmac.new(hash_key, raw.encode("utf-8"), sha256).hexdigest()[:24]
    return f"{prefix}_{digest}"


def _safe_tag(raw: str, hash_key: bytes) -> str:
    # Tags are operator-controlled text and can contain names, e-mail
    # addresses, tenant identifiers, or other sensitive labels. Always hash
    # them, even when the syntax itself looks harmless.
    return _pseudonym("tag", hash_key, raw)


def _json_items(payload: str) -> list[object]:
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise XrayStatsParseError("invalid Xray stats payload") from exc
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        raise XrayStatsParseError("invalid Xray stats payload")
    items = document.get("stat", document.get("stats"))
    if not isinstance(items, list):
        raise XrayStatsParseError("invalid Xray stats payload")
    return items


def _text_items(payload: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for match in _TEXT_STAT.finditer(payload):
        try:
            name = json.loads(f'"{match.group("name")}"')
        except json.JSONDecodeError as exc:
            raise XrayStatsParseError("invalid Xray stats payload") from exc
        items.append({"name": name, "value": match.group("value")})
    if not items and payload.strip():
        raise XrayStatsParseError("invalid Xray stats payload")
    return items


def parse_xray_stats(payload: str, hash_key: bytes) -> tuple[XrayTrafficCounter, ...]:
    """Parse supported Xray counters without returning raw identities.

    User labels and inbound/outbound tags are always HMAC pseudonyms.
    Unsupported stats are ignored rather than persisted as raw names.
    """

    if len(hash_key) < 16:
        raise ValueError("Xray user hashing key must contain at least 16 bytes")
    if len(payload.encode("utf-8")) > MAX_STATS_OUTPUT_BYTES:
        raise XrayStatsParseError("Xray stats payload is too large")
    stripped = payload.strip()
    if not stripped:
        return ()
    if stripped.startswith(("{", "[")):
        items = _json_items(stripped)
    else:
        items = _text_items(stripped)

    counters: dict[tuple[str, str, str, str], XrayTrafficCounter] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        raw_value = item.get("value")
        if not isinstance(name, str):
            continue
        parts = name.split(">>>")
        if len(parts) != 4:
            continue
        scope, raw_identity, metric, direction = parts
        if scope not in {"user", "inbound", "outbound"}:
            continue
        if metric != "traffic" or direction not in {"uplink", "downlink"}:
            continue
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            continue
        if not 0 <= value <= 2**63 - 1:
            continue
        if scope == "user":
            identity_label = "user_hash"
            identity_value = _pseudonym("usr", hash_key, raw_identity)
        else:
            identity_label = "tag"
            identity_value = _safe_tag(raw_identity, hash_key)
        key = (scope, direction, identity_label, identity_value)
        counters[key] = XrayTrafficCounter(
            scope=scope,
            direction=direction,
            identity_label=identity_label,
            identity_value=identity_value,
            value=value,
        )
    return tuple(counters[key] for key in sorted(counters))


def _reset_identity(inspect_output: str) -> str:
    digest = sha256(f"xray-container\0{inspect_output.strip()}".encode("utf-8")).hexdigest()
    return f"xray-container:{digest[:24]}"


def _parse_container_state(result: CommandResult) -> ContainerState:
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 4096:
        return ContainerState(False)
    fields = result.stdout.strip().split("|")
    if len(fields) != 5:
        return ContainerState(False)
    container_id, started_at, status, raw_restarts, raw_oom = fields
    if (
        not container_id
        or len(container_id) > 128
        or not started_at
        or len(started_at) > 128
        or status not in _CONTAINER_STATES
    ):
        return ContainerState(False)
    try:
        restart_count = int(raw_restarts)
    except ValueError:
        return ContainerState(False)
    if not 0 <= restart_count <= 2**31 - 1 or raw_oom.lower() not in {"true", "false"}:
        return ContainerState(False)
    return ContainerState(
        True,
        reset_material=f"{container_id}|{started_at}",
        status=status,
        restart_count=restart_count,
        oom_killed=raw_oom.lower() == "true",
    )


class XrayCollector:
    """Collect Xray stats with fixed argv calls and no Docker socket mount."""

    def __init__(
        self,
        *,
        hash_key: bytes,
        docker_binary: str = "docker",
        container: str = "xray",
        xray_binary: str = "xray",
        api_server: str = "127.0.0.1:10084",
        timeout_seconds: float = 10.0,
        runner: CommandRunner = _run_command,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if len(hash_key) < 16:
            raise ValueError("Xray user hashing key must contain at least 16 bytes")
        self._hash_key = hash_key
        self._docker_binary = docker_binary
        self._container = container
        self._xray_binary = xray_binary
        self._api_server = api_server
        self._timeout_seconds = timeout_seconds
        self._runner = runner
        self._clock = clock

    def collect(self) -> XraySnapshot:
        observed_at = self._clock()
        container_state = ContainerState(False)
        try:
            inspect = self._runner(
                (
                    self._docker_binary,
                    "inspect",
                    "--format={{.Id}}|{{.State.StartedAt}}|{{.State.Status}}|"
                    "{{.RestartCount}}|{{.State.OOMKilled}}",
                    self._container,
                ),
                self._timeout_seconds,
            )
            container_state = _parse_container_state(inspect)
        except (OSError, subprocess.TimeoutExpired):
            pass
        reset_id = _reset_identity(container_state.reset_material)

        try:
            result = self._runner(
                (
                    self._docker_binary,
                    "exec",
                    self._container,
                    self._xray_binary,
                    "api",
                    "statsquery",
                    f"--server={self._api_server}",
                    "--pattern=",
                    "--reset=false",
                ),
                self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return self._failure_snapshot(
                observed_at,
                reset_id,
                "Xray stats command unavailable",
                container_state,
            )
        if result.returncode != 0:
            return self._failure_snapshot(
                observed_at,
                reset_id,
                "Xray stats command failed",
                container_state,
                command_exit=result.returncode,
            )
        try:
            counters = parse_xray_stats(result.stdout, self._hash_key)
        except XrayStatsParseError:
            return self._failure_snapshot(
                observed_at,
                reset_id,
                "Xray stats response was invalid",
                container_state,
            )

        if not container_state.inspect_ok:
            state = HealthState.DEGRADED
            message = "Xray counters collected without container health evidence"
        elif container_state.status != "running":
            state = HealthState.UNAVAILABLE
            message = "Xray container is not running"
        elif container_state.oom_killed:
            state = HealthState.DEGRADED
            message = "Xray container reports an out-of-memory termination"
        elif container_state.restart_count:
            state = HealthState.DEGRADED
            message = "Xray container has restarted since it was created"
        else:
            state = HealthState.HEALTHY
            message = "Xray counters and container health collected"
        return XraySnapshot(
            observed_at=observed_at,
            reset_id=reset_id,
            counters=counters,
            health=HealthObservation(
                observed_at=observed_at,
                component="xray",
                state=state,
                message=message,
                details={
                    "counter_count": len(counters),
                    "inspect_ok": container_state.inspect_ok,
                    "container_status": container_state.status,
                    "restart_count": container_state.restart_count,
                    "oom_killed": container_state.oom_killed,
                },
            ),
        )
    @staticmethod
    def _failure_snapshot(
        observed_at: float,
        reset_id: str,
        message: str,
        container_state: ContainerState,
        command_exit: int | None = None,
    ) -> XraySnapshot:
        details: dict[str, str | int | bool | None] = {
            "counter_count": 0,
            "inspect_ok": container_state.inspect_ok,
            "container_status": container_state.status,
            "restart_count": container_state.restart_count,
            "oom_killed": container_state.oom_killed,
        }
        if command_exit is not None:
            details["command_exit"] = command_exit
        return XraySnapshot(
            observed_at=observed_at,
            reset_id=reset_id,
            counters=(),
            health=HealthObservation(
                observed_at=observed_at,
                component="xray",
                state=HealthState.UNAVAILABLE,
                message=message,
                details=details,
            ),
        )
