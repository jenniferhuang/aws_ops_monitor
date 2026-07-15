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
_SAFE_TAG = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_UUID = re.compile(
    r"(?i)(?:^|[^0-9a-f])"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"(?:$|[^0-9a-f])"
)


class XrayStatsParseError(ValueError):
    """Safe parse failure that never contains raw Xray output."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], float], CommandResult]


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
    if _SAFE_TAG.fullmatch(raw) and not _UUID.search(raw):
        return raw
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

    User labels are always HMAC pseudonyms. Inbound/outbound tags are retained
    only when they match a conservative tag grammar and do not contain a UUID.
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
        inspect_ok = False
        inspect_material = "inspect-unavailable"
        try:
            inspect = self._runner(
                (
                    self._docker_binary,
                    "inspect",
                    "--format={{.Id}}|{{.State.StartedAt}}",
                    self._container,
                ),
                self._timeout_seconds,
            )
            if inspect.returncode == 0 and inspect.stdout.strip():
                inspect_ok = True
                inspect_material = inspect.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
        reset_id = _reset_identity(inspect_material)

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
                inspect_ok,
            )
        if result.returncode != 0:
            return self._failure_snapshot(
                observed_at,
                reset_id,
                "Xray stats command failed",
                inspect_ok,
                command_exit=result.returncode,
            )
        try:
            counters = parse_xray_stats(result.stdout, self._hash_key)
        except XrayStatsParseError:
            return self._failure_snapshot(
                observed_at,
                reset_id,
                "Xray stats response was invalid",
                inspect_ok,
            )

        state = HealthState.HEALTHY if inspect_ok else HealthState.DEGRADED
        message = (
            "Xray counters collected"
            if inspect_ok
            else "Xray counters collected without container reset identity"
        )
        return XraySnapshot(
            observed_at=observed_at,
            reset_id=reset_id,
            counters=counters,
            health=HealthObservation(
                observed_at=observed_at,
                component="xray",
                state=state,
                message=message,
                details={"counter_count": len(counters), "inspect_ok": inspect_ok},
            ),
        )
    @staticmethod
    def _failure_snapshot(
        observed_at: float,
        reset_id: str,
        message: str,
        inspect_ok: bool,
        command_exit: int | None = None,
    ) -> XraySnapshot:
        details: dict[str, str | int | bool | None] = {
            "counter_count": 0,
            "inspect_ok": inspect_ok,
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
