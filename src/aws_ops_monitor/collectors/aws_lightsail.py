"""Optional least-privilege, read-only AWS Lightsail telemetry.

The adapter only invokes GetInstance, GetInstancePortStates,
GetInstanceMetricData, and GetAlarms. It never persists account identifiers,
instance names, addresses, alarm names, credentials, exception text, or raw
firewall source values.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import ipaddress
import math
import os
import time
from typing import Protocol

from ..models import GaugeObservation, HealthObservation, HealthState


class LightsailClient(Protocol):
    def get_instance(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_instance_port_states(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_instance_metric_data(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_alarms(self, **kwargs: object) -> Mapping[str, object]: ...


ClientFactory = Callable[[str, float], LightsailClient]

_BYTES_PER_PLAN_GB = 1024**3
_SQLITE_INTEGER_MAX = 2**63 - 1
_CPU_HIGH_PERCENT = 85.0
_BURST_LOW_PERCENT = 20.0
_DEFAULT_EXPECTED_WORLD_TCP_PORTS = (22, 80)
_AWS_PLAN_ALLOCATION_PROVENANCE = "aws_instance_networking"
_MIN_FRESH_FOR_SECONDS = 600
_MAX_FRESH_FOR_SECONDS = 172800
_MAX_ALARM_PAGES = 100
_MAX_ALARMS = 10000


@dataclass(frozen=True, slots=True)
class LightsailSnapshot:
    observed_at: float
    gauges: tuple[GaugeObservation, ...]
    health: HealthObservation


@dataclass(frozen=True, slots=True)
class _FirewallEvaluation:
    available: bool
    rules: str
    scopes: str
    unsafe_world_open_count: int
    invalid_rule_count: int


@dataclass(frozen=True, slots=True)
class _AlarmEvaluation:
    available: bool
    alarm_count: int
    active_count: int
    indeterminate_count: int
    truncated: bool


def _default_client_factory(region: str, timeout_seconds: float) -> LightsailClient:
    # Custom endpoints can turn an SDK lookup into an arbitrary HTTP request.
    # Production collection uses only the regional AWS endpoint selected by the
    # SDK. Tests inject an in-memory client instead.
    if os.environ.get("AWS_ENDPOINT_URL") or os.environ.get(
        "AWS_ENDPOINT_URL_LIGHTSAIL"
    ):
        raise RuntimeError("custom endpoint disabled")
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.config import (  # type: ignore[import-not-found]
            Config as BotoConfig,
        )
    except ImportError as error:
        raise RuntimeError("AWS SDK unavailable") from error
    return boto3.client(
        "lightsail",
        region_name=region,
        config=BotoConfig(
            connect_timeout=timeout_seconds,
            read_timeout=timeout_seconds,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )


def _failure_category(error: BaseException) -> str:
    response = getattr(error, "response", None)
    code = ""
    if isinstance(response, Mapping):
        error_data = response.get("Error")
        if isinstance(error_data, Mapping):
            code = str(error_data.get("Code", ""))
    lowered = code.lower()
    if (
        "unauthenticated" in lowered
        or "credential" in lowered
        or error.__class__.__name__
        in {
            "NoCredentialsError",
            "PartialCredentialsError",
        }
    ):
        return "credentials_unavailable"
    if "accessdenied" in lowered or "unauthorized" in lowered:
        return "access_denied"
    return "request_failed"


def _month_start(timestamp: float) -> datetime:
    current = datetime.fromtimestamp(timestamp, UTC)
    return current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _safe_sequence(value: object) -> Sequence[object] | None:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return None


def _metric_values(response: Mapping[str, object], statistic: str) -> tuple[float, ...]:
    raw_points = _safe_sequence(response.get("metricData"))
    if raw_points is None:
        return ()
    values: list[float] = []
    for raw_point in raw_points:
        if not isinstance(raw_point, Mapping) or statistic not in raw_point:
            continue
        if isinstance(raw_point[statistic], bool):
            continue
        try:
            value = float(raw_point[statistic])
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and value >= 0:
            values.append(value)
    return tuple(values)


def _sum_metric(response: Mapping[str, object]) -> int | None:
    values = _metric_values(response, "sum")
    if not values:
        return None
    total = 0
    for value in values:
        total = min(total + int(value), _SQLITE_INTEGER_MAX)
    return total


def _instance_mapping(response: Mapping[str, object]) -> Mapping[str, object] | None:
    instance = response.get("instance")
    return instance if isinstance(instance, Mapping) else None


def _safe_instance_state(response: Mapping[str, object]) -> str:
    instance = _instance_mapping(response)
    if instance is None:
        return "unknown"
    state = instance.get("state")
    if not isinstance(state, Mapping):
        return "unknown"
    value = str(state.get("name", "unknown")).lower()
    allowed = {
        "pending",
        "running",
        "shutting-down",
        "terminated",
        "stopping",
        "stopped",
    }
    return value if value in allowed else "unknown"


def _safe_static_ip(response: Mapping[str, object]) -> bool | None:
    instance = _instance_mapping(response)
    if instance is None:
        return None
    value = instance.get("isStaticIp")
    return value if isinstance(value, bool) else None


def _instance_plan_allocation_bytes(response: Mapping[str, object]) -> int | None:
    """Return the nominal per-instance bundle allocation, never account usage.

    Lightsail reports this field on the instance networking object. It is a
    plan attribute; regional transfer pooling and billing cannot be inferred
    from it.
    """

    instance = _instance_mapping(response)
    if instance is None:
        return None
    networking = instance.get("networking")
    if not isinstance(networking, Mapping):
        return None
    monthly_transfer = networking.get("monthlyTransfer")
    if not isinstance(monthly_transfer, Mapping):
        return None
    raw_value = monthly_transfer.get("gbPerMonthAllocated")
    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        return None
    if raw_value <= 0:
        return None
    byte_value = raw_value * _BYTES_PER_PLAN_GB
    return byte_value if 0 < byte_value <= _SQLITE_INTEGER_MAX else None


def _source_category(raw_value: object) -> str:
    try:
        network = ipaddress.ip_network(str(raw_value), strict=False)
    except ValueError:
        return "invalid_source"
    version = "ipv4" if network.version == 4 else "ipv6"
    if network.prefixlen == 0:
        return f"world_{version}"
    if network.is_loopback:
        return f"loopback_{version}"
    if network.is_link_local:
        return f"link_local_{version}"
    if network.is_private:
        return f"private_{version}"
    return f"restricted_{version}"


def _rule_scopes(raw_state: Mapping[str, object]) -> tuple[set[str], int]:
    scopes: set[str] = set()
    invalid = 0
    for key in ("cidrs", "ipv6Cidrs"):
        if key not in raw_state:
            continue
        raw_sources = _safe_sequence(raw_state.get(key))
        if raw_sources is None:
            invalid += 1
            continue
        for raw_source in raw_sources:
            category = _source_category(raw_source)
            scopes.add(category)
            invalid += int(category == "invalid_source")
    if "cidrListAliases" in raw_state:
        raw_aliases = _safe_sequence(raw_state.get("cidrListAliases"))
        if raw_aliases is None:
            invalid += 1
        elif raw_aliases:
            # Alias values can contain account-specific names. Only the fact
            # that an AWS-managed source alias exists is retained.
            scopes.add("managed_alias")
    if not scopes:
        scopes.add("unspecified")
        invalid += 1
    return scopes, invalid


def _rule_descriptor(
    raw_state: Mapping[str, object],
    protocol: str,
    expected_world_tcp_ports: frozenset[int],
) -> tuple[str, bool, bool]:
    """Return a safe descriptor, whether its shape is valid, and expectedness."""

    if protocol in {"all", "icmp", "icmpv6"}:
        return protocol, True, False
    if protocol not in {"tcp", "udp"}:
        return "invalid", False, False
    try:
        raw_start = raw_state.get("fromPort", -1)
        raw_end = raw_state.get("toPort", raw_start)
        if isinstance(raw_start, bool) or isinstance(raw_end, bool):
            raise ValueError
        start = int(raw_start)
        end = int(raw_end)
    except (TypeError, ValueError):
        return f"{protocol}:invalid", False, False
    if not 0 <= start <= end <= 65535:
        return f"{protocol}:invalid", False, False
    port_text = str(start) if start == end else f"{start}-{end}"
    expected = protocol == "tcp" and start == end and start in expected_world_tcp_ports
    return f"{port_text}/{protocol}", True, expected


def _safe_firewall(
    response: Mapping[str, object],
    *,
    expected_world_tcp_ports: Sequence[int] = _DEFAULT_EXPECTED_WORLD_TCP_PORTS,
    limit: int = 20,
) -> _FirewallEvaluation:
    raw_states = _safe_sequence(response.get("portStates"))
    if raw_states is None:
        return _FirewallEvaluation(False, "", "", 0, 1)
    values: set[str] = set()
    all_scopes: set[str] = set()
    unsafe_world_open_count = 0
    invalid_rule_count = 0
    for raw_state in raw_states:
        if not isinstance(raw_state, Mapping):
            invalid_rule_count += 1
            continue
        state = str(raw_state.get("state", "open")).lower()
        if state == "closed":
            continue
        if state not in {"open", ""}:
            invalid_rule_count += 1
            continue
        protocol = str(raw_state.get("protocol", "")).lower()
        descriptor, valid_shape, expected_world_rule = _rule_descriptor(
            raw_state, protocol, frozenset(expected_world_tcp_ports)
        )
        scopes, invalid_sources = _rule_scopes(raw_state)
        all_scopes.update(scopes)
        invalid_rule_count += invalid_sources + int(not valid_shape)
        world_open = bool({"world_ipv4", "world_ipv6"} & scopes)
        if world_open and (not valid_shape or not expected_world_rule):
            unsafe_world_open_count += 1
        values.add(f"{descriptor}@{'+'.join(sorted(scopes))}")
    ordered = sorted(values)[:limit]
    if len(values) > limit:
        ordered.append("more")
    rules = ""
    for value in ordered:
        candidate = f"{rules},{value}" if rules else value
        if len(candidate) > 480:
            if rules and not rules.endswith("more"):
                rules = f"{rules},more"
            elif not rules:
                rules = "more"
            break
        rules = candidate
    return _FirewallEvaluation(
        True,
        rules,
        ",".join(sorted(all_scopes)),
        unsafe_world_open_count,
        invalid_rule_count,
    )


def _safe_open_ports(
    response: Mapping[str, object],
    *,
    expected_world_tcp_ports: Sequence[int] = _DEFAULT_EXPECTED_WORLD_TCP_PORTS,
    limit: int = 20,
) -> str:
    """Compatibility wrapper returning only privacy-safe firewall summaries."""

    return _safe_firewall(
        response,
        expected_world_tcp_ports=expected_world_tcp_ports,
        limit=limit,
    ).rules


def _safe_alarms(response: Mapping[str, object]) -> _AlarmEvaluation:
    raw_alarms = _safe_sequence(response.get("alarms"))
    if raw_alarms is None:
        return _AlarmEvaluation(False, 0, 0, 0, False)
    alarm_count = 0
    active_count = 0
    indeterminate_count = 0
    for raw_alarm in raw_alarms[:10000]:
        if not isinstance(raw_alarm, Mapping):
            indeterminate_count += 1
            continue
        alarm_count += 1
        state = str(raw_alarm.get("state", "")).upper()
        if state == "ALARM":
            active_count += 1
        elif state != "OK":
            indeterminate_count += 1
    return _AlarmEvaluation(
        True,
        alarm_count,
        active_count,
        indeterminate_count,
        len(raw_alarms) > 10000 or bool(response.get("nextPageToken")),
    )


def _safe_alarm_count(response: Mapping[str, object]) -> int:
    """Compatibility wrapper returning a bounded, identifier-free count."""

    return _safe_alarms(response).alarm_count


class LightsailCollector:
    """Fetch a five-minute-cached Lightsail control-plane snapshot."""

    def __init__(
        self,
        *,
        region: str,
        instance_name: str,
        request_timeout_seconds: float = 10.0,
        minimum_interval_seconds: float = 300.0,
        expected_public_tcp_ports: Sequence[int] = _DEFAULT_EXPECTED_WORLD_TCP_PORTS,
        transfer_allowance_bytes: int | None = None,
        transfer_allowance_provenance: str | None = None,
        client: LightsailClient | None = None,
        client_factory: ClientFactory = _default_client_factory,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            isinstance(minimum_interval_seconds, bool)
            or not isinstance(minimum_interval_seconds, (int, float))
            or not math.isfinite(float(minimum_interval_seconds))
            or not 300.0 <= float(minimum_interval_seconds) <= 86400.0
        ):
            raise ValueError("minimum_interval_seconds must be between 300 and 86400")
        expected_ports = tuple(expected_public_tcp_ports)
        if tuple(sorted(set(expected_ports))) != expected_ports or any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
            for port in expected_ports
        ):
            raise ValueError(
                "expected_public_tcp_ports must contain unique sorted ports"
            )
        self._region = region
        self._instance_name = instance_name
        self._request_timeout_seconds = request_timeout_seconds
        self._minimum_interval_seconds = minimum_interval_seconds
        self._fresh_for_seconds = max(
            _MIN_FRESH_FOR_SECONDS,
            min(
                _MAX_FRESH_FOR_SECONDS,
                int(math.ceil(float(minimum_interval_seconds) * 2.0)),
            ),
        )
        self._expected_public_tcp_ports = frozenset(expected_ports)
        self._transfer_allowance_bytes = transfer_allowance_bytes
        self._transfer_allowance_provenance = transfer_allowance_provenance
        self._client = client
        self._client_factory = client_factory
        self._clock = clock
        self._monotonic = monotonic
        self._last_attempt: float | None = None
        self._last_snapshot: LightsailSnapshot | None = None

    def collect(self) -> LightsailSnapshot:
        monotonic_now = self._monotonic()
        if (
            self._last_snapshot is not None
            and self._last_attempt is not None
            and monotonic_now - self._last_attempt < self._minimum_interval_seconds
        ):
            return self._last_snapshot
        self._last_attempt = monotonic_now
        observed_at = self._clock()

        if self._client is None:
            try:
                self._client = self._client_factory(
                    self._region, self._request_timeout_seconds
                )
            except Exception:
                snapshot = self._unavailable(observed_at, "client_unavailable")
                self._last_snapshot = snapshot
                return snapshot

        responses: dict[str, Mapping[str, object]] = {}
        failures: dict[str, str] = {}
        requests: tuple[
            tuple[str, Callable[..., Mapping[str, object]], dict[str, object]], ...
        ] = (
            (
                "get_instance",
                self._client.get_instance,
                {"instanceName": self._instance_name},
            ),
            (
                "get_instance_port_states",
                self._client.get_instance_port_states,
                {"instanceName": self._instance_name},
            ),
            (
                "network_in",
                self._client.get_instance_metric_data,
                self._metric_request("NetworkIn", observed_at, current_month=True),
            ),
            (
                "network_out",
                self._client.get_instance_metric_data,
                self._metric_request("NetworkOut", observed_at, current_month=True),
            ),
            (
                "cpu_utilization",
                self._client.get_instance_metric_data,
                self._metric_request("CPUUtilization", observed_at),
            ),
            (
                "burst_capacity",
                self._client.get_instance_metric_data,
                self._metric_request("BurstCapacityPercentage", observed_at),
            ),
            (
                "status_check_failed",
                self._client.get_instance_metric_data,
                self._metric_request("StatusCheckFailed", observed_at),
            ),
        )
        for name, method, arguments in requests:
            try:
                response = method(**arguments)
                responses[name] = response if isinstance(response, Mapping) else {}
            except Exception as error:
                failures[name] = _failure_category(error)
        try:
            responses["get_alarms"] = self._collect_alarm_pages()
        except Exception as error:
            failures["get_alarms"] = _failure_category(error)

        gauges: list[GaugeObservation] = []
        missing_data: set[str] = set()
        risks: set[str] = set()

        network_in = self._network_gauge(
            responses, "network_in", "network_in_month_bytes", observed_at, gauges
        )
        network_out = self._network_gauge(
            responses, "network_out", "network_out_month_bytes", observed_at, gauges
        )
        if "network_in" in responses and network_in is None:
            missing_data.add("network_in")
        if "network_out" in responses and network_out is None:
            missing_data.add("network_out")
        if network_in is not None and network_out is not None:
            gauges.append(
                GaugeObservation(
                    observed_at,
                    "aws",
                    "transfer_used_month_bytes",
                    min(network_in + network_out, _SQLITE_INTEGER_MAX),
                )
            )

        cpu_max = self._operational_gauge(
            responses,
            "cpu_utilization",
            "cpu_utilization_max_percent",
            "maximum",
            "max",
            observed_at,
            gauges,
        )
        burst_min = self._operational_gauge(
            responses,
            "burst_capacity",
            "burst_capacity_min_percent",
            "minimum",
            "min",
            observed_at,
            gauges,
        )
        status_failures = self._status_gauge(responses, observed_at, gauges)
        for response_name, value in (
            ("cpu_utilization", cpu_max),
            ("burst_capacity", burst_min),
            ("status_check_failed", status_failures),
        ):
            if response_name in responses and value is None:
                missing_data.add(response_name)
        if cpu_max is not None and cpu_max >= _CPU_HIGH_PERCENT:
            risks.add("high_cpu")
        if burst_min is not None and burst_min <= _BURST_LOW_PERCENT:
            risks.add("low_burst_capacity")
        if status_failures is not None and status_failures > 0:
            risks.add("status_check_failed")

        instance_state = "unknown"
        static_ip: bool | None = None
        if "get_instance" in responses:
            instance_state = _safe_instance_state(responses["get_instance"])
            static_ip = _safe_static_ip(responses["get_instance"])
            if instance_state == "unknown":
                missing_data.add("instance_state")
            if static_ip is None:
                missing_data.add("static_ip")
            elif not static_ip:
                risks.add("no_static_ip")

        plan_allocation_bytes = self._transfer_allowance_bytes
        plan_allocation_provenance = self._transfer_allowance_provenance
        if plan_allocation_bytes is not None and plan_allocation_provenance is None:
            plan_allocation_provenance = "operator_plan_allocation_configuration"
        if plan_allocation_bytes is None and "get_instance" in responses:
            plan_allocation_bytes = _instance_plan_allocation_bytes(
                responses["get_instance"]
            )
            if plan_allocation_bytes is not None:
                plan_allocation_provenance = _AWS_PLAN_ALLOCATION_PROVENANCE
            else:
                missing_data.add("plan_allocation")
        if (
            plan_allocation_bytes is not None
            and 0 < plan_allocation_bytes <= _SQLITE_INTEGER_MAX
        ):
            gauges.append(
                GaugeObservation(
                    observed_at,
                    "aws",
                    "transfer_plan_allocation_bytes",
                    plan_allocation_bytes,
                    {"provenance": str(plan_allocation_provenance)},
                )
            )

        firewall: _FirewallEvaluation | None = None
        if "get_instance_port_states" in responses:
            firewall = _safe_firewall(
                responses["get_instance_port_states"],
                expected_world_tcp_ports=self._expected_public_tcp_ports,
            )
            if not firewall.available or firewall.invalid_rule_count:
                missing_data.add("firewall_rules")
            if firewall.unsafe_world_open_count:
                risks.add("unsafe_world_open_firewall")

        alarms: _AlarmEvaluation | None = None
        if "get_alarms" in responses:
            alarms = _safe_alarms(responses["get_alarms"])
            if not alarms.available or alarms.truncated:
                missing_data.add("alarms")
            if alarms.active_count:
                risks.add("active_alarms")
            if alarms.indeterminate_count:
                risks.add("indeterminate_alarms")

        stopped_states = {
            "pending",
            "shutting-down",
            "terminated",
            "stopping",
            "stopped",
        }
        if instance_state in stopped_states:
            state = HealthState.UNAVAILABLE
            risks.add("instance_not_running")
        elif not responses:
            state = HealthState.UNAVAILABLE
        elif failures or missing_data or risks:
            state = HealthState.DEGRADED
        else:
            state = HealthState.HEALTHY

        successful = len(responses)
        details: dict[str, str | int | float | bool] = {
            "successful_read_count": successful,
            "failed_read_count": len(failures),
            "metric_period_seconds": 300,
            "fresh_for_seconds": self._fresh_for_seconds,
            # Kept as the stable contract consumed by existing projections.
            "metric_window": "current_month_utc",
            "network_metric_window": "current_month_utc",
            "operational_metric_window": "recent_15_minutes",
        }
        if "get_instance" in responses:
            details["instance_state"] = instance_state
            if static_ip is not None:
                details["static_ip"] = static_ip
        if firewall is not None:
            if firewall.available:
                details["firewall_open_ports"] = firewall.rules
                details["firewall_source_scopes"] = firewall.scopes
                details["unsafe_world_open_rule_count"] = (
                    firewall.unsafe_world_open_count
                )
                details["invalid_firewall_rule_count"] = firewall.invalid_rule_count
        if alarms is not None and alarms.available:
            details["alarm_count"] = alarms.alarm_count
            details["active_alarm_count"] = alarms.active_count
            details["indeterminate_alarm_count"] = alarms.indeterminate_count
        if cpu_max is not None:
            details["cpu_utilization_max_percent"] = round(cpu_max, 2)
        if burst_min is not None:
            details["burst_capacity_min_percent"] = round(burst_min, 2)
        if status_failures is not None:
            details["status_check_failed_count"] = status_failures
        if failures:
            details["failed_calls"] = ",".join(sorted(failures))
            details["failure_categories"] = ",".join(sorted(set(failures.values())))
        if missing_data:
            details["missing_data"] = ",".join(sorted(missing_data))
        if risks:
            details["risk_flags"] = ",".join(sorted(risks))
        if plan_allocation_provenance is not None:
            details["plan_allocation_provenance"] = plan_allocation_provenance

        message = (
            "Lightsail read-only telemetry collected"
            if state is HealthState.HEALTHY
            else (
                "Lightsail instance is not running"
                if "instance_not_running" in risks
                else (
                    "Lightsail read-only telemetry has risks or incomplete data"
                    if state is HealthState.DEGRADED
                    else "Lightsail read-only telemetry unavailable"
                )
            )
        )
        snapshot = LightsailSnapshot(
            observed_at,
            tuple(gauges),
            HealthObservation(observed_at, "aws", state, message, details),
        )
        self._last_snapshot = snapshot
        return snapshot

    @staticmethod
    def _network_gauge(
        responses: Mapping[str, Mapping[str, object]],
        response_name: str,
        gauge_name: str,
        observed_at: float,
        gauges: list[GaugeObservation],
    ) -> int | None:
        response = responses.get(response_name)
        if response is None:
            return None
        value = _sum_metric(response)
        if value is not None:
            gauges.append(GaugeObservation(observed_at, "aws", gauge_name, value))
        return value

    def _collect_alarm_pages(self) -> Mapping[str, object]:
        """Fetch bounded alarm pages without retaining names or page tokens."""

        assert self._client is not None
        alarm_states: list[dict[str, str]] = []
        page_token: str | None = None
        seen_tokens: set[str] = set()
        truncated = False
        for _page_number in range(_MAX_ALARM_PAGES):
            arguments: dict[str, object] = {
                "monitoredResourceName": self._instance_name
            }
            if page_token is not None:
                arguments["pageToken"] = page_token
            response = self._client.get_alarms(**arguments)
            if not isinstance(response, Mapping):
                return (
                    {"alarms": tuple(alarm_states), "nextPageToken": True}
                    if alarm_states
                    else {}
                )
            raw_alarms = _safe_sequence(response.get("alarms"))
            if raw_alarms is None:
                return (
                    {"alarms": tuple(alarm_states), "nextPageToken": True}
                    if alarm_states
                    else {}
                )
            for raw_alarm in raw_alarms:
                if len(alarm_states) >= _MAX_ALARMS:
                    truncated = True
                    break
                if isinstance(raw_alarm, Mapping):
                    alarm_states.append({"state": str(raw_alarm.get("state", ""))})
                else:
                    # Preserve malformed-entry evidence without any raw value.
                    alarm_states.append({})
            raw_token = response.get("nextPageToken")
            if not raw_token:
                return {
                    "alarms": tuple(alarm_states),
                    **({"nextPageToken": True} if truncated else {}),
                }
            if (
                not isinstance(raw_token, str)
                or len(raw_token) > 1024
                or raw_token in seen_tokens
                or truncated
            ):
                return {"alarms": tuple(alarm_states), "nextPageToken": True}
            seen_tokens.add(raw_token)
            page_token = raw_token
        return {"alarms": tuple(alarm_states), "nextPageToken": True}

    @staticmethod
    def _operational_gauge(
        responses: Mapping[str, Mapping[str, object]],
        response_name: str,
        gauge_name: str,
        statistic: str,
        aggregation: str,
        observed_at: float,
        gauges: list[GaugeObservation],
    ) -> float | None:
        response = responses.get(response_name)
        if response is None:
            return None
        values = _metric_values(response, statistic)
        if not values:
            return None
        value = max(values) if aggregation == "max" else min(values)
        gauges.append(
            GaugeObservation(
                observed_at,
                "aws",
                gauge_name,
                value,
                {
                    "window": "recent_15_minutes",
                    "statistic": statistic,
                    "aggregation": aggregation,
                },
            )
        )
        return value

    @staticmethod
    def _status_gauge(
        responses: Mapping[str, Mapping[str, object]],
        observed_at: float,
        gauges: list[GaugeObservation],
    ) -> int | None:
        response = responses.get("status_check_failed")
        if response is None:
            return None
        value = _sum_metric(response)
        if value is not None:
            gauges.append(
                GaugeObservation(
                    observed_at,
                    "aws",
                    "status_check_failed_count",
                    value,
                    {"window": "recent_15_minutes", "aggregation": "sum"},
                )
            )
        return value

    def _metric_request(
        self,
        metric_name: str,
        observed_at: float,
        *,
        current_month: bool = False,
    ) -> dict[str, object]:
        end_time = datetime.fromtimestamp(observed_at, UTC)
        is_network = metric_name in {"NetworkIn", "NetworkOut"}
        is_status = metric_name == "StatusCheckFailed"
        if is_network or is_status:
            statistics = ["Sum"]
        elif metric_name == "CPUUtilization":
            statistics = ["Maximum"]
        else:
            statistics = ["Minimum"]
        return {
            "instanceName": self._instance_name,
            "metricName": metric_name,
            "period": 300,
            "startTime": (
                _month_start(observed_at)
                if current_month
                else end_time - timedelta(minutes=15)
            ),
            "endTime": end_time,
            "unit": "Bytes" if is_network else "Count" if is_status else "Percent",
            "statistics": statistics,
        }

    def _unavailable(self, observed_at: float, reason: str) -> LightsailSnapshot:
        gauges: tuple[GaugeObservation, ...] = ()
        provenance = self._transfer_allowance_provenance
        if self._transfer_allowance_bytes is not None:
            provenance = provenance or "operator_plan_allocation_configuration"
            gauges = (
                GaugeObservation(
                    observed_at,
                    "aws",
                    "transfer_plan_allocation_bytes",
                    self._transfer_allowance_bytes,
                    {"provenance": provenance},
                ),
            )
        details: dict[str, str | int] = {
            "reason": reason,
            "fresh_for_seconds": self._fresh_for_seconds,
        }
        if provenance is not None:
            details["plan_allocation_provenance"] = provenance
        return LightsailSnapshot(
            observed_at,
            gauges,
            HealthObservation(
                observed_at,
                "aws",
                HealthState.UNAVAILABLE,
                "Lightsail read-only telemetry unavailable",
                details,
            ),
        )
