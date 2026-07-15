"""Small, storage-neutral telemetry models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import math
from typing import Mapping, TypeAlias


Scalar: TypeAlias = str | int | float | bool | None


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


def _validate_metric_part(kind: str, value: str) -> None:
    if not value or len(value) > 128 or any(ord(char) < 32 for char in value):
        raise ValueError(f"invalid {kind}")


def _validate_labels(labels: Mapping[str, str]) -> None:
    if len(labels) > 16:
        raise ValueError("too many metric labels")
    for key, value in labels.items():
        _validate_metric_part("label key", str(key))
        if len(str(value)) > 256 or any(ord(char) < 32 for char in str(value)):
            raise ValueError("invalid label value")


@dataclass(frozen=True, slots=True)
class GaugeObservation:
    observed_at: float
    source: str
    name: str
    value: float
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_metric_part("source", self.source)
        _validate_metric_part("metric name", self.name)
        _validate_labels(self.labels)
        if not math.isfinite(self.observed_at) or self.observed_at < 0:
            raise ValueError("observed_at must be a finite Unix timestamp")
        if not math.isfinite(self.value):
            raise ValueError("gauge value must be finite")


@dataclass(frozen=True, slots=True)
class CounterObservation:
    observed_at: float
    source: str
    name: str
    value: int
    reset_id: str
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_metric_part("source", self.source)
        _validate_metric_part("metric name", self.name)
        _validate_metric_part("reset identity", self.reset_id)
        _validate_labels(self.labels)
        if not math.isfinite(self.observed_at) or self.observed_at < 0:
            raise ValueError("observed_at must be a finite Unix timestamp")
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise ValueError("counter value must be an integer")
        if not 0 <= self.value <= 2**63 - 1:
            raise ValueError("counter value is outside SQLite integer range")


@dataclass(frozen=True, slots=True)
class CounterResult:
    source: str
    name: str
    value: int
    delta: int
    reset_id: str
    is_baseline: bool
    is_reset: bool
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class HealthObservation:
    observed_at: float
    component: str
    state: HealthState
    message: str
    details: Mapping[str, Scalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_metric_part("component", self.component)
        if len(self.message) > 512 or any(ord(char) < 32 for char in self.message):
            raise ValueError("invalid health message")
        if len(self.details) > 32:
            raise ValueError("too many health details")
        for key, value in self.details.items():
            _validate_metric_part("health detail key", str(key))
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("health detail values must be scalar")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("health detail numbers must be finite")
            if isinstance(value, str) and len(value) > 512:
                raise ValueError("health detail string is too long")


@dataclass(frozen=True, slots=True)
class InterfaceCounters:
    name: str
    receive_bytes: int
    receive_packets: int
    receive_errors: int
    receive_drops: int
    transmit_bytes: int
    transmit_packets: int
    transmit_errors: int
    transmit_drops: int


@dataclass(frozen=True, slots=True)
class HostSnapshot:
    observed_at: float
    hostname: str
    reset_id: str
    uptime_seconds: float
    load_1m: float
    load_5m: float
    load_15m: float
    cpu_count: int
    cpu_total_jiffies: int
    cpu_idle_jiffies: int
    memory_total_bytes: int
    memory_available_bytes: int
    disk_total_bytes: int
    disk_available_bytes: int
    interfaces: tuple[InterfaceCounters, ...]
    health: HealthObservation


@dataclass(frozen=True, slots=True)
class XrayTrafficCounter:
    scope: str
    direction: str
    identity_label: str
    identity_value: str
    value: int


@dataclass(frozen=True, slots=True)
class XraySnapshot:
    observed_at: float
    reset_id: str
    counters: tuple[XrayTrafficCounter, ...]
    health: HealthObservation


@dataclass(frozen=True, slots=True)
class ListenerObservation:
    """A privacy-safe listening socket classification.

    Only the transport, port and exposure class leave the collector. Raw bind
    addresses and peer addresses are deliberately absent from this model.
    """

    transport: str
    port: int
    exposure: str

    def __post_init__(self) -> None:
        if self.transport not in {"tcp", "udp"}:
            raise ValueError("listener transport must be tcp or udp")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError("listener port is out of range")
        if self.exposure not in {"loopback", "link_local", "public"}:
            raise ValueError("listener exposure must be loopback, link_local, or public")


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    observed_at: float
    listeners: tuple[ListenerObservation, ...]
    health: tuple[HealthObservation, ...]


@dataclass(frozen=True, slots=True)
class CollectionResult:
    observed_at: float
    host_state: HealthState
    xray_state: HealthState
    gauge_count: int
    counter_count: int
    network_state: HealthState = HealthState.DISABLED
    aws_state: HealthState = HealthState.DISABLED
