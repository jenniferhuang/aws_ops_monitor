"""Collection orchestration; this module never opens a listening socket."""

from __future__ import annotations

import logging
from threading import Event
import time
from typing import Callable

from .collectors.host import HostCollector
from .collectors.xray import XrayCollector
from .config import Config
from .models import (
    CollectionResult,
    CounterObservation,
    GaugeObservation,
    HealthObservation,
    HealthState,
    HostSnapshot,
    XraySnapshot,
)
from .store import MetricStore


LOG = logging.getLogger(__name__)


class Collector:
    """Collect local host/Xray snapshots and persist a single atomic batch."""

    def __init__(
        self,
        config: Config,
        store: MetricStore,
        *,
        host_collector: HostCollector | None = None,
        xray_collector: XrayCollector | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.store = store
        self._clock = clock
        self._monotonic = monotonic
        self._host = host_collector or HostCollector(clock=clock)
        if xray_collector is not None:
            self._xray = xray_collector
        elif config.xray_enabled:
            assert config.xray_user_hash_key is not None
            self._xray = XrayCollector(
                hash_key=config.xray_user_hash_key,
                docker_binary=config.docker_binary,
                container=config.xray_container,
                xray_binary=config.xray_binary,
                api_server=config.xray_api_server,
                timeout_seconds=config.xray_command_timeout_seconds,
                clock=clock,
            )
        else:
            self._xray = None

    def collect_once(self) -> CollectionResult:
        gauges: list[GaugeObservation] = []
        counters: list[CounterObservation] = []
        health: list[HealthObservation] = []

        if self.config.host_enabled:
            try:
                host = self._host.collect()
            except Exception:  # A failed probe must become health data, not leak internals.
                observed_at = self._clock()
                host_health = HealthObservation(
                    observed_at=observed_at,
                    component="host",
                    state=HealthState.UNAVAILABLE,
                    message="host collector failed",
                )
                health.append(host_health)
                host_state = host_health.state
            else:
                host_gauges, host_counters = _host_observations(host)
                gauges.extend(host_gauges)
                counters.extend(host_counters)
                health.append(host.health)
                host_state = host.health.state
        else:
            observed_at = self._clock()
            host_health = HealthObservation(
                observed_at=observed_at,
                component="host",
                state=HealthState.DISABLED,
                message="host collection disabled",
            )
            health.append(host_health)
            host_state = host_health.state

        if self._xray is not None:
            try:
                xray = self._xray.collect()
            except Exception:  # Keep the daemon alive without persisting raw errors.
                observed_at = self._clock()
                xray_health = HealthObservation(
                    observed_at=observed_at,
                    component="xray",
                    state=HealthState.UNAVAILABLE,
                    message="Xray collector failed",
                )
                health.append(xray_health)
                xray_state = xray_health.state
            else:
                counters.extend(_xray_observations(xray))
                health.append(xray.health)
                xray_state = xray.health.state
        else:
            observed_at = self._clock()
            xray_health = HealthObservation(
                observed_at=observed_at,
                component="xray",
                state=HealthState.DISABLED,
                message="Xray collection disabled",
            )
            health.append(xray_health)
            xray_state = xray_health.state

        self.store.record_batch(gauges=gauges, counters=counters, health=health)
        result = CollectionResult(
            observed_at=self._clock(),
            host_state=host_state,
            xray_state=xray_state,
            gauge_count=len(gauges),
            counter_count=len(counters),
        )
        LOG.info(
            "collection complete host=%s xray=%s gauges=%d counters=%d",
            result.host_state.value,
            result.xray_state.value,
            result.gauge_count,
            result.counter_count,
        )
        return result

    def run_forever(self, stop_event: Event | None = None) -> None:
        stop = stop_event or Event()
        while not stop.is_set():
            started = self._monotonic()
            try:
                self.collect_once()
            except Exception:
                LOG.exception("collection persistence failed")
            elapsed = max(0.0, self._monotonic() - started)
            stop.wait(max(0.0, self.config.interval_seconds - elapsed))


def _host_observations(
    snapshot: HostSnapshot,
) -> tuple[list[GaugeObservation], list[CounterObservation]]:
    failed = set(str(snapshot.health.details.get("failed_groups", "")).split(","))
    labels = {"host": snapshot.hostname}
    gauges: list[GaugeObservation] = []
    counters: list[CounterObservation] = []

    if "uptime" not in failed:
        gauges.append(
            GaugeObservation(
                snapshot.observed_at, "host", "uptime_seconds", snapshot.uptime_seconds, labels
            )
        )
    if "loadavg" not in failed:
        gauges.extend(
            GaugeObservation(snapshot.observed_at, "host", name, value, labels)
            for name, value in (
                ("load_1m", snapshot.load_1m),
                ("load_5m", snapshot.load_5m),
                ("load_15m", snapshot.load_15m),
            )
        )
    if "cpu_count" not in failed:
        gauges.append(
            GaugeObservation(
                snapshot.observed_at,
                "host",
                "cpu_count",
                snapshot.cpu_count,
                labels,
            )
        )
    if "memory" not in failed:
        gauges.extend(
            (
                GaugeObservation(
                    snapshot.observed_at,
                    "host",
                    "memory_total_bytes",
                    snapshot.memory_total_bytes,
                    labels,
                ),
                GaugeObservation(
                    snapshot.observed_at,
                    "host",
                    "memory_available_bytes",
                    snapshot.memory_available_bytes,
                    labels,
                ),
            )
        )
    if "disk" not in failed:
        gauges.extend(
            (
                GaugeObservation(
                    snapshot.observed_at,
                    "host",
                    "disk_total_bytes",
                    snapshot.disk_total_bytes,
                    labels,
                ),
                GaugeObservation(
                    snapshot.observed_at,
                    "host",
                    "disk_available_bytes",
                    snapshot.disk_available_bytes,
                    labels,
                ),
            )
        )
    if "cpu" not in failed:
        counters.extend(
            (
                CounterObservation(
                    snapshot.observed_at,
                    "host",
                    "cpu_total_jiffies",
                    snapshot.cpu_total_jiffies,
                    snapshot.reset_id,
                    labels,
                ),
                CounterObservation(
                    snapshot.observed_at,
                    "host",
                    "cpu_idle_jiffies",
                    snapshot.cpu_idle_jiffies,
                    snapshot.reset_id,
                    labels,
                ),
            )
        )
    if "network" not in failed:
        for interface in snapshot.interfaces:
            interface_labels = {**labels, "interface": interface.name}
            for name, value in (
                ("network_receive_bytes_total", interface.receive_bytes),
                ("network_receive_packets_total", interface.receive_packets),
                ("network_receive_errors_total", interface.receive_errors),
                ("network_receive_drops_total", interface.receive_drops),
                ("network_transmit_bytes_total", interface.transmit_bytes),
                ("network_transmit_packets_total", interface.transmit_packets),
                ("network_transmit_errors_total", interface.transmit_errors),
                ("network_transmit_drops_total", interface.transmit_drops),
            ):
                counters.append(
                    CounterObservation(
                        snapshot.observed_at,
                        "host",
                        name,
                        value,
                        snapshot.reset_id,
                        interface_labels,
                    )
                )
    return gauges, counters


def _xray_observations(snapshot: XraySnapshot) -> list[CounterObservation]:
    observations: list[CounterObservation] = []
    for counter in snapshot.counters:
        observations.append(
            CounterObservation(
                observed_at=snapshot.observed_at,
                source="xray",
                name="traffic_bytes_total",
                value=counter.value,
                reset_id=snapshot.reset_id,
                labels={
                    "scope": counter.scope,
                    "direction": counter.direction,
                    counter.identity_label: counter.identity_value,
                },
            )
        )
    return observations
