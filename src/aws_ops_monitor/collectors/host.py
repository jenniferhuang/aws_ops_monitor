"""Linux host and interface metric collection from procfs/statvfs."""

from __future__ import annotations

from collections.abc import Callable
from hashlib import sha256
import os
from pathlib import Path
import re
import socket
import time

from ..models import HealthObservation, HealthState, HostSnapshot, InterfaceCounters


_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


def parse_uptime(text: str) -> float:
    value = float(text.split()[0])
    if value < 0:
        raise ValueError("negative uptime")
    return value


def parse_loadavg(text: str) -> tuple[float, float, float]:
    fields = text.split()
    if len(fields) < 3:
        raise ValueError("loadavg has too few fields")
    values = tuple(float(field) for field in fields[:3])
    if any(value < 0 for value in values):
        raise ValueError("negative load average")
    return values  # type: ignore[return-value]


def parse_cpu_stat(text: str) -> tuple[int, int]:
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] == "cpu":
            values = [int(value) for value in fields[1:]]
            if len(values) < 4 or any(value < 0 for value in values):
                raise ValueError("invalid aggregate CPU fields")
            # Linux reports guest and guest_nice after the first eight fields,
            # but those values are already included in user/nice. Excluding
            # them avoids double-counting aggregate CPU time.
            total = sum(values[:8])
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            return total, idle
    raise ValueError("aggregate CPU line is missing")


def parse_meminfo(text: str) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        fields = raw.split()
        if not fields:
            continue
        number = int(fields[0])
        multiplier = 1024 if len(fields) > 1 and fields[1].lower() == "kb" else 1
        values[key] = number * multiplier
    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    if available is None:
        fallback = ("MemFree", "Buffers", "Cached")
        if all(key in values for key in fallback):
            available = sum(values[key] for key in fallback)
    if total is None or available is None or total < 0 or available < 0:
        raise ValueError("required memory fields are missing")
    return total, min(total, available)


def parse_proc_net_dev(text: str) -> tuple[InterfaceCounters, ...]:
    interfaces: list[InterfaceCounters] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        raw_name, raw_values = line.split(":", 1)
        name = raw_name.strip()
        if not _INTERFACE_NAME.fullmatch(name):
            continue
        fields = raw_values.split()
        if len(fields) < 16:
            raise ValueError("network interface line has too few fields")
        values = [int(field) for field in fields[:16]]
        if any(value < 0 for value in values):
            raise ValueError("network interface counter is negative")
        interfaces.append(
            InterfaceCounters(
                name=name,
                receive_bytes=values[0],
                receive_packets=values[1],
                receive_errors=values[2],
                receive_drops=values[3],
                transmit_bytes=values[8],
                transmit_packets=values[9],
                transmit_errors=values[10],
                transmit_drops=values[11],
            )
        )
    if not interfaces:
        raise ValueError("no network interfaces found")
    return tuple(sorted(interfaces, key=lambda item: item.name))


def _opaque_reset_id(namespace: str, value: str) -> str:
    digest = sha256(f"{namespace}\0{value}".encode("utf-8")).hexdigest()[:24]
    return f"{namespace}:{digest}"


class HostCollector:
    """Collect host metrics without subprocesses or network access."""

    def __init__(
        self,
        *,
        proc_root: str | Path = "/proc",
        root_path: str | Path = "/",
        clock: Callable[[], float] = time.time,
        hostname: Callable[[], str] = socket.gethostname,
        cpu_count: Callable[[], int | None] = os.cpu_count,
        statvfs: Callable[[str | bytes | os.PathLike[str]], os.statvfs_result] = os.statvfs,
    ) -> None:
        self._proc_root = Path(proc_root)
        self._root_path = Path(root_path)
        self._clock = clock
        self._hostname = hostname
        self._cpu_count = cpu_count
        self._statvfs = statvfs

    def collect(self) -> HostSnapshot:
        observed_at = self._clock()
        hostname = self._hostname().strip()[:255] or "unknown-host"
        failures: list[str] = []

        uptime = 0.0
        try:
            uptime = parse_uptime((self._proc_root / "uptime").read_text())
        except (OSError, ValueError, IndexError):
            failures.append("uptime")

        loads = (0.0, 0.0, 0.0)
        try:
            loads = parse_loadavg((self._proc_root / "loadavg").read_text())
        except (OSError, ValueError):
            failures.append("loadavg")

        cpu_total = 0
        cpu_idle = 0
        try:
            cpu_total, cpu_idle = parse_cpu_stat(
                (self._proc_root / "stat").read_text()
            )
        except (OSError, ValueError):
            failures.append("cpu")

        memory_total = 0
        memory_available = 0
        try:
            memory_total, memory_available = parse_meminfo(
                (self._proc_root / "meminfo").read_text()
            )
        except (OSError, ValueError):
            failures.append("memory")

        interfaces: tuple[InterfaceCounters, ...] = ()
        try:
            interfaces = parse_proc_net_dev(
                (self._proc_root / "net" / "dev").read_text()
            )
        except (OSError, ValueError):
            failures.append("network")

        disk_total = 0
        disk_available = 0
        try:
            disk = self._statvfs(self._root_path)
            fragment_size = disk.f_frsize or disk.f_bsize
            disk_total = int(fragment_size * disk.f_blocks)
            disk_available = int(fragment_size * disk.f_bavail)
        except (OSError, ValueError):
            failures.append("disk")

        boot_material = ""
        try:
            boot_material = (
                self._proc_root / "sys" / "kernel" / "random" / "boot_id"
            ).read_text().strip()
            if not boot_material:
                raise ValueError("empty boot identity")
        except (OSError, ValueError):
            failures.append("boot_id")
            boot_material = f"fallback:{hostname}"
        reset_id = _opaque_reset_id("host-boot", boot_material)

        processor_count = self._cpu_count() or 0
        if processor_count < 1:
            failures.append("cpu_count")
            processor_count = 0

        if not failures:
            state = HealthState.HEALTHY
            message = "host metrics collected"
        elif uptime > 0 or memory_total > 0 or interfaces:
            state = HealthState.DEGRADED
            message = "partial host metrics collected"
        else:
            state = HealthState.UNAVAILABLE
            message = "host metrics unavailable"
        health = HealthObservation(
            observed_at=observed_at,
            component="host",
            state=state,
            message=message,
            details={
                "failure_count": len(failures),
                "failed_groups": ",".join(sorted(failures)),
                "interface_count": len(interfaces),
            },
        )
        return HostSnapshot(
            observed_at=observed_at,
            hostname=hostname,
            reset_id=reset_id,
            uptime_seconds=uptime,
            load_1m=loads[0],
            load_5m=loads[1],
            load_15m=loads[2],
            cpu_count=processor_count,
            cpu_total_jiffies=cpu_total,
            cpu_idle_jiffies=cpu_idle,
            memory_total_bytes=memory_total,
            memory_available_bytes=memory_available,
            disk_total_bytes=disk_total,
            disk_available_bytes=disk_available,
            interfaces=interfaces,
            health=health,
        )
