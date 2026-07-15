"""Environment-only configuration for the collector process.

The collector intentionally has no HTTP server or listening socket. Enabling
Xray collection requires a private hashing key so user labels are pseudonymized
before they leave the in-memory parser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
import os
import re
from typing import Mapping


class ConfigError(ValueError):
    """Raised when configuration is unsafe or internally inconsistent."""


_SAFE_EXECUTABLE = re.compile(r"^[A-Za-z0-9_./-]{1,255}$")
_SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SAFE_AWS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_SAFE_AWS_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SAFE_PROVENANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SAFE_HTTP_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$")
_LOOPBACK_SERVER = re.compile(r"^(?:127\.0\.0\.1|\[::1\]):([0-9]{1,5})$")
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _default_database_path(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    state_home = values.get("XDG_STATE_HOME")
    base = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return base / "aws-ops-monitor" / "metrics.sqlite3"


def _parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean value")


def _parse_float(name: str, raw: str, minimum: float, maximum: float) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum:g} and {maximum:g}")
    return value


def _parse_int(name: str, raw: str, minimum: int, maximum: int) -> int:
    value = raw.strip()
    if not value.isascii() or not value.isdecimal():
        raise ConfigError(f"{name} must be an integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _parse_database_mode(raw: str) -> int:
    try:
        mode = int(raw, 8)
    except ValueError as exc:
        raise ConfigError("AWS_OPS_DB_FILE_MODE must be an octal file mode") from exc
    if mode not in {0o600, 0o640}:
        raise ConfigError("AWS_OPS_DB_FILE_MODE must be 0600 or 0640")
    return mode


def _parse_ports(name: str, raw: str) -> tuple[int, ...]:
    ports: set[int] = set()
    if not raw.strip():
        return ()
    for item in raw.split(","):
        value = item.strip()
        if not value.isascii() or not value.isdecimal():
            raise ConfigError(f"{name} must be a comma-separated list of ports")
        port = int(value)
        if not 1 <= port <= 65535:
            raise ConfigError(f"{name} contains a port outside 1-65535")
        ports.add(port)
    return tuple(sorted(ports))


def _parse_optional_bytes(name: str, raw: str | None) -> int | None:
    if raw is None or not raw.strip():
        return None
    value = raw.strip()
    if not value.isascii() or not value.isdecimal():
        raise ConfigError(f"{name} must be a positive integer byte count")
    parsed = int(value)
    if not 1 <= parsed <= 2**63 - 1:
        raise ConfigError(f"{name} is outside the supported byte range")
    return parsed


def _read_hash_key(environment: Mapping[str, str]) -> bytes | None:
    direct = environment.get("AWS_OPS_XRAY_USER_HASH_KEY")
    key_file = environment.get("AWS_OPS_XRAY_USER_HASH_KEY_FILE")
    if direct and key_file:
        raise ConfigError(
            "set only one of AWS_OPS_XRAY_USER_HASH_KEY and "
            "AWS_OPS_XRAY_USER_HASH_KEY_FILE"
        )
    if key_file:
        path = Path(key_file).expanduser()
        try:
            if not path.is_file():
                raise ConfigError("AWS_OPS_XRAY_USER_HASH_KEY_FILE must be a regular file")
            metadata = path.stat()
            if not metadata.st_mode & 0o400 or metadata.st_mode & 0o077:
                raise ConfigError(
                    "AWS_OPS_XRAY_USER_HASH_KEY_FILE must be owner-readable only"
                )
            if metadata.st_size > 4096:
                raise ConfigError("AWS_OPS_XRAY_USER_HASH_KEY_FILE is unexpectedly large")
            value = path.read_bytes().strip()
        except OSError as exc:
            raise ConfigError("unable to read AWS_OPS_XRAY_USER_HASH_KEY_FILE") from exc
    elif direct:
        value = direct.encode("utf-8")
    else:
        return None
    if len(value) < 16:
        raise ConfigError("the Xray user hashing key must contain at least 16 bytes")
    return value


def _validate_executable(name: str, value: str) -> str:
    if not _SAFE_EXECUTABLE.fullmatch(value):
        raise ConfigError(f"{name} contains unsafe characters")
    return value


def _validate_server(value: str) -> str:
    match = _LOOPBACK_SERVER.fullmatch(value)
    if not match:
        raise ConfigError("AWS_OPS_XRAY_API_SERVER must use a loopback address")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise ConfigError("AWS_OPS_XRAY_API_SERVER port is out of range")
    return value


def _validate_public_hostname(value: str) -> str:
    hostname = value.rstrip(".")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ConfigError("AWS_OPS_PROBE_PUBLIC_HOST must be a valid DNS hostname")
    if (
        hostname != value
        or len(hostname) > 253
        or "." not in hostname
        or any(not _SAFE_HOST_LABEL.fullmatch(label) for label in hostname.split("."))
    ):
        raise ConfigError("AWS_OPS_PROBE_PUBLIC_HOST must be a valid DNS hostname")
    return hostname.lower()


def _validate_http_path(value: str) -> str:
    if not _SAFE_HTTP_PATH.fullmatch(value) or "//" in value:
        raise ConfigError("AWS_OPS_PROBE_PUBLIC_PATH must be a bounded absolute path")
    return value


@dataclass(frozen=True, slots=True)
class Config:
    """Validated collector configuration.

    Xray is disabled by default. It may only be enabled with a hashing key;
    the key is excluded from dataclass representations to prevent accidental
    logging.
    """

    database_path: Path = field(default_factory=_default_database_path)
    database_file_mode: int = 0o600
    interval_seconds: float = 30.0
    raw_retention_days: int = 7
    rollup_retention_days: int = 400
    retention_prune_interval_seconds: float = 3600.0
    host_enabled: bool = True
    xray_enabled: bool = False
    docker_binary: str = "docker"
    xray_container: str = "xray"
    xray_binary: str = "xray"
    xray_api_server: str = "127.0.0.1:10084"
    xray_command_timeout_seconds: float = 10.0
    xray_user_hash_key: bytes | None = field(default=None, repr=False)
    network_enabled: bool = True
    ss_binary: str = "ss"
    network_command_timeout_seconds: float = 5.0
    expected_public_ports: tuple[int, ...] = (22, 80)
    expected_loopback_ports: tuple[int, ...] = (8787, 10084)
    expected_public_udp_ports: tuple[int, ...] = ()
    expected_loopback_udp_ports: tuple[int, ...] = ()
    path_probes_enabled: bool = True
    probe_public_hostname: str = "v2.hermes-node.com"
    probe_public_path: str = "/302"
    warp_probe_enabled: bool = True
    warp_proxy_server: str = "127.0.0.1:1087"
    probe_timeout_seconds: float = 8.0
    probe_minimum_interval_seconds: float = 300.0
    getent_binary: str = "getent"
    aws_enabled: bool = False
    aws_region: str = "ap-southeast-1"
    lightsail_instance_name: str = ""
    aws_request_timeout_seconds: float = 10.0
    aws_minimum_interval_seconds: float = 300.0
    transfer_allowance_bytes: int | None = None
    transfer_allowance_provenance: str | None = None

    def __post_init__(self) -> None:
        if self.database_file_mode not in {0o600, 0o640}:
            raise ConfigError("database_file_mode must be 0600 or 0640")
        if not 5.0 <= self.interval_seconds <= 3600.0:
            raise ConfigError("interval_seconds must be between 5 and 3600")
        if (
            isinstance(self.raw_retention_days, bool)
            or not isinstance(self.raw_retention_days, int)
            or not 1 <= self.raw_retention_days <= 30
        ):
            raise ConfigError("raw_retention_days must be between 1 and 30")
        if (
            isinstance(self.rollup_retention_days, bool)
            or not isinstance(self.rollup_retention_days, int)
            or not 30 <= self.rollup_retention_days <= 800
        ):
            raise ConfigError("rollup_retention_days must be between 30 and 800")
        if self.rollup_retention_days <= self.raw_retention_days:
            raise ConfigError("rollup retention must be longer than raw retention")
        if not 300.0 <= self.retention_prune_interval_seconds <= 86400.0:
            raise ConfigError(
                "retention_prune_interval_seconds must be between 300 and 86400"
            )
        if not 1.0 <= self.xray_command_timeout_seconds <= 60.0:
            raise ConfigError("xray_command_timeout_seconds must be between 1 and 60")
        if not 1.0 <= self.network_command_timeout_seconds <= 60.0:
            raise ConfigError("network_command_timeout_seconds must be between 1 and 60")
        if not 1.0 <= self.probe_timeout_seconds <= 30.0:
            raise ConfigError("probe_timeout_seconds must be between 1 and 30")
        if not 300.0 <= self.probe_minimum_interval_seconds <= 86400.0:
            raise ConfigError("probe_minimum_interval_seconds must be between 300 and 86400")
        if not 1.0 <= self.aws_request_timeout_seconds <= 60.0:
            raise ConfigError("aws_request_timeout_seconds must be between 1 and 60")
        if not 300.0 <= self.aws_minimum_interval_seconds <= 86400.0:
            raise ConfigError("aws_minimum_interval_seconds must be between 300 and 86400")
        _validate_executable("docker_binary", self.docker_binary)
        _validate_executable("xray_binary", self.xray_binary)
        _validate_executable("ss_binary", self.ss_binary)
        _validate_executable("getent_binary", self.getent_binary)
        if not _SAFE_CONTAINER.fullmatch(self.xray_container):
            raise ConfigError("xray_container contains unsafe characters")
        _validate_server(self.xray_api_server)
        _validate_public_hostname(self.probe_public_hostname)
        _validate_http_path(self.probe_public_path)
        _validate_server(self.warp_proxy_server)
        if self.xray_enabled and not self.xray_user_hash_key:
            raise ConfigError("Xray collection requires a private user hashing key")
        if self.xray_user_hash_key is not None and len(self.xray_user_hash_key) < 16:
            raise ConfigError("the Xray user hashing key must contain at least 16 bytes")
        for ports, name in (
            (self.expected_public_ports, "expected_public_ports"),
            (self.expected_loopback_ports, "expected_loopback_ports"),
            (self.expected_public_udp_ports, "expected_public_udp_ports"),
            (self.expected_loopback_udp_ports, "expected_loopback_udp_ports"),
        ):
            if tuple(sorted(set(ports))) != ports or any(
                isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                for port in ports
            ):
                raise ConfigError(f"{name} must contain unique sorted ports")
        if not _SAFE_AWS_REGION.fullmatch(self.aws_region):
            raise ConfigError("aws_region is invalid")
        if self.lightsail_instance_name and not _SAFE_AWS_NAME.fullmatch(
            self.lightsail_instance_name
        ):
            raise ConfigError("lightsail_instance_name is invalid")
        if self.aws_enabled and not self.lightsail_instance_name:
            raise ConfigError("AWS collection requires an explicit Lightsail instance name")
        if self.transfer_allowance_bytes is not None and (
            isinstance(self.transfer_allowance_bytes, bool)
            or not isinstance(self.transfer_allowance_bytes, int)
            or not 1 <= self.transfer_allowance_bytes <= 2**63 - 1
        ):
            raise ConfigError("transfer_allowance_bytes is outside the supported range")
        if self.transfer_allowance_bytes is not None:
            if not self.transfer_allowance_provenance or not _SAFE_PROVENANCE.fullmatch(
                self.transfer_allowance_provenance
            ):
                raise ConfigError(
                    "a safe transfer allowance provenance is required with an allowance"
                )
        elif self.transfer_allowance_provenance is not None:
            raise ConfigError("transfer allowance provenance requires an allowance")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Config:
        env = os.environ if environ is None else environ
        database_path = Path(
            env.get("AWS_OPS_DB_PATH", str(_default_database_path(env)))
        ).expanduser()
        interval_seconds = _parse_float(
            "AWS_OPS_INTERVAL_SECONDS",
            env.get("AWS_OPS_INTERVAL_SECONDS", "30"),
            5,
            3600,
        )
        raw_retention_days = _parse_int(
            "AWS_OPS_RAW_RETENTION_DAYS",
            env.get("AWS_OPS_RAW_RETENTION_DAYS", "7"),
            1,
            30,
        )
        rollup_retention_days = _parse_int(
            "AWS_OPS_ROLLUP_RETENTION_DAYS",
            env.get("AWS_OPS_ROLLUP_RETENTION_DAYS", "400"),
            30,
            800,
        )
        retention_interval = _parse_float(
            "AWS_OPS_RETENTION_INTERVAL_SECONDS",
            env.get("AWS_OPS_RETENTION_INTERVAL_SECONDS", "3600"),
            300,
            86400,
        )
        host_enabled = _parse_bool(
            "AWS_OPS_HOST_ENABLED", env.get("AWS_OPS_HOST_ENABLED", "true")
        )
        xray_enabled = _parse_bool(
            "AWS_OPS_XRAY_ENABLED", env.get("AWS_OPS_XRAY_ENABLED", "false")
        )
        timeout = _parse_float(
            "AWS_OPS_XRAY_TIMEOUT_SECONDS",
            env.get("AWS_OPS_XRAY_TIMEOUT_SECONDS", "10"),
            1,
            60,
        )
        network_timeout = _parse_float(
            "AWS_OPS_NETWORK_TIMEOUT_SECONDS",
            env.get("AWS_OPS_NETWORK_TIMEOUT_SECONDS", "5"),
            1,
            60,
        )
        probe_timeout = _parse_float(
            "AWS_OPS_PROBE_TIMEOUT_SECONDS",
            env.get("AWS_OPS_PROBE_TIMEOUT_SECONDS", "8"),
            1,
            30,
        )
        probe_interval = _parse_float(
            "AWS_OPS_PROBE_INTERVAL_SECONDS",
            env.get("AWS_OPS_PROBE_INTERVAL_SECONDS", "300"),
            300,
            86400,
        )
        aws_timeout = _parse_float(
            "AWS_OPS_AWS_TIMEOUT_SECONDS",
            env.get("AWS_OPS_AWS_TIMEOUT_SECONDS", "10"),
            1,
            60,
        )
        aws_interval = _parse_float(
            "AWS_OPS_AWS_INTERVAL_SECONDS",
            env.get("AWS_OPS_AWS_INTERVAL_SECONDS", "300"),
            300,
            86400,
        )
        allowance = _parse_optional_bytes(
            "AWS_OPS_TRANSFER_ALLOWANCE_BYTES",
            env.get("AWS_OPS_TRANSFER_ALLOWANCE_BYTES"),
        )
        provenance = env.get("AWS_OPS_TRANSFER_ALLOWANCE_SOURCE") or None
        return cls(
            database_path=database_path,
            database_file_mode=_parse_database_mode(
                env.get("AWS_OPS_DB_FILE_MODE", "0600")
            ),
            interval_seconds=interval_seconds,
            raw_retention_days=raw_retention_days,
            rollup_retention_days=rollup_retention_days,
            retention_prune_interval_seconds=retention_interval,
            host_enabled=host_enabled,
            xray_enabled=xray_enabled,
            docker_binary=_validate_executable(
                "AWS_OPS_DOCKER_BINARY", env.get("AWS_OPS_DOCKER_BINARY", "docker")
            ),
            xray_container=env.get("AWS_OPS_XRAY_CONTAINER", "xray"),
            xray_binary=_validate_executable(
                "AWS_OPS_XRAY_BINARY", env.get("AWS_OPS_XRAY_BINARY", "xray")
            ),
            xray_api_server=_validate_server(
                env.get("AWS_OPS_XRAY_API_SERVER", "127.0.0.1:10084")
            ),
            xray_command_timeout_seconds=timeout,
            xray_user_hash_key=_read_hash_key(env),
            network_enabled=_parse_bool(
                "AWS_OPS_NETWORK_ENABLED", env.get("AWS_OPS_NETWORK_ENABLED", "true")
            ),
            ss_binary=_validate_executable(
                "AWS_OPS_SS_BINARY", env.get("AWS_OPS_SS_BINARY", "ss")
            ),
            network_command_timeout_seconds=network_timeout,
            expected_public_ports=_parse_ports(
                "AWS_OPS_EXPECTED_PUBLIC_PORTS",
                env.get("AWS_OPS_EXPECTED_PUBLIC_PORTS", "22,80"),
            ),
            expected_loopback_ports=_parse_ports(
                "AWS_OPS_EXPECTED_LOOPBACK_PORTS",
                env.get("AWS_OPS_EXPECTED_LOOPBACK_PORTS", "8787,10084"),
            ),
            expected_public_udp_ports=_parse_ports(
                "AWS_OPS_EXPECTED_PUBLIC_UDP_PORTS",
                env.get("AWS_OPS_EXPECTED_PUBLIC_UDP_PORTS", ""),
            ),
            expected_loopback_udp_ports=_parse_ports(
                "AWS_OPS_EXPECTED_LOOPBACK_UDP_PORTS",
                env.get("AWS_OPS_EXPECTED_LOOPBACK_UDP_PORTS", ""),
            ),
            path_probes_enabled=_parse_bool(
                "AWS_OPS_PATH_PROBES_ENABLED",
                env.get("AWS_OPS_PATH_PROBES_ENABLED", "true"),
            ),
            probe_public_hostname=_validate_public_hostname(
                env.get("AWS_OPS_PROBE_PUBLIC_HOST", "v2.hermes-node.com")
            ),
            probe_public_path=_validate_http_path(
                env.get("AWS_OPS_PROBE_PUBLIC_PATH", "/302")
            ),
            warp_probe_enabled=_parse_bool(
                "AWS_OPS_WARP_PROBE_ENABLED",
                env.get("AWS_OPS_WARP_PROBE_ENABLED", "true"),
            ),
            warp_proxy_server=_validate_server(
                env.get("AWS_OPS_WARP_PROXY_SERVER", "127.0.0.1:1087")
            ),
            probe_timeout_seconds=probe_timeout,
            probe_minimum_interval_seconds=probe_interval,
            getent_binary=_validate_executable(
                "AWS_OPS_GETENT_BINARY", env.get("AWS_OPS_GETENT_BINARY", "getent")
            ),
            aws_enabled=_parse_bool(
                "AWS_OPS_AWS_ENABLED", env.get("AWS_OPS_AWS_ENABLED", "false")
            ),
            aws_region=env.get("AWS_OPS_AWS_REGION", "ap-southeast-1"),
            lightsail_instance_name=env.get("AWS_OPS_LIGHTSAIL_INSTANCE", ""),
            aws_request_timeout_seconds=aws_timeout,
            aws_minimum_interval_seconds=aws_interval,
            transfer_allowance_bytes=allowance,
            transfer_allowance_provenance=provenance,
        )
