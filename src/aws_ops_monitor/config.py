"""Environment-only configuration for the collector process.

The collector intentionally has no HTTP server or listening socket. Enabling
Xray collection requires a private hashing key so user labels are pseudonymized
before they leave the in-memory parser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import re
from typing import Mapping


class ConfigError(ValueError):
    """Raised when configuration is unsafe or internally inconsistent."""


_SAFE_EXECUTABLE = re.compile(r"^[A-Za-z0-9_./-]{1,255}$")
_SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
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


def _parse_database_mode(raw: str) -> int:
    try:
        mode = int(raw, 8)
    except ValueError as exc:
        raise ConfigError("AWS_OPS_DB_FILE_MODE must be an octal file mode") from exc
    if mode not in {0o600, 0o640}:
        raise ConfigError("AWS_OPS_DB_FILE_MODE must be 0600 or 0640")
    return mode


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
    host_enabled: bool = True
    xray_enabled: bool = False
    docker_binary: str = "docker"
    xray_container: str = "xray"
    xray_binary: str = "xray"
    xray_api_server: str = "127.0.0.1:10084"
    xray_command_timeout_seconds: float = 10.0
    xray_user_hash_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.database_file_mode not in {0o600, 0o640}:
            raise ConfigError("database_file_mode must be 0600 or 0640")
        if not 5.0 <= self.interval_seconds <= 3600.0:
            raise ConfigError("interval_seconds must be between 5 and 3600")
        if not 1.0 <= self.xray_command_timeout_seconds <= 60.0:
            raise ConfigError("xray_command_timeout_seconds must be between 1 and 60")
        _validate_executable("docker_binary", self.docker_binary)
        _validate_executable("xray_binary", self.xray_binary)
        if not _SAFE_CONTAINER.fullmatch(self.xray_container):
            raise ConfigError("xray_container contains unsafe characters")
        _validate_server(self.xray_api_server)
        if self.xray_enabled and not self.xray_user_hash_key:
            raise ConfigError("Xray collection requires a private user hashing key")
        if self.xray_user_hash_key is not None and len(self.xray_user_hash_key) < 16:
            raise ConfigError("the Xray user hashing key must contain at least 16 bytes")

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
        return cls(
            database_path=database_path,
            database_file_mode=_parse_database_mode(
                env.get("AWS_OPS_DB_FILE_MODE", "0600")
            ),
            interval_seconds=interval_seconds,
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
        )
