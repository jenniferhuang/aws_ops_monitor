"""Bounded, privacy-safe synthetic checks for the configured VPN paths.

Probe implementations retain resolved addresses and response bytes only in
local variables.  Persisted observations contain fixed labels, status codes,
timings, and a small failure enum; they never contain an address, response
body, response header, or exception string.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import base64
from hashlib import sha1
import hmac
import http.client
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import time

from ..models import HealthObservation, HealthState


MAX_DNS_OUTPUT_BYTES = 64 * 1024
MAX_HTTP_OUTPUT_BYTES = 16 * 1024
_WARP_MARKER = re.compile(rb"(?:^|\n)warp=(?:on|plus)(?:\r?\n|$)")
_SAFE_REASONS = frozenset(
    {
        "collector_failed",
        "connection_failed",
        "dns_unavailable",
        "invalid_upgrade",
        "no_global_address",
        "proxy_unavailable",
        "resolution_failed",
        "resolved",
        "resolver_unavailable",
        "response_too_large",
        "timeout",
        "tls_failed",
        "trace_marker_missing",
        "trace_marker_observed",
        "unexpected_status",
        "upgrade_accepted",
        "unavailable",
    }
)
_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass(frozen=True, slots=True)
class DNSResult:
    ok: bool
    addresses: tuple[str, ...] = ()
    reason: str = "unavailable"
    latency_ms: int = 0


@dataclass(frozen=True, slots=True)
class ProbeResult:
    ok: bool
    reason: str
    latency_ms: int
    status_code: int | None = None
    marker_observed: bool | None = None


Resolver = Callable[[str, str, float], DNSResult]
WebSocketProber = Callable[[str, str, Sequence[str], float], ProbeResult]
WarpProber = Callable[[str, float], ProbeResult]


def _bounded_ms(started: float, monotonic: Callable[[], float]) -> int:
    return min(2**31 - 1, max(0, round((monotonic() - started) * 1000)))


def _safe_reason(value: str) -> str:
    return value if value in _SAFE_REASONS else "unavailable"


def _safe_latency(value: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**31 - 1:
        return value
    return 0


def _safe_status(value: int | None) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return None


def _valid_websocket_upgrade(payload: bytes, key: str) -> bool:
    """Require the complete RFC 6455 server-side HTTP/1.1 handshake."""

    header_block, separator, _body = payload.partition(b"\r\n\r\n")
    if not separator:
        return False
    lines = header_block.split(b"\r\n")
    if not lines or lines[0].split(b" ", 2)[:2] != [b"HTTP/1.1", b"101"]:
        return False
    headers: dict[bytes, list[bytes]] = {}
    for line in lines[1:]:
        name, header_separator, value = line.partition(b":")
        if not header_separator or not name:
            return False
        headers.setdefault(name.strip().lower(), []).append(value.strip())

    upgrade_tokens = {
        token.strip().lower()
        for value in headers.get(b"upgrade", ())
        for token in value.split(b",")
    }
    connection_tokens = {
        token.strip().lower()
        for value in headers.get(b"connection", ())
        for token in value.split(b",")
    }
    accepts = headers.get(b"sec-websocket-accept", ())
    if b"websocket" not in upgrade_tokens or b"upgrade" not in connection_tokens:
        return False
    if len(accepts) != 1:
        return False
    expected = base64.b64encode(
        sha1(f"{key}{_WEBSOCKET_GUID}".encode("ascii")).digest()
    )
    return hmac.compare_digest(accepts[0], expected)


def resolve_public_addresses(
    getent_binary: str,
    hostname: str,
    timeout_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> DNSResult:
    """Resolve a configured name and accept only globally routable answers."""

    started = monotonic()
    try:
        result = subprocess.run(  # noqa: S603 - validated binary and hostname, no shell
            (getent_binary, "ahosts", hostname),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return DNSResult(False, reason="timeout", latency_ms=_bounded_ms(started, monotonic))
    except OSError:
        return DNSResult(
            False, reason="resolver_unavailable", latency_ms=_bounded_ms(started, monotonic)
        )
    if result.returncode != 0:
        return DNSResult(
            False,
            reason="resolution_failed",
            latency_ms=_bounded_ms(started, monotonic),
        )
    if len(result.stdout) > MAX_DNS_OUTPUT_BYTES:
        return DNSResult(
            False,
            reason="response_too_large",
            latency_ms=_bounded_ms(started, monotonic),
        )

    addresses: list[str] = []
    for raw_line in result.stdout.splitlines()[:128]:
        field = raw_line.split(maxsplit=1)[0] if raw_line.split(maxsplit=1) else b""
        try:
            address = ipaddress.ip_address(field.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            continue
        if address.is_global and str(address) not in addresses:
            addresses.append(str(address))
        if len(addresses) >= 4:
            break
    if not addresses:
        return DNSResult(
            False,
            reason="no_global_address",
            latency_ms=_bounded_ms(started, monotonic),
        )
    return DNSResult(
        True,
        tuple(addresses),
        reason="resolved",
        latency_ms=_bounded_ms(started, monotonic),
    )


def probe_websocket_upgrade(
    hostname: str,
    path: str,
    addresses: Sequence[str],
    timeout_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> ProbeResult:
    """Perform a TLS WebSocket handshake and require HTTP 101."""

    started = monotonic()
    deadline = started + timeout_seconds
    saw_timeout = False
    for raw_address in tuple(addresses)[:4]:
        remaining = deadline - monotonic()
        if remaining <= 0:
            saw_timeout = True
            break
        plain_socket: socket.socket | None = None
        tls_socket: ssl.SSLSocket | None = None
        try:
            address = ipaddress.ip_address(raw_address)
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            endpoint: tuple[object, ...]
            endpoint = (str(address), 443, 0, 0) if address.version == 6 else (str(address), 443)
            plain_socket = socket.socket(family, socket.SOCK_STREAM)
            plain_socket.settimeout(remaining)
            plain_socket.connect(endpoint)
            context = ssl.create_default_context()
            tls_socket = context.wrap_socket(plain_socket, server_hostname=hostname)
            plain_socket = None
            key = base64.b64encode(os.urandom(16)).decode("ascii")
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "User-Agent: aws-ops-monitor\r\n\r\n"
            ).encode("ascii")
            tls_socket.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) <= MAX_HTTP_OUTPUT_BYTES:
                chunk = tls_socket.recv(min(4096, MAX_HTTP_OUTPUT_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
            if len(response) > MAX_HTTP_OUTPUT_BYTES:
                return ProbeResult(
                    False, "response_too_large", _bounded_ms(started, monotonic)
                )
            status_line = bytes(response).split(b"\r\n", 1)[0]
            parts = status_line.split(b" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
            if status_code == 101 and _valid_websocket_upgrade(bytes(response), key):
                return ProbeResult(True, "upgrade_accepted", _bounded_ms(started, monotonic), 101)
            if status_code == 101:
                return ProbeResult(
                    False,
                    "invalid_upgrade",
                    _bounded_ms(started, monotonic),
                    101,
                )
            return ProbeResult(
                False,
                "unexpected_status",
                _bounded_ms(started, monotonic),
                status_code,
            )
        except (TimeoutError, socket.timeout):
            saw_timeout = True
        except ssl.SSLError:
            return ProbeResult(False, "tls_failed", _bounded_ms(started, monotonic))
        except (OSError, ValueError):
            pass
        finally:
            if tls_socket is not None:
                tls_socket.close()
            if plain_socket is not None:
                plain_socket.close()
    return ProbeResult(
        False,
        "timeout" if saw_timeout else "connection_failed",
        _bounded_ms(started, monotonic),
    )


def probe_warp_trace(
    proxy_server: str,
    timeout_seconds: float,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> ProbeResult:
    """Fetch Cloudflare's fixed trace endpoint through the local HTTP proxy."""

    started = monotonic()
    raw_host, raw_port = proxy_server.rsplit(":", 1)
    host = raw_host.strip("[]")
    connection: http.client.HTTPSConnection | None = None
    try:
        connection = http.client.HTTPSConnection(
            host,
            int(raw_port),
            timeout=timeout_seconds,
            context=ssl.create_default_context(),
        )
        connection.set_tunnel("www.cloudflare.com", 443)
        connection.request(
            "GET",
            "/cdn-cgi/trace",
            headers={"Host": "www.cloudflare.com", "User-Agent": "aws-ops-monitor"},
        )
        response = connection.getresponse()
        payload = response.read(MAX_HTTP_OUTPUT_BYTES + 1)
        if len(payload) > MAX_HTTP_OUTPUT_BYTES:
            return ProbeResult(
                False,
                "response_too_large",
                _bounded_ms(started, monotonic),
                response.status,
                False,
            )
        marker_observed = bool(_WARP_MARKER.search(payload))
        ok = response.status == 200 and marker_observed
        reason = "trace_marker_observed" if ok else (
            "unexpected_status" if response.status != 200 else "trace_marker_missing"
        )
        return ProbeResult(
            ok,
            reason,
            _bounded_ms(started, monotonic),
            response.status,
            marker_observed,
        )
    except (TimeoutError, socket.timeout):
        return ProbeResult(False, "timeout", _bounded_ms(started, monotonic))
    except ssl.SSLError:
        return ProbeResult(False, "tls_failed", _bounded_ms(started, monotonic))
    except (OSError, ValueError, http.client.HTTPException):
        return ProbeResult(False, "proxy_unavailable", _bounded_ms(started, monotonic))
    finally:
        if connection is not None:
            connection.close()


class PathProbeCollector:
    """Run synthetic path checks no more often than the configured interval."""

    def __init__(
        self,
        *,
        public_hostname: str,
        public_path: str,
        warp_enabled: bool,
        warp_proxy_server: str,
        getent_binary: str = "getent",
        timeout_seconds: float = 8.0,
        minimum_interval_seconds: float = 300.0,
        resolver: Resolver = resolve_public_addresses,
        websocket_prober: WebSocketProber = probe_websocket_upgrade,
        warp_prober: WarpProber = probe_warp_trace,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._public_hostname = public_hostname
        self._public_path = public_path
        self._warp_enabled = warp_enabled
        self._warp_proxy_server = warp_proxy_server
        self._getent_binary = getent_binary
        self._timeout_seconds = timeout_seconds
        self._minimum_interval_seconds = max(300.0, minimum_interval_seconds)
        self._fresh_for_seconds = min(
            172800,
            max(600, round(self._minimum_interval_seconds * 2)),
        )
        self._resolver = resolver
        self._websocket_prober = websocket_prober
        self._warp_prober = warp_prober
        self._clock = clock
        self._monotonic = monotonic
        self._last_attempt: float | None = None

    def collect(self) -> tuple[HealthObservation, ...]:
        now = self._monotonic()
        if (
            self._last_attempt is not None
            and now - self._last_attempt < self._minimum_interval_seconds
        ):
            return ()
        self._last_attempt = now
        observed_at = self._clock()

        dns = self._resolver(
            self._getent_binary,
            self._public_hostname,
            self._timeout_seconds,
        )
        global_addresses: list[str] = []
        for raw_address in tuple(dns.addresses)[:4]:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                continue
            if address.is_global:
                global_addresses.append(str(address))
        dns_ok = dns.ok and bool(global_addresses)
        dns_health = HealthObservation(
            observed_at,
            "path_public_dns",
            HealthState.HEALTHY if dns_ok else HealthState.UNAVAILABLE,
            "public hostname resolved to a global address"
            if dns_ok
            else "public hostname resolution failed",
            {
                "name": "Public DNS",
                "direction": "outbound check",
                "route": "Lightsail>DNS resolver>global address",
                "status": "verified" if dns_ok else "failed",
                "evidence": "synthetic_probe",
                "required": True,
                "fresh_for_seconds": self._fresh_for_seconds,
                "reason": _safe_reason(dns.reason),
                "latency_ms": _safe_latency(dns.latency_ms),
            },
        )
        if dns_ok:
            websocket = self._websocket_prober(
                self._public_hostname,
                self._public_path,
                tuple(global_addresses),
                self._timeout_seconds,
            )
        else:
            websocket = ProbeResult(False, "dns_unavailable", dns.latency_ms)
        websocket_details: dict[str, str | int | bool | None] = {
            "name": "Public Xray WebSocket",
            "direction": "inbound synthetic loop",
            "route": "Lightsail>Cloudflare HTTPS>Xray WebSocket",
            "status": "verified" if websocket.ok else "failed",
            "evidence": "synthetic_probe",
            "required": True,
            "fresh_for_seconds": self._fresh_for_seconds,
            "reason": _safe_reason(websocket.reason),
            "latency_ms": _safe_latency(websocket.latency_ms),
        }
        websocket_status = _safe_status(websocket.status_code)
        if websocket_status is not None:
            websocket_details["http_status"] = websocket_status
        websocket_health = HealthObservation(
            observed_at,
            "path_cloudflare_xray",
            HealthState.HEALTHY if websocket.ok else HealthState.UNAVAILABLE,
            "public WebSocket upgrade returned HTTP 101"
            if websocket.ok
            else "public WebSocket upgrade check failed",
            websocket_details,
        )

        if self._warp_enabled:
            warp = self._warp_prober(self._warp_proxy_server, self._timeout_seconds)
            warp_details: dict[str, str | int | bool | None] = {
                "name": "VPN application egress",
                "direction": "outbound synthetic",
                "route": "Xray local proxy>WARP>Cloudflare trace",
                "status": "verified" if warp.ok else "failed",
                "evidence": "synthetic_probe",
                "required": True,
                "fresh_for_seconds": self._fresh_for_seconds,
                "reason": _safe_reason(warp.reason),
                "latency_ms": _safe_latency(warp.latency_ms),
                "trace_marker": bool(warp.marker_observed),
            }
            warp_status = _safe_status(warp.status_code)
            if warp_status is not None:
                warp_details["http_status"] = warp_status
            warp_health = HealthObservation(
                observed_at,
                "path_xray_egress",
                HealthState.HEALTHY if warp.ok else HealthState.UNAVAILABLE,
                "WARP trace marker observed"
                if warp.ok
                else "WARP trace marker check failed",
                warp_details,
            )
        else:
            warp_health = HealthObservation(
                observed_at,
                "path_xray_egress",
                HealthState.DISABLED,
                "WARP synthetic probe disabled",
                {
                    "name": "VPN application egress",
                    "direction": "outbound synthetic",
                    "route": "Xray local proxy>WARP>Cloudflare trace",
                    "status": "disabled",
                    "evidence": "synthetic_probe",
                    "required": False,
                    "fresh_for_seconds": self._fresh_for_seconds,
                },
            )
        return dns_health, websocket_health, warp_health
