"""
TimeCodeSecurity (TCS) Pinned-IP HTTPS Webhook Client.

Defines:
- DeliveryStatus: 16 discrete delivery outcome classifications.
- WebhookAuthConfig: Configuration-only secret token model.
- PinnedIPHTTPSConnection: Custom HTTPSConnection preventing DNS rebinding
  by connecting directly to validated IP while preserving TLS SNI.
- WebhookClient: Outbound delivery transport enforcing strict TLS,
  10.0s monotonic deadline checks, bounded retries, and error sanitization.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import logging
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ssrf_guard import DNSResolutionError, SSRFGuard, SSRFValidationError, SSRFValidationResult

logger = logging.getLogger("tcs.webhook_client")

MAX_ERROR_MESSAGE_LENGTH = 512
DEFAULT_RETRY_BACKOFF_SECONDS: float = 1.0
MAX_DELIVERY_ATTEMPTS: int = 2


class DeliveryStatus(str, Enum):
    """Refined 16-state delivery outcome classification."""
    SUCCESS = "SUCCESS"
    SSRF_BLOCKED = "SSRF_BLOCKED"
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    READ_TIMEOUT = "READ_TIMEOUT"
    TLS_ERROR = "TLS_ERROR"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    HTTP_CLIENT_ERROR = "HTTP_CLIENT_ERROR"
    HTTP_RATE_LIMITED = "HTTP_RATE_LIMITED"
    HTTP_SERVER_ERROR = "HTTP_SERVER_ERROR"
    REDIRECT_BLOCKED = "REDIRECT_BLOCKED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    QUEUE_OVERFLOW = "QUEUE_OVERFLOW"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    SHUTDOWN_ABORTED = "SHUTDOWN_ABORTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


@dataclass(frozen=True)
class WebhookAuthConfig:
    """
    Configuration-only authentication credentials.
    Strict invariant: secret_token MUST NEVER appear in SecurityDomainEvent,
    NotificationIntent, payload bodies, DeliveryResult, logs, or error messages.
    """
    secret_token: Optional[str] = None


@dataclass(frozen=True)
class ClientExecutionResult:
    """Internal delivery outcome returned by WebhookClient."""
    success: bool
    status: DeliveryStatus
    status_code: Optional[int]
    error_message: Optional[str]
    duration_ms: float
    attempts: int
    target_ip: Optional[str] = None


class PinnedIPHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPSConnection that binds directly to a pre-validated IP address,
    preventing DNS rebinding (TOCTOU) attacks while retaining the original
    hostname for TLS SNI and X.509 certificate verification.
    """

    def __init__(
        self,
        target_ip: str,
        hostname: str,
        port: int = 443,
        timeout: float = 3.0,
        ssl_context: Optional[ssl.SSLContext] = None,
        socket_factory: Optional[Callable[..., socket.socket]] = None,
    ) -> None:
        super().__init__(host=hostname, port=port, timeout=timeout)
        self.target_ip = target_ip
        self.original_hostname = hostname

        if ssl_context is None:
            ctx = ssl.create_default_context()
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            self.ssl_context = ctx
        else:
            # Enforce TLS security invariants: NEVER CERT_NONE, NEVER check_hostname=False
            if ssl_context.verify_mode == ssl.CERT_NONE:
                raise ValueError("Insecure TLS configuration: CERT_NONE is strictly forbidden.")
            if not ssl_context.check_hostname:
                raise ValueError("Insecure TLS configuration: check_hostname=False is strictly forbidden.")
            self.ssl_context = ssl_context

        self.socket_factory = socket_factory or socket.create_connection

    def connect(self) -> None:
        """
        Connects TCP directly to target_ip without secondary DNS query,
        then performs TLS handshake validating original_hostname.
        """
        raw_sock = self.socket_factory(
            (self.target_ip, self.port),
            timeout=self.timeout
        )
        self.sock = self.ssl_context.wrap_socket(
            raw_sock,
            server_hostname=self.original_hostname
        )


def compute_webhook_signature(secret_token: str, payload_bytes: bytes) -> str:
    """
    Computes HMAC-SHA256 signature over the EXACT transmitted UTF-8 payload bytes.
    """
    return hmac.new(
        secret_token.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()


class WebhookClient:
    """
    Hardened outbound HTTP client for webhook delivery.
    Enforces 10.0s monotonic deadline checks across all deadline-aware phases,
    SSRF validation, pinned IP TLS, redirect blocking, and retry policies.
    """

    def __init__(
        self,
        ssrf_guard: Optional[SSRFGuard] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], None] = time.sleep,
        socket_factory: Optional[Callable[..., socket.socket]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        http_connection_factory: Optional[Callable[..., http.client.HTTPSConnection]] = None,
    ) -> None:
        self._ssrf_guard = ssrf_guard or SSRFGuard()
        self._clock = clock
        self._sleep_fn = sleep_fn
        self._socket_factory = socket_factory
        self._ssl_context = ssl_context
        self._http_connection_factory = http_connection_factory

    def send(
        self,
        url: str,
        payload_bytes: bytes,
        auth_config: Optional[WebhookAuthConfig] = None,
        idempotency_key: str = "",
    ) -> ClientExecutionResult:
        """
        Executes outbound HTTPS delivery adhering to all Phase 15C security invariants.
        Enforces monotonic deadline, pinned IP connection, strict TLS, and bounded retries.
        """
        start_time = self._clock()
        overall_deadline = start_time + 10.0

        def remaining_deadline() -> float:
            rem = overall_deadline - self._clock()
            return rem

        # 1. Monotonic Deadline Check: before DNS
        if remaining_deadline() <= 0:
            return ClientExecutionResult(
                success=False,
                status=DeliveryStatus.CONNECTION_TIMEOUT,
                status_code=None,
                error_message="overall deadline exceeded before DNS resolution",
                duration_ms=0.0,
                attempts=0,
            )

        # 2. SSRF Validation & Deterministic IP Pinning
        try:
            ssrf_res = self._ssrf_guard.validate_url(url)
        except DNSResolutionError as exc:
            return ClientExecutionResult(
                success=False,
                status=DeliveryStatus.DNS_RESOLUTION_FAILED,
                status_code=None,
                error_message=str(exc)[:MAX_ERROR_MESSAGE_LENGTH],
                duration_ms=(self._clock() - start_time) * 1000.0,
                attempts=0,
            )
        except SSRFValidationError as exc:
            return ClientExecutionResult(
                success=False,
                status=DeliveryStatus.SSRF_BLOCKED,
                status_code=None,
                error_message=str(exc)[:MAX_ERROR_MESSAGE_LENGTH],
                duration_ms=(self._clock() - start_time) * 1000.0,
                attempts=0,
            )
        except Exception as exc:
            return ClientExecutionResult(
                success=False,
                status=DeliveryStatus.SSRF_BLOCKED,
                status_code=None,
                error_message=f"SSRF validation exception: {exc}"[:MAX_ERROR_MESSAGE_LENGTH],
                duration_ms=(self._clock() - start_time) * 1000.0,
                attempts=0,
            )

        target_ip = ssrf_res.target_ip
        hostname = ssrf_res.hostname
        port = ssrf_res.port

        # 3. Monotonic Deadline Check: after DNS
        if remaining_deadline() <= 0:
            return ClientExecutionResult(
                success=False,
                status=DeliveryStatus.CONNECTION_TIMEOUT,
                status_code=None,
                error_message="overall deadline exceeded after DNS resolution",
                duration_ms=(self._clock() - start_time) * 1000.0,
                attempts=0,
                target_ip=target_ip,
            )

        # Prepare request URI and headers
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        headers: Dict[str, str] = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "TCS-Webhook-Delivery/1.0",
            "Content-Length": str(len(payload_bytes)),
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        if auth_config and auth_config.secret_token:
            sig = compute_webhook_signature(auth_config.secret_token, payload_bytes)
            headers["X-TCS-Signature"] = f"sha256={sig}"

        attempts = 0
        max_attempts = 2

        while attempts < max_attempts:
            attempts += 1

            # 4. Monotonic Deadline Check: before connect
            rem = remaining_deadline()
            if rem <= 0:
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.CONNECTION_TIMEOUT,
                    status_code=None,
                    error_message="overall deadline exceeded before connect",
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            connect_timeout = min(3.0, rem)

            conn: Optional[Union[PinnedIPHTTPSConnection, http.client.HTTPSConnection]] = None
            try:
                if self._http_connection_factory is not None:
                    conn = self._http_connection_factory(
                        target_ip=target_ip,
                        hostname=hostname,
                        port=port,
                        timeout=connect_timeout,
                    )
                else:
                    conn = PinnedIPHTTPSConnection(
                        target_ip=target_ip,
                        hostname=hostname,
                        port=port,
                        timeout=connect_timeout,
                        ssl_context=self._ssl_context,
                        socket_factory=self._socket_factory,
                    )

                # Connect phase
                conn.connect()

                # 5. Monotonic Deadline Check: before read
                rem = remaining_deadline()
                if rem <= 0:
                    return ClientExecutionResult(
                        success=False,
                        status=DeliveryStatus.READ_TIMEOUT,
                        status_code=None,
                        error_message="overall deadline exceeded before read",
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                read_timeout = min(5.0, rem)
                conn.sock.settimeout(read_timeout)

                # Send request
                conn.request("POST", path, body=payload_bytes, headers=headers)
                resp = conn.getresponse()
                status_code = resp.status

                # Read response safely (bounded, discard raw content)
                resp.read(1024)

                # 6. Evaluate HTTP Response
                # Redirects: Strictly disabled
                if status_code in (301, 302, 303, 307, 308):
                    return ClientExecutionResult(
                        success=False,
                        status=DeliveryStatus.REDIRECT_BLOCKED,
                        status_code=status_code,
                        error_message="HTTP redirect blocked",
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                # Success: 200-299
                if 200 <= status_code < 300:
                    return ClientExecutionResult(
                        success=True,
                        status=DeliveryStatus.SUCCESS,
                        status_code=status_code,
                        error_message=None,
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                # Rate Limited: 429
                if status_code == 429:
                    retry_after_hdr = resp.getheader("Retry-After")
                    should_retry = False
                    retry_delay = 0.0

                    if retry_after_hdr:
                        try:
                            val = int(retry_after_hdr.strip())
                            if 0 < val <= 2:
                                should_retry = True
                                retry_delay = float(val)
                        except (ValueError, TypeError):
                            should_retry = False

                    if should_retry and attempts < max_attempts:
                        # Check deadline before retry sleep
                        if remaining_deadline() > (retry_delay + 0.5):
                            self._sleep_fn(retry_delay)
                            continue

                    return ClientExecutionResult(
                        success=False,
                        status=DeliveryStatus.HTTP_RATE_LIMITED,
                        status_code=status_code,
                        error_message="HTTP 429",
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                # Client Errors: 400-499 (except 429) -> Zero retries
                if 400 <= status_code < 500:
                    return ClientExecutionResult(
                        success=False,
                        status=DeliveryStatus.HTTP_CLIENT_ERROR,
                        status_code=status_code,
                        error_message=f"HTTP {status_code}",
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                # Server Errors: 500-599
                if 500 <= status_code < 600:
                    if attempts < max_attempts:
                        backoff = DEFAULT_RETRY_BACKOFF_SECONDS
                        if remaining_deadline() > backoff:
                            self._sleep_fn(backoff)
                            continue

                    return ClientExecutionResult(
                        success=False,
                        status=DeliveryStatus.HTTP_SERVER_ERROR,
                        status_code=status_code,
                        error_message=f"HTTP {status_code}",
                        duration_ms=(self._clock() - start_time) * 1000.0,
                        attempts=attempts,
                        target_ip=target_ip,
                    )

                # Unexpected status code
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.HTTP_SERVER_ERROR,
                    status_code=status_code,
                    error_message=f"HTTP {status_code}",
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            except (socket.timeout, TimeoutError):
                if attempts < max_attempts and remaining_deadline() > DEFAULT_RETRY_BACKOFF_SECONDS:
                    self._sleep_fn(DEFAULT_RETRY_BACKOFF_SECONDS)
                    continue
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.CONNECTION_TIMEOUT,
                    status_code=None,
                    error_message="connect timeout",
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            except ssl.SSLError:
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.TLS_ERROR,
                    status_code=None,
                    error_message="TLS verification failed",
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            except ConnectionRefusedError:
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.CONNECTION_REFUSED,
                    status_code=None,
                    error_message="connection refused",
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            except Exception as exc:
                return ClientExecutionResult(
                    success=False,
                    status=DeliveryStatus.INTERNAL_ERROR,
                    status_code=None,
                    error_message=f"Delivery error: {exc}"[:MAX_ERROR_MESSAGE_LENGTH],
                    duration_ms=(self._clock() - start_time) * 1000.0,
                    attempts=attempts,
                    target_ip=target_ip,
                )

            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass

        # If exhausted attempts
        return ClientExecutionResult(
            success=False,
            status=DeliveryStatus.HTTP_SERVER_ERROR,
            status_code=None,
            error_message="Maximum delivery attempts exceeded",
            duration_ms=(self._clock() - start_time) * 1000.0,
            attempts=attempts,
            target_ip=target_ip,
        )
