"""
TimeCodeSecurity (TCS) Server-Side Request Forgery (SSRF) Guard.

Defines the 9-stage validation gate for outbound webhook URLs.
Strictly standard library only (socket, ipaddress, urllib.parse).

Invariants:
- HTTPS ONLY (rejects http, ftp, and all non-https schemes).
- Rejects userinfo / embedded credentials (@).
- Port must be in range 1-65535 (default 443).
- Validates hostname syntax (ASCII/IDNA, zero whitespace/control characters).
- Resolves ALL A and AAAA records. If 0 records: DNS_RESOLUTION_FAILED.
- Inspects EVERY resolved IP address: if ANY is forbidden, the ENTIRE hostname is rejected.
- Comprehensive IPv4 and IPv6 blocklist (loopback, RFC 1918, link-local, cloud metadata,
  CGNAT 100.64.0.0/10, documentation, multicast, broadcast).
- IPv4-mapped IPv6 addresses are unwrapped and tested against IPv4 rules.
- Deterministic IP selection: IPv4 first (sorted numerically), then IPv6 (sorted numerically).
- Zero nondeterministic or random target selection.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Sequence, Set, Tuple, Union


class SSRFValidationError(Exception):
    """Raised when an outbound URL or IP fails SSRF validation rules."""
    def __init__(self, message: str, status_code: Optional[str] = "SSRF_BLOCKED") -> None:
        super().__init__(message)
        self.status_code = status_code


class DNSResolutionError(SSRFValidationError):
    """Raised when DNS resolution yields zero valid records or gaierror."""
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code="DNS_RESOLUTION_FAILED")


# ---------------------------------------------------------------------------
# Strict Subnet Blocklists
# ---------------------------------------------------------------------------

IPV4_BLOCKED_NETWORKS: Tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),         # Current Network / Broadcast
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT (RFC 6598) - blocked by default
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved / Future Use
    ipaddress.ip_network("255.255.255.255/32"),# Limited Broadcast
)

IPV6_BLOCKED_NETWORKS: Tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("fc00::/7"),          # Unique Local Addresses (ULA)
    ipaddress.ip_network("fe80::/10"),         # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),          # Multicast
    ipaddress.ip_network("::ffff:0:0/96"),     # IPv4-mapped IPv6
    ipaddress.ip_network("::/96"),             # IPv4-compatible (deprecated)
    ipaddress.ip_network("2001:db8::/32"),     # Documentation
    ipaddress.ip_network("100::/64"),          # Discard-Only Prefix (RFC 6666)
)


@dataclass(frozen=True)
class SSRFValidationResult:
    """Immutable result of successful SSRF validation."""
    target_ip: str
    hostname: str
    port: int
    canonical_endpoint: str
    all_resolved_ips: Tuple[str, ...]


def is_ip_blocked(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """
    Checks whether an IP address belongs to any blocked subnet.
    Unwraps IPv4-mapped IPv6 addresses to test against IPv4 rules.
    """
    # Check if IPv6 is IPv4-mapped (e.g. ::ffff:192.168.1.1)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            unwrapped_v4 = ip.ipv4_mapped
            for net in IPV4_BLOCKED_NETWORKS:
                if unwrapped_v4 in net:
                    return True, f"IPv4-mapped IPv6 {ip} unwrapped to {unwrapped_v4} which is in blocked subnet {net}"
            if unwrapped_v4.is_loopback or unwrapped_v4.is_private or unwrapped_v4.is_link_local:
                return True, f"IPv4-mapped IPv6 {ip} unwrapped to private/loopback {unwrapped_v4}"

        for net in IPV6_BLOCKED_NETWORKS:
            if ip in net:
                return True, f"IPv6 address {ip} is in blocked subnet {net}"
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return True, f"IPv6 address {ip} is private/loopback/unspecified"

    elif isinstance(ip, ipaddress.IPv4Address):
        for net in IPV4_BLOCKED_NETWORKS:
            if ip in net:
                return True, f"IPv4 address {ip} is in blocked subnet {net}"
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True, f"IPv4 address {ip} is private/loopback/unspecified"

    return False, ""


def select_deterministic_ip(
    validated_ips: Sequence[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]
) -> str:
    """
    Deterministically selects an IP address from a sequence of validated addresses.
    Ordering rule:
    1. IPv4 addresses first (sorted by numerical integer value).
    2. IPv6 addresses next (sorted by numerical integer value).
    3. Select the first address.
    """
    if not validated_ips:
        raise ValueError("Cannot select deterministic IP from empty sequence.")

    sorted_ips = sorted(
        validated_ips,
        key=lambda ip: (0 if ip.version == 4 else 1, int(ip))
    )
    return str(sorted_ips[0])


class SSRFGuard:
    """
    SSRF validation gatekeeper.
    Performs full syntactic, DNS, and IP inspection before network connection.
    Supports dependency injection for DNS resolution to enable 100% offline unit testing.
    """

    def __init__(
        self,
        dns_resolver: Optional[Callable[[str, int], List[Tuple[Any, ...]]]] = None
    ) -> None:
        self._dns_resolver = dns_resolver or socket.getaddrinfo

    def validate_url(self, url: str) -> SSRFValidationResult:
        """
        Executes the 9-stage SSRF validation pipeline against the provided URL.
        Returns SSRFValidationResult with the pinned target_ip.
        Raises SSRFValidationError or DNSResolutionError on failure.
        """
        if not url or not isinstance(url, str):
            raise SSRFValidationError("Webhook URL must be a non-empty string.")

        # Stage 1: URL Parsing & Scheme Validation (HTTPS ONLY)
        try:
            parsed = urllib.parse.urlsplit(url.strip())
        except Exception as exc:
            raise SSRFValidationError(f"Malformed URL: {exc}")

        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise SSRFValidationError(
                f"Invalid URL scheme '{scheme}'. Webhooks strictly require HTTPS."
            )

        # Stage 2: Userinfo Rejection (no embedded credentials)
        if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
            raise SSRFValidationError(
                "Embedded user credentials (user:pass@) are strictly forbidden in webhook URLs."
            )

        # Stage 3: Port Validation
        port = parsed.port
        if port is None:
            port = 443
        else:
            if not (1 <= port <= 65535):
                raise SSRFValidationError(f"Invalid port number: {port}. Must be 1-65535.")

        # Stage 4: Hostname Validation
        raw_hostname = parsed.hostname
        if not raw_hostname:
            raise SSRFValidationError("Missing hostname in webhook URL.")

        if any(c.isspace() or ord(c) < 32 for c in raw_hostname):
            raise SSRFValidationError("Hostname contains whitespace or control characters.")

        # Normalize hostname (lowercase, strip single trailing dot)
        hostname = raw_hostname.lower()
        if hostname.endswith("."):
            hostname = hostname[:-1]

        if not hostname:
            raise SSRFValidationError("Invalid empty hostname after trailing dot removal.")

        try:
            # Validate IDNA encoding
            hostname.encode("idna")
        except Exception as exc:
            raise SSRFValidationError(f"Invalid IDNA hostname: {exc}")

        # Stage 5: DNS Resolution (ALL A and AAAA records)
        # Check if hostname is already a raw IP literal
        resolved_records: List[Tuple[Any, ...]] = []
        is_ip_literal = False
        try:
            ip_literal_obj = ipaddress.ip_address(hostname)
            is_ip_literal = True
            family = socket.AF_INET if ip_literal_obj.version == 4 else socket.AF_INET6
            resolved_records = [(family, socket.SOCK_STREAM, 6, "", (str(ip_literal_obj), port))]
        except ValueError:
            is_ip_literal = False

        if not is_ip_literal:
            try:
                resolved_records = self._dns_resolver(hostname, port)
            except socket.gaierror as exc:
                raise DNSResolutionError(f"DNS resolution failed for hostname '{hostname}': {exc}")
            except Exception as exc:
                raise DNSResolutionError(f"DNS resolver error for hostname '{hostname}': {exc}")

        if not resolved_records:
            raise DNSResolutionError(f"Zero DNS records resolved for hostname '{hostname}'.")

        # Stage 6 & 7: Exhaustive IP Inspection (every single IP checked)
        parsed_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
        seen_ip_strs: Set[str] = set()

        for record in resolved_records:
            sockaddr = record[4]
            ip_str = sockaddr[0]
            if ip_str in seen_ip_strs:
                continue
            seen_ip_strs.add(ip_str)

            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError as exc:
                raise SSRFValidationError(f"Unparseable IP address '{ip_str}' resolved: {exc}")

            # Check if this IP is forbidden
            blocked, reason = is_ip_blocked(ip_obj)
            if blocked:
                raise SSRFValidationError(
                    f"SSRF violation: Hostname '{hostname}' resolves to forbidden address {ip_str}. Reason: {reason}"
                )

            parsed_ips.append(ip_obj)

        if not parsed_ips:
            raise DNSResolutionError(f"No valid IP addresses extracted from DNS for '{hostname}'.")

        # Stage 8: Deterministic Target-IP Selection
        target_ip = select_deterministic_ip(parsed_ips)

        # Stage 9: Build Canonical Endpoint Representation
        # Preserve path and query exactly
        port_str = f":{port}" if port != 443 else ""
        canonical_endpoint = f"{scheme}://{hostname}{port_str}{parsed.path}"
        if parsed.query:
            canonical_endpoint += f"?{parsed.query}"

        return SSRFValidationResult(
            target_ip=target_ip,
            hostname=hostname,
            port=port,
            canonical_endpoint=canonical_endpoint,
            all_resolved_ips=tuple(str(ip) for ip in parsed_ips),
        )
