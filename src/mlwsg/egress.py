"""Isolated-lab HTTP egress: validate every DNS answer and pin the socket for each hop."""

import asyncio
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urljoin, urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

IPAddress = IPv4Address | IPv6Address
Resolve = Callable[[str, int], Awaitable[Sequence[str]]]

# Only these exact host/address pairs represent public services in the isolated lab.
# The default guard cannot reach arbitrary global Internet addresses.
LAB_ADDRESSES: Mapping[str, frozenset[IPAddress]] = {
    "public.lab": frozenset({ip_address("10.20.0.20")}),
    "redirect.attacker.lab": frozenset({ip_address("10.20.0.30")}),
}


@dataclass(frozen=True, slots=True)
class Fetched:
    status: int
    body: bytes
    content_type: str


class Blocked(Exception):
    """The requested URL, a DNS answer or a redirect violates egress policy."""


class FetchError(Exception):
    """An allowed destination could not be fetched."""


async def _system_resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    answers = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [answer[4][0] for answer in answers]


class _PinnedResolver(AbstractResolver):
    """Give aiohttp the *validated* address, never a second DNS lookup."""

    def __init__(self, host: str, address: IPAddress) -> None:
        self.host = host
        self.address = address

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict]:
        if host.lower() != self.host:
            raise Blocked("host changed between validation and connection")
        return [
            {
                "hostname": host,
                "host": str(self.address),
                "port": port,
                "family": socket.AF_INET if self.address.version == 4 else socket.AF_INET6,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
        ]

    async def close(self) -> None:
        pass


class _PinnedConnector(aiohttp.TCPConnector):
    """Check the peer while the connection still owns its transport."""

    def __init__(self, host: str, address: IPAddress) -> None:
        super().__init__(
            resolver=_PinnedResolver(host, address), use_dns_cache=False, force_close=True
        )
        self._expected_address = address

    async def _create_connection(self, req, traces, timeout):
        protocol = await super()._create_connection(req, traces, timeout)
        transport = protocol.transport
        peer = transport.get_extra_info("peername") if transport else None
        if not peer or ip_address(peer[0]) != self._expected_address:
            protocol.close()
            raise Blocked("connected socket differs from validated DNS address")
        return protocol


class Guard:
    """Fetch HTTP URLs only from known public lab fixtures.

    ``resolver`` and ``lab_addresses`` are privileged test seams for local socket tests;
    the application uses the fixed default fixture addresses. A single resolution is
    validated in full before each connection, then pinned in aiohttp's connector.
    """

    def __init__(
        self,
        *,
        resolver: Resolve | None = None,
        lab_addresses: Mapping[str, Sequence[str]] | None = None,
        timeout: float = 5.0,
        max_body: int = 1_048_576,
        max_redirects: int = 5,
    ) -> None:
        if timeout <= 0 or max_body <= 0 or max_redirects < 0:
            raise ValueError("timeout and max_body must be positive; max_redirects nonnegative")
        self._resolve = resolver or _system_resolve
        self._lab_addresses = (
            {host: frozenset(ip_address(ip) for ip in ips) for host, ips in lab_addresses.items()}
            if lab_addresses is not None
            else LAB_ADDRESSES
        )
        if not self._lab_addresses.keys() <= LAB_ADDRESSES.keys():
            raise ValueError("only named public lab fixtures may be allowed")
        self.timeout = timeout
        self.max_body = max_body
        self.max_redirects = max_redirects

    def _target(self, url: str) -> tuple[str, int]:
        if (
            not isinstance(url, str)
            or not url
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in url)
        ):
            raise Blocked("malformed URL")
        if "\\" in url:
            raise Blocked("backslashes are ambiguous in HTTP URLs")
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
                raise Blocked("only absolute HTTP(S) URLs are allowed")
            if "@" in parsed.netloc or "%" in parsed.netloc:
                raise Blocked("encoded hosts and userinfo are not allowed")
            host = parsed.hostname.lower()
            if "%" in host or not host.isascii():
                raise Blocked("ambiguous hostname")
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            if not 1 <= port <= 65535:
                raise Blocked("invalid port")
        except ValueError as exc:
            raise Blocked("malformed URL") from exc
        return host, port

    async def _validated_address(self, host: str, port: int) -> IPAddress:
        if host not in self._lab_addresses:
            raise Blocked("destination is outside the public lab allowlist")
        try:
            # A single resolution is used for validation and socket pinning.
            answers = await self._resolve(host, port)
            if not answers:
                raise Blocked("DNS returned no addresses")
            addresses = [ip_address(answer) for answer in answers]
        except (OSError, ValueError) as exc:
            raise Blocked("DNS returned an invalid address") from exc
        for address in addresses:
            if address.version == 6 and address.ipv4_mapped:
                raise Blocked("IPv4-mapped IPv6 address")
            if address not in self._lab_addresses[host]:
                raise Blocked("DNS answer is not the public fixture address")
        return addresses[0]

    async def _fetch(self, url: str) -> Fetched | str:
        host, port = self._target(url)
        address = await self._validated_address(host, port)
        connector = _PinnedConnector(host, address)
        async with (
            aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(),
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as session,
            session.get(url, allow_redirects=False) as response,
        ):
            if response.status in (301, 302, 303, 307, 308) and "Location" in response.headers:
                return urljoin(url, response.headers["Location"])
            body = await response.content.read(self.max_body + 1)
            if len(body) > self.max_body:
                raise Blocked("response body exceeds lab limit")
            return Fetched(response.status, body, response.headers.get("Content-Type", ""))

    async def fetch(self, url: str) -> Fetched:
        """Fetch with one resolution and one policy decision per redirect hop."""
        try:
            async with asyncio.timeout(self.timeout):
                current = url
                for hop in range(self.max_redirects + 1):
                    result = await self._fetch(current)
                    if isinstance(result, Fetched):
                        return result
                    if hop == self.max_redirects:
                        raise Blocked("redirect limit exceeded")
                    current = result
        except (aiohttp.ClientError, OSError) as exc:
            raise FetchError("allowed lab service could not be fetched") from exc
        except TimeoutError as exc:
            raise FetchError("fetch timed out") from exc
        raise AssertionError("unreachable")
