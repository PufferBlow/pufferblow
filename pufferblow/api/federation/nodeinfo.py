"""Asking another instance what it is (nodeinfo), without letting it point us at our own network.

A peer's host name comes from outside, so the address it resolves to is checked before anything is sent:
private, loopback, link-local and other non-public addresses are refused (set
``PUFFERBLOW_ALLOW_PRIVATE_FEDERATION=1`` for a lab where instances really do live on a private network).
Redirects are not followed, the answer is size-limited, and only JSON is read.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
from urllib.parse import urlsplit, urlunsplit
from typing import Any, Awaitable, Callable

import httpx

MAX_BYTES = 262_144
TIMEOUT_SECONDS = 4.0
USER_AGENT = "Pufferblow-nodeinfo/1.0"

Resolver = Callable[[str, int], list[tuple]]


class UnsafeHost(Exception):
    """The host resolves to an address this instance must not send requests to."""


def private_federation_allowed() -> bool:
    return os.environ.get("PUFFERBLOW_ALLOW_PRIVATE_FEDERATION", "").strip().lower() in {"1", "true", "yes"}


def assert_public(host: str, resolve: Resolver = socket.getaddrinfo, allow_private: bool | None = None) -> None:
    """Raise :class:`UnsafeHost` unless every address ``host`` resolves to is a public one."""
    if allow_private is None:
        allow_private = private_federation_allowed()
    name, _, port = host.partition(":")
    try:
        infos = resolve(name, int(port) if port else 443)
    except OSError as exc:
        raise UnsafeHost(f"{name} does not resolve") from exc
    if not infos:
        raise UnsafeHost(f"{name} does not resolve")
    if allow_private:
        return
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if not address.is_global:
            raise UnsafeHost(f"{name} resolves to a non-public address")


def public_addresses(host: str, port: int, resolve: Resolver = socket.getaddrinfo, allow_private: bool | None = None) -> list[str]:
    """The addresses ``host`` resolves to, each checked: all of them must be public (unless a lab says otherwise)."""
    if allow_private is None:
        allow_private = private_federation_allowed()
    try:
        infos = resolve(host, port)
    except OSError as exc:
        raise UnsafeHost(f"{host} does not resolve") from exc
    addresses = [info[4][0].split("%")[0] for info in infos]
    if not addresses:
        raise UnsafeHost(f"{host} does not resolve")
    if not allow_private:
        for address in addresses:
            if not ipaddress.ip_address(address).is_global:
                raise UnsafeHost(f"{host} resolves to a non-public address")
    return addresses


async def fetch_public_json(url: str, *, resolve: Resolver = socket.getaddrinfo, allow_private: bool | None = None, accept: str = "application/json") -> Any:
    """GET a JSON document from a stranger's address without being able to be pointed anywhere else.

    The name is resolved once, every address is checked, and the connection goes to the address that was checked (so
    the name cannot resolve somewhere else a moment later). Redirects are not followed, the answer is size-limited,
    and plain ``http`` is only for a lab.
    """
    if allow_private is None:
        allow_private = private_federation_allowed()
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or (parts.scheme == "http" and not allow_private):
        raise UnsafeHost("only https addresses are fetched")
    if parts.username or parts.password or not parts.hostname:
        raise UnsafeHost("the address is not a plain host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    loop = asyncio.get_running_loop()
    addresses = await loop.run_in_executor(None, lambda: public_addresses(parts.hostname, port, resolve, allow_private))
    ip = addresses[0]
    pinned_host = f"[{ip}]" if ":" in ip else ip
    pinned = urlunsplit((parts.scheme, f"{pinned_host}:{port}", parts.path or "/", parts.query, ""))
    headers = {"Accept": accept, "User-Agent": USER_AGENT, "Host": parts.netloc}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        async with client.stream("GET", pinned, headers=headers, extensions={"sni_hostname": parts.hostname}) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError("The answer is too large.")
                chunks.append(chunk)
    return json.loads(b"".join(chunks))


Fetcher = Callable[[str], Awaitable[Any]]


async def default_fetch(url: str) -> Any:
    """GET a URL and parse its JSON: no redirects, a hard size cap, a short timeout."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        async with client.stream("GET", url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError("The answer is too large.")
                chunks.append(chunk)
    return json.loads(b"".join(chunks))


def _link(links: Any, *rels: str) -> str | None:
    for link in links if isinstance(links, list) else []:
        if isinstance(link, dict) and link.get("rel") in rels and isinstance(link.get("href"), str):
            return link["href"]
    return None


async def fetch_peer_info(
    host: str,
    *,
    fetch: Fetcher = default_fetch,
    resolve: Resolver = socket.getaddrinfo,
    allow_private: bool | None = None,
) -> dict | None:
    """What ``host`` says about itself: ``{software, version, users}``, or None if it says nothing usable.

    Never raises for a peer that is down, slow, odd or hostile; the caller just gets nothing. A refused
    address is the exception: that raises :class:`UnsafeHost` so the caller can say why.
    """
    assert_public(host, resolve, allow_private)
    scheme = "http" if (allow_private if allow_private is not None else private_federation_allowed()) and host.split(":")[0] in {"localhost", "127.0.0.1"} else "https"
    try:
        index = await fetch(f"{scheme}://{host}/.well-known/nodeinfo")
        href = _link(index.get("links") if isinstance(index, dict) else None, "http://nodeinfo.diaspora.software/ns/schema/2.0", "http://nodeinfo.diaspora.software/ns/schema/2.1")
        # The index points at a document; it must stay on the same host, or it is an invitation to go elsewhere.
        if href is None or not href.startswith(f"{scheme}://{host}/"):
            return None
        document = await fetch(href)
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    software = document.get("software") if isinstance(document.get("software"), dict) else {}
    users = (document.get("usage") or {}).get("users") if isinstance(document.get("usage"), dict) else None
    total = users.get("total") if isinstance(users, dict) else None
    info = {
        "software": software.get("name") if isinstance(software.get("name"), str) else None,
        "version": software.get("version") if isinstance(software.get("version"), str) else None,
        "users": total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None,
    }
    return info if any(v is not None for v in info.values()) else None
