"""Remember, for the length of one request, what it has already read from the cache."""

from __future__ import annotations

from pufferblow.api.cache.memcache import begin_request_reads, end_request_reads


class RequestCacheMiddleware:
    """Pure ASGI middleware: HTTP requests get their own read memo (see ``api/cache/memcache.py``); sockets do not."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        token = begin_request_reads()
        try:
            await self.app(scope, receive, send)
        finally:
            end_request_reads(token)
