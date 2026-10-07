"""Shared buffered upstream client with selectable, reviewable HTTP engines.

The request body is forwarded as bytes. Neither engine follows redirects or
retains upstream cookies across users. The aiohttp session is created lazily in
the running ASGI event loop, shared across requests, and closed on shutdown.
"""
import json
import os
from http.cookiejar import CookieJar, DefaultCookiePolicy
from dataclasses import dataclass
import httpx


class _NoStoredCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):
        return False


@dataclass
class BufferedResponse:
    status_code: int
    content: bytes
    headers: object

    def json(self):
        return json.loads(self.content)

    @property
    def text(self):
        return self.content.decode('utf-8', errors='replace')


class UpstreamClient:
    def __init__(self, timeout):
        self.timeout = timeout
        self.backend = os.getenv('GUARD_HTTP_TRANSPORT', 'httpx').lower()
        if self.backend not in {'httpx', 'aiohttp'}:
            raise ValueError('GUARD_HTTP_TRANSPORT must be httpx or aiohttp')
        self._session = None
        self._httpx = None
        if self.backend == 'aiohttp':
            import aiohttp
            self._aiohttp = aiohttp
        else:
            self._httpx = httpx.AsyncClient(timeout=timeout, trust_env=False,
                cookies=CookieJar(policy=_NoStoredCookies()),
                limits=httpx.Limits(max_connections=256,
                                   max_keepalive_connections=128, keepalive_expiry=60))

    async def request(self, method, url, *, headers=None, content=None, params=None, timeout=None):
        if self.backend == 'httpx':
            # Existing engine retained for a like-for-like performance baseline.
            return await self._httpx.request(method, url, headers=headers, content=content,
                                            params=params, timeout=timeout or self.timeout)
        aiohttp = self._aiohttp
        if self._session is None:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=256, keepalive_timeout=60),
                cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
                skip_auto_headers={'Content-Type'},
                timeout=aiohttp.ClientTimeout(total=self.timeout))
        async with self._session.request(method, url, headers=headers, data=content,
                params=params, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout or self.timeout)) as response:
            return BufferedResponse(response.status, await response.read(), response.headers)

    async def get(self, url, **kwargs):
        return await self.request('GET', url, **kwargs)

    async def aclose(self):
        if self._session is not None:
            await self._session.close()
        if self._httpx is not None:
            await self._httpx.aclose()
