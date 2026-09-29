"""The crossing: asynchronous proxy testing engine.

Protocol auto-detection works as a race: for every proxy, SOCKS5, SOCKS4 and
HTTP CONNECT-style attempts are launched concurrently against a judge; the
first protocol to bring back an answer wins and becomes the detected type.
Dead proxies are cheap — a single TCP probe short-circuits the race before it
begins.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import aiohttp

from .judges import (
    HTTP_JUDGES,
    HTTPS_JUDGES,
    HEADER_JUDGES,
    IP_LEAK_HEADERS,
    PROXY_ID_HEADERS,
    SPEED_URL,
    extract_ip,
)
from .models import (
    DETECTION_CANDIDATES,
    Anonymity,
    Proxy,
    ProxyResult,
    Status,
)

try:
    from aiohttp_socks import ProxyConnector
except ImportError:  # pragma: no cover
    ProxyConnector = None  # type: ignore[assignment]

OnResult = Callable[[ProxyResult], None]


@dataclass
class EngineOptions:
    workers: int = 250
    timeout: float = 8.0
    tcp_timeout: float = 4.0
    schemes: tuple = DETECTION_CANDIDATES  # candidates when input has no scheme
    judge: Optional[str] = None            # custom judge URL (prepended)
    header_judge: Optional[str] = None     # custom header-echo URL (trusted, full taxonomy)
    speed_test: bool = False
    speed_kbytes: int = 1024
    speed_timeout: float = 25.0
    skip_anonymity: bool = False


@dataclass
class Attempt:
    ok: bool
    scheme: Optional[str] = None
    latency_ms: Optional[int] = None
    exit_ip: Optional[str] = None
    error: Optional[str] = None


class JudgeError(Exception):
    pass


class Engine:
    def __init__(self, opts: EngineOptions, real_ip: Optional[str] = None,
                 on_result: Optional[OnResult] = None):
        self.opts = opts
        self.real_ip = real_ip
        self.on_result = on_result
        self.results: list[ProxyResult] = []
        # a custom judge replaces the public pool — professionals bring their own
        self.http_judges = [opts.judge] if opts.judge else list(HTTP_JUDGES)
        self.header_judges = [opts.header_judge] if opts.header_judge else list(HEADER_JUDGES)
        self.trusted_header_judge = opts.header_judge is not None
        self._judge_cursor = 0

    # -- judge rotation -----------------------------------------------------

    def _next_judge(self, judges: list[str]) -> str:
        self._judge_cursor += 1
        return judges[self._judge_cursor % len(judges)]

    # -- public API ---------------------------------------------------------

    async def run(self, proxies: list[Proxy]) -> list[ProxyResult]:
        sem = asyncio.Semaphore(self.opts.workers)

        async def _worker(proxy: Proxy) -> None:
            async with sem:
                result = await self.check_one(proxy)
                self.results.append(result)
                if self.on_result:
                    self.on_result(result)

        await asyncio.gather(*(_worker(p) for p in proxies))
        return self.results

    async def check_one(self, proxy: Proxy) -> ProxyResult:
        result = ProxyResult(proxy=proxy)

        if not await self._tcp_reachable(proxy):
            result.error = "tcp unreachable / filtered"
            return result

        try:
            attempt = await asyncio.wait_for(
                self._race_detect(proxy), timeout=self.opts.timeout + 2.0
            )
        except asyncio.TimeoutError:
            attempt = Attempt(ok=False, error="detection timed out")

        if not attempt.ok:
            result.error = attempt.error or "all protocols failed"
            return result

        result.status = Status.ALIVE
        result.detected_scheme = attempt.scheme
        result.latency_ms = attempt.latency_ms
        result.exit_ip = attempt.exit_ip
        if self.real_ip and result.exit_ip == self.real_ip:
            result.anonymity = Anonymity.TRANSPARENT
            result.leaks = ["exit-ip-equals-client-ip"]

        if not self.opts.skip_anonymity and not result.leaks:
            await self._check_anonymity(proxy, attempt.scheme, result)

        result.https_capable = (
            attempt.scheme in ("socks5", "socks4")
            or proxy.scheme == "https"
            or await self._https_tunnel_ok(proxy, attempt.scheme)
        )

        if self.opts.speed_test and result.https_capable:
            await self._speed_test(proxy, attempt.scheme, result)

        result.compute_grade()
        return result

    # -- stage 1: TCP precheck ----------------------------------------------

    async def _tcp_reachable(self, proxy: Proxy) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=self.opts.tcp_timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    # -- stage 2: protocol race ---------------------------------------------

    async def _race_detect(self, proxy: Proxy) -> Attempt:
        if proxy.scheme == "https":
            candidates = ("http",)  # an "https proxy" is an HTTP proxy that tunnels TLS
        elif proxy.scheme:
            candidates = (proxy.scheme,)
        else:
            candidates = self.opts.schemes
        pending: set[asyncio.Task] = set()
        errors: list[str] = []
        for scheme in candidates:
            pending.add(asyncio.create_task(self._attempt(proxy, scheme)))
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                attempt = task.result()
                if attempt.ok:
                    for other in pending:
                        other.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    return attempt
                errors.append(attempt.error or f"{attempt.scheme} failed")
        return Attempt(ok=False, scheme=None, error=" | ".join(errors[-3:]))

    async def _attempt(self, proxy: Proxy, scheme: str) -> Attempt:
        judges = self.http_judges
        if proxy.scheme == "https" and scheme == "http":
            judges = ([self.opts.judge] if self.opts.judge else []) + list(HTTPS_JUDGES)
        url = self._next_judge(judges)
        start = asyncio.get_running_loop().time()
        try:
            _status, body = await self._fetch(proxy, scheme, url, self.opts.timeout)
            latency = int((asyncio.get_running_loop().time() - start) * 1000)
        except Exception as exc:
            return Attempt(ok=False, scheme=scheme, error=f"{scheme}: {short_error(exc)}")
        ip = extract_ip(body)
        if not ip:
            return Attempt(ok=False, scheme=scheme, error=f"{scheme}: judge gave no IP")
        return Attempt(ok=True, scheme=scheme, latency_ms=latency, exit_ip=ip)

    # -- stage 3: anonymity --------------------------------------------------

    async def _check_anonymity(self, proxy: Proxy, scheme: str, result: ProxyResult) -> None:
        try:
            _status, body = await self._fetch(
                proxy, scheme, self._next_judge(self.header_judges), self.opts.timeout
            )
            data = json.loads(body)
            raw = data.get("headers", {})
            # some judges return header values as lists (one per occurrence)
            headers = {k.lower(): ", ".join(v) if isinstance(v, list) else str(v)
                       for k, v in raw.items()}
        except Exception:
            result.anonymity = Anonymity.UNKNOWN
            return

        present_ip = [h for h in IP_LEAK_HEADERS if h in headers]
        if self.real_ip:
            for h in present_ip:
                if self.real_ip in headers[h]:
                    result.anonymity = Anonymity.TRANSPARENT
                    result.leaks = [h]
                    return

        if not self.trusted_header_judge:
            # public judges sit behind CDNs that add Via/XFF of their own —
            # only a leaked real IP is a reliable signal there
            result.anonymity = Anonymity.ELITE
            return

        present_id = [h for h in PROXY_ID_HEADERS if h in headers]
        if present_ip:
            # the proxy forwards client-identifying headers — textbook transparent
            result.anonymity = Anonymity.TRANSPARENT
            result.leaks = present_ip
        elif present_id:
            result.anonymity = Anonymity.ANONYMOUS
            result.leaks = present_id
        else:
            result.anonymity = Anonymity.ELITE

    # -- stage 4: TLS tunnelling & speed -------------------------------------

    async def _https_tunnel_ok(self, proxy: Proxy, scheme: str) -> bool:
        if scheme == "https":
            return True
        url = self._next_judge(list(HTTPS_JUDGES))
        try:
            await self._fetch(proxy, scheme, url, self.opts.timeout)
            return True
        except Exception:
            return False

    async def _speed_test(self, proxy: Proxy, scheme: str, result: ProxyResult) -> None:
        url = SPEED_URL.format(size=self.opts.speed_kbytes * 1024)
        limit = self.opts.speed_kbytes * 1024
        try:
            session, kwargs, cleanup = await self._session(proxy, scheme, self.opts.speed_timeout)
        except Exception:
            return
        downloaded = 0
        start = time.monotonic()
        try:
            async with session.get(url, **kwargs) as resp:
                if resp.status >= 400:
                    return
                async for chunk in resp.content.iter_any():
                    downloaded += len(chunk)
                    if downloaded >= limit or time.monotonic() - start > self.opts.speed_timeout:
                        break
        except Exception:
            return
        finally:
            await cleanup()
        elapsed = time.monotonic() - start
        if elapsed > 0 and downloaded > 0:
            result.speed_kbps = round(downloaded * 8 / 1000 / elapsed, 1)

    # -- transport -----------------------------------------------------------

    async def _session(self, proxy: Proxy, scheme: str, timeout: float):
        """Build (session, request_kwargs, cleanup) for the given protocol."""
        t = aiohttp.ClientTimeout(total=timeout, sock_connect=timeout, connect=timeout)
        if scheme in ("socks5", "socks4"):
            if ProxyConnector is None:
                raise RuntimeError("aiohttp-socks is not installed")
            connector = ProxyConnector.from_url(proxy.url(scheme), rdns=True)
            session = aiohttp.ClientSession(connector=connector, timeout=t)
            kwargs: dict = {}
        else:
            kwargs = {"proxy": proxy.http_proxy_url()}
            if proxy.username:
                kwargs["proxy_auth"] = aiohttp.BasicAuth(
                    proxy.username, proxy.password or "", encoding="latin1"
                )
            session = aiohttp.ClientSession(timeout=t)

        async def cleanup() -> None:
            await session.close()

        return session, kwargs, cleanup

    async def _fetch(self, proxy: Proxy, scheme: str, url: str, timeout: float) -> tuple[int, str]:
        session, kwargs, cleanup = await self._session(proxy, scheme, timeout)
        try:
            async with session.get(url, **kwargs) as resp:
                body = await resp.text(errors="replace")
                if resp.status >= 400:
                    raise JudgeError(f"HTTP {resp.status}")
                return resp.status, body
        except aiohttp.ClientError as exc:
            raise JudgeError(short_error(exc)) from exc
        finally:
            await cleanup()


def short_error(exc: BaseException) -> str:
    msg = str(exc) or exc.__class__.__name__
    msg = " ".join(msg.split())
    return msg[:90]


async def fetch_real_ip(timeout: float = 6.0) -> Optional[str]:
    """Who are we, when we cross the river ourselves? (direct connection)"""
    import aiohttp

    t = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=t) as session:
        for url in list(HTTP_JUDGES)[:3]:
            try:
                async with session.get(url) as resp:
                    ip = extract_ip(await resp.text(errors="replace"))
                    if ip:
                        return ip
            except Exception:
                continue
    return None
