"""Bring your own judge — `styx judge`.

Public echo services live behind CDNs and load balancers that strip or inject
Via / X-Forwarded-For headers, which blurs anonymity grading. Serving your own
judge removes the noise: what the proxy sent is exactly what you see.

Endpoints:
    GET /ip    -> the caller's IP as plain text
    GET /echo  -> {"origin": ip, "headers": {...}} as JSON
"""

from __future__ import annotations

import asyncio

from aiohttp import web


async def _ip(request: web.Request) -> web.Response:
    peer = request.transport.get_extra_info("peername")
    return web.Response(text=peer[0] if peer else "unknown")


async def _echo(request: web.Request) -> web.Response:
    peer = request.transport.get_extra_info("peername")
    return web.json_response({
        "origin": peer[0] if peer else "unknown",
        "headers": dict(request.headers),
    })


def make_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/ip", _ip)
    app.router.add_get("/echo", _echo)
    return app


async def serve(host: str, port: int) -> None:
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()
