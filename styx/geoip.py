"""GeoIP & reputation enrichment via the free ip-api.com batch endpoint.

Enriches alive results with country, city, ISP, ASN, and — the interesting
part — whether the exit IP is already flagged as a known proxy/VPN in public
databases, plus a hosting/residential/mobile classification.
"""

from __future__ import annotations

import asyncio
from typing import Optional

import aiohttp

from .models import ProxyResult

BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp,org,as,asname,mobile,proxy,hosting"
BATCH_SIZE = 100
# free tier: ~15 batch requests/minute — stay polite
BATCH_PAUSE = 4.2


def classify_ip_type(info: dict) -> str:
    if info.get("hosting"):
        return "hosting"
    if info.get("mobile"):
        return "mobile"
    if info.get("proxy"):
        return "vpn/proxy"
    return "residential/isp"


async def enrich(results: list[ProxyResult], on_batch=None) -> int:
    """Fill geo fields on alive results. Returns number of enriched proxies."""
    alive = [r for r in results if r.alive and r.exit_ip]
    unique_ips = sorted({r.exit_ip for r in alive if r.exit_ip})
    if not unique_ips:
        return 0

    info_by_ip: dict[str, dict] = {}
    timeout = aiohttp.ClientTimeout(total=10.0, connect=8.0)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for i in range(0, len(unique_ips), BATCH_SIZE):
            chunk = unique_ips[i:i + BATCH_SIZE]
            payload = [{"query": ip, "fields": "status,query,country,countryCode,city,isp,org,as,mobile,proxy,hosting"} for ip in chunk]
            for attempt in range(2):
                try:
                    async with session.post(BATCH_URL, json=payload) as resp:
                        if resp.status == 429:
                            await asyncio.sleep(30)
                            continue
                        resp.raise_for_status()
                        for item in await resp.json():
                            if item.get("status") == "success" and item.get("query"):
                                info_by_ip[item["query"]] = item
                        break
                except Exception:
                    if attempt == 1:
                        break
                    await asyncio.sleep(3)
            if on_batch:
                on_batch(min(i + BATCH_SIZE, len(unique_ips)), len(unique_ips))
            if i + BATCH_SIZE < len(unique_ips):
                await asyncio.sleep(BATCH_PAUSE)

    enriched = 0
    for r in alive:
        info: Optional[dict] = info_by_ip.get(r.exit_ip or "")
        if not info:
            continue
        r.country = info.get("country")
        r.country_code = info.get("countryCode")
        r.city = info.get("city")
        r.isp = info.get("isp")
        r.org = info.get("org")
        r.asn = (info.get("as") or "").split(" ")[0] or None
        r.known_proxy = bool(info.get("proxy"))
        r.ip_type = classify_ip_type(info)
        enriched += 1
    return enriched
