"""Judge endpoints: IP echo services and header-echo services.

Judges are only ever asked one question: "who do you see?".
"""

from __future__ import annotations

import json
import re
from typing import Optional

HTTP_JUDGES = [
    "http://api.ipify.org/",
    "http://httpbin.org/ip",
    "http://ifconfig.me/ip",
    "http://icanhazip.com",
    "http://checkip.amazonaws.com",
]

HTTPS_JUDGES = [
    "https://api.ipify.org/",
    "https://httpbin.org/ip",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
]

#: header echo judges. Public ones sit behind CDNs that strip/inject Via and
#: X-Forwarded-For — for court-grade grading run your own (`styx judge`).
HEADER_JUDGES = [
    "http://httpbingo.org/headers",
    "http://httpbin.org/headers",
    "http://eu.httpbin.org/headers",
]

SPEED_URL = "https://speed.cloudflare.com/__down?bytes={size}"

# headers that, seen by a judge, mean the proxy forwards client identity
IP_LEAK_HEADERS = (
    "x-forwarded-for", "x-real-ip", "client-ip", "x-client-ip",
    "x-original-forwarded-for", "forwarded", "x-cluster-client-ip",
    "x-proxyuser-ip", "x-roxy-user-ip",
)

# headers that reveal proxy usage without necessarily leaking the client IP
PROXY_ID_HEADERS = (
    "via", "proxy-connection", "x-proxy-id", "proxy-agent",
    "x-bluecoat-via", "x-forwarded-server", "x-http-via", "x-cache-lookup",
)

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)")


def extract_ip(body: str) -> Optional[str]:
    """Pull the caller's IP out of a judge response, JSON or plain text."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        for key in ("origin", "ip", "query"):
            value = data.get(key)
            if isinstance(value, str) and _looks_like_ip(value.split(",")[0].strip()):
                return value.split(",")[0].strip()
    if isinstance(body, str):
        m = _IP_RE.search(body)
        if m:
            candidate = m.group(1)
            if _looks_like_ip(candidate):
                return candidate
    return None


def _looks_like_ip(value: str) -> bool:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return all(0 <= int(p) <= 255 for p in value.split("."))
    return ":" in value and bool(re.fullmatch(r"[0-9a-fA-F:.]+", value))
