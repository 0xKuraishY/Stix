"""Input parser — understands every proxy list dialect known to humankind.

Supported per line:
    host:port
    host:port:user:pass            (the classic)
    user:pass@host:port
    host:port@user:pass            (the cursed variant)
    scheme://host:port
    scheme://user:pass@host:port
    [2001:db8::1]:1080             (IPv6)

Anything else is counted as skipped junk instead of crashing the crossing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import SCHEME_ALIASES, Proxy

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


@dataclass
class ParseReport:
    proxies: list[Proxy] = field(default_factory=list)
    skipped: int = 0
    duplicates: int = 0

    @property
    def seen(self) -> int:
        return len(self.proxies) + self.duplicates


def _valid_host(host: str) -> bool:
    if not host:
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return all(0 <= int(p) <= 255 for p in host.split("."))
    if _DOMAIN_RE.match(host):
        return True
    if _IPV6_RE.match(host) and ":" in host:
        try:
            import ipaddress

            ipaddress.IPv6Address(host)
            return True
        except ValueError:
            return False
    return False


def _split_auth(auth: str) -> tuple[Optional[str], Optional[str]]:
    if ":" in auth:
        user, pwd = auth.split(":", 1)
        return user or None, pwd
    return auth or None, None


def parse_line(line: str) -> Optional[Proxy]:
    raw = line.strip()
    if not raw or raw.startswith(("#", ";", "//")):
        return None

    scheme: Optional[str] = None
    rest = raw
    if "://" in raw:
        head, rest = raw.split("://", 1)
        scheme = SCHEME_ALIASES.get(head.strip().lower())
        if scheme is None:
            return None

    username = password = None
    hostpart = rest

    if "@" in rest:
        before, after = rest.rsplit("@", 1)
        # host:port@user:pass  vs  user:pass@host:port — decide by side shapes
        left_hostish = ":" in before and _looks_like_hostport(before)
        right_hostish = _looks_like_hostport(after)
        if right_hostish:
            hostpart = after
            username, password = _split_auth(before)
        elif left_hostish:
            hostpart = before
            username, password = _split_auth(after)
        else:
            return None

    host: str
    port_s: str
    if hostpart.startswith("["):
        end = hostpart.find("]")
        if end == -1 or end + 1 >= len(hostpart) or hostpart[end + 1] != ":":
            return None
        host, port_s = hostpart[1:end], hostpart[end + 2:]
    elif hostpart.count(":") == 3:
        # the classic: host:port:user:pass
        host, port_s, user_s, pass_s = hostpart.split(":", 3)
        if username is None and user_s:
            username, password = user_s, pass_s
    elif hostpart.count(":") == 1:
        host, port_s = hostpart.rsplit(":", 1)
    else:
        # bare IPv6 without brackets, or garbage
        return None

    if not port_s.isdigit():
        return None
    port = int(port_s)
    if not (1 <= port <= 65535):
        return None
    host = host.strip().lower().rstrip(".")
    if not _valid_host(host):
        return None

    return Proxy(
        host=host,
        port=port,
        username=username,
        password=password,
        scheme=scheme,
        source_line=raw,
    )


def _looks_like_hostport(part: str) -> bool:
    if part.startswith("["):
        return True
    host, sep, port = part.rpartition(":")
    if not sep or not port.isdigit():
        return False
    host = host.strip().lower().rstrip(".")
    return bool(host) and (_DOMAIN_RE.match(host) is not None or
                           re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) is not None)


def parse_lines(lines: Iterable[str]) -> ParseReport:
    report = ParseReport()
    seen_keys: set[tuple] = set()
    for line in lines:
        proxy = parse_line(line)
        if proxy is None:
            if line.strip() and not line.strip().startswith(("#", ";")):
                report.skipped += 1
            continue
        k = proxy.key()
        if k in seen_keys:
            report.duplicates += 1
            continue
        seen_keys.add(k)
        report.proxies.append(proxy)
    return report
