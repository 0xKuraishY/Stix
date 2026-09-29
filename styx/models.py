"""Core data models: proxies, results, anonymity levels, grading."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import quote

# ---------------------------------------------------------------------------
# schemes

SCHEME_ALIASES = {
    "socks5": "socks5",
    "socks5h": "socks5",
    "socks4": "socks4",
    "socks4a": "socks4",
    "http": "http",
    "https": "https",
}

#: wire protocols probed during auto-detection, fastest first
DETECTION_CANDIDATES = ("socks5", "socks4", "http")

IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


class Status(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"


class Anonymity(str, Enum):
    ELITE = "elite"
    ANONYMOUS = "anonymous"
    TRANSPARENT = "transparent"
    UNKNOWN = "unknown"


GRADE_RANK = {"S": 0, "A": 1, "B": 2, "C": 3, "D": 4, "F": 5}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# proxy

@dataclass
class Proxy:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    scheme: Optional[str] = None  # declared in input, if any
    source_line: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def has_auth(self) -> bool:
        return bool(self.username)

    def key(self) -> tuple:
        return (
            (self.scheme or "").lower(),
            self.host.lower(),
            self.port,
            self.username or "",
            self.password or "",
        )

    def _auth_part(self) -> str:
        if not self.username:
            return ""
        user = quote(self.username, safe="")
        pwd = quote(self.password or "", safe="")
        return f"{user}:{pwd}@"

    def _host_part(self) -> str:
        # bracket IPv6 hosts for URL building
        return f"[{self.host}]" if ":" in self.host else self.host

    def url(self, scheme: Optional[str] = None) -> str:
        """Canonical URL: scheme://[auth@]host:port."""
        return f"{scheme or self.scheme or 'http'}://{self._auth_part()}{self._host_part()}:{self.port}"

    def http_proxy_url(self) -> str:
        """URL for aiohttp's proxy= parameter (never embed credentials)."""
        return f"http://{self._host_part()}:{self.port}"

    def legacy_line(self, scheme: Optional[str] = None) -> str:
        """host:port[:user:pass] dialect, matching the classic list format."""
        base = self.endpoint
        if self.username:
            base += f":{self.username}:{self.password or ''}"
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "scheme": self.scheme,
            "source_line": self.source_line,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Proxy":
        return cls(
            host=d["host"],
            port=int(d["port"]),
            username=d.get("username"),
            password=d.get("password"),
            scheme=d.get("scheme"),
            source_line=d.get("source_line", ""),
        )


# ---------------------------------------------------------------------------
# result

@dataclass
class ProxyResult:
    proxy: Proxy
    status: Status = Status.DEAD
    detected_scheme: Optional[str] = None
    latency_ms: Optional[int] = None
    exit_ip: Optional[str] = None
    anonymity: Anonymity = Anonymity.UNKNOWN
    https_capable: bool = False
    speed_kbps: Optional[float] = None
    grade: str = "F"
    error: Optional[str] = None
    leaks: list[str] = field(default_factory=list)
    # geo / reputation enrichment
    ip_type: Optional[str] = None  # residential | hosting | mobile | business
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    known_proxy: Optional[bool] = None  # flagged in public proxy/VPN databases
    checked_at: str = field(default_factory=now_iso)

    @property
    def alive(self) -> bool:
        return self.status == Status.ALIVE

    def compute_grade(self) -> str:
        """S-F score blending anonymity, latency, TLS tunnelling and speed."""
        if not self.alive:
            self.grade = "F"
            return self.grade
        score = {
            Anonymity.ELITE: 3.0,
            Anonymity.UNKNOWN: 1.5,
            Anonymity.ANONYMOUS: 2.0,
            Anonymity.TRANSPARENT: 0.5,
        }[self.anonymity]
        lat = self.latency_ms if self.latency_ms is not None else 99999
        score += 2.0 if lat <= 400 else 1.5 if lat <= 800 else 1.0 if lat <= 1500 else 0.5 if lat <= 3000 else 0.0
        if self.https_capable:
            score += 0.5
        spd = self.speed_kbps
        if spd is not None:
            score += 2.0 if spd >= 5000 else 1.5 if spd >= 1500 else 1.0 if spd >= 500 else 0.5 if spd >= 100 else 0.0
        self.grade = "S" if score >= 7 else "A" if score >= 5.5 else "B" if score >= 4 else "C" if score >= 2 else "D"
        return self.grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "proxy": self.proxy.to_dict(),
            "status": self.status.value,
            "detected_scheme": self.detected_scheme,
            "latency_ms": self.latency_ms,
            "exit_ip": self.exit_ip,
            "anonymity": self.anonymity.value,
            "https_capable": self.https_capable,
            "speed_kbps": self.speed_kbps,
            "grade": self.grade,
            "error": self.error,
            "leaks": self.leaks,
            "ip_type": self.ip_type,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "known_proxy": self.known_proxy,
            "checked_at": self.checked_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProxyResult":
        return cls(
            proxy=Proxy.from_dict(d["proxy"]),
            status=Status(d.get("status", "dead")),
            detected_scheme=d.get("detected_scheme"),
            latency_ms=d.get("latency_ms"),
            exit_ip=d.get("exit_ip"),
            anonymity=Anonymity(d.get("anonymity", "unknown")),
            https_capable=d.get("https_capable", False),
            speed_kbps=d.get("speed_kbps"),
            grade=d.get("grade", "F"),
            error=d.get("error"),
            leaks=list(d.get("leaks", [])),
            ip_type=d.get("ip_type"),
            country=d.get("country"),
            country_code=d.get("country_code"),
            city=d.get("city"),
            isp=d.get("isp"),
            org=d.get("org"),
            asn=d.get("asn"),
            known_proxy=d.get("known_proxy"),
            checked_at=d.get("checked_at", now_iso()),
        )
