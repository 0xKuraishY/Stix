"""Exporters — every format a proxy hoarder could ever ask for."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .models import GRADE_RANK, ProxyResult, Status, now_iso

CSV_COLUMNS = [
    "host", "port", "scheme_detected", "scheme_input", "username", "password",
    "status", "grade", "latency_ms", "exit_ip", "anonymity", "https_capable",
    "speed_kbps", "ip_type", "country", "country_code", "city", "isp", "org",
    "asn", "known_proxy", "error", "leaks", "checked_at", "source_line",
]


def _alive_sorted(results: list[ProxyResult]) -> list[ProxyResult]:
    alive = [r for r in results if r.alive]
    alive.sort(key=lambda r: (GRADE_RANK.get(r.grade, 9), r.latency_ms or 9_999_999))
    return alive


def _url_line(r: ProxyResult) -> str:
    return r.proxy.url(r.detected_scheme)


def build_summary(results: list[ProxyResult]) -> dict[str, Any]:
    alive = [r for r in results if r.alive]
    schemes = Counter(r.detected_scheme for r in alive)
    anon = Counter(r.anonymity.value for r in alive)
    grades = Counter(r.grade for r in results)
    lats = [r.latency_ms for r in alive if r.latency_ms is not None]
    speeds = [r.speed_kbps for r in alive if r.speed_kbps is not None]
    return {
        "total": len(results),
        "alive": len(alive),
        "dead": len(results) - len(alive),
        "schemes": dict(schemes),
        "anonymity": dict(anon),
        "grades": dict(grades),
        "avg_latency_ms": round(sum(lats) / len(lats)) if lats else None,
        "avg_speed_kbps": round(sum(speeds) / len(speeds), 1) if speeds else None,
        "unique_exit_ips": len({r.exit_ip for r in alive if r.exit_ip}),
    }


def write_exports(results: list[ProxyResult], outdir: Path, source: str = "",
                  real_ip: Optional[str] = None, config: Optional[dict] = None,
                  elapsed_s: Optional[float] = None) -> dict[str, str]:
    outdir.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    alive = _alive_sorted(results)

    def _dump(name: str, text: str) -> None:
        path = outdir / name
        path.write_text(text, encoding="utf-8")
        written[name] = str(path)

    # --- full JSON report -------------------------------------------------
    payload = {
        "tool": "styx",
        "version": __version__,
        "generated_at": now_iso(),
        "source": source,
        "real_ip": real_ip,
        "elapsed_s": round(elapsed_s, 2) if elapsed_s else None,
        "config": config or {},
        "summary": build_summary(results),
        "results": [r.to_dict() for r in results],
    }
    (outdir / "results.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    written["results.json"] = str(outdir / "results.json")

    # --- plain lists --------------------------------------------------------
    _dump("alive.txt", "".join(f"{_url_line(r)}\n" for r in alive))
    _dump("alive-legacy.txt", "".join(f"{r.proxy.legacy_line()}\n" for r in alive))
    _dump("dead.txt", "".join(f"{r.proxy.source_line or r.proxy.endpoint}\n"
                              for r in results if not r.alive))

    # --- per-protocol files ---------------------------------------------------
    by_type = outdir / "by-type"
    for scheme in ("socks5", "socks4", "http"):
        group = [r for r in alive if r.detected_scheme == scheme]
        (by_type / f"{scheme}.txt").parent.mkdir(parents=True, exist_ok=True)
        (by_type / f"{scheme}.txt").write_text(
            "".join(f"{_url_line(r)}\n" for r in group), encoding="utf-8")
        if group:
            written[f"by-type/{scheme}.txt"] = str(by_type / f"{scheme}.txt")

    # elite-only shortlist
    elite = [r for r in alive if r.anonymity.value == "elite"]
    _dump("elite.txt", "".join(f"{_url_line(r)}\n" for r in elite))

    # --- CSV ------------------------------------------------------------------
    csv_path = outdir / "results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in results:
            p = r.proxy
            writer.writerow({
                "host": p.host, "port": p.port,
                "scheme_detected": r.detected_scheme or "",
                "scheme_input": p.scheme or "",
                "username": p.username or "", "password": p.password or "",
                "status": r.status.value, "grade": r.grade,
                "latency_ms": r.latency_ms or "", "exit_ip": r.exit_ip or "",
                "anonymity": r.anonymity.value, "https_capable": r.https_capable,
                "speed_kbps": r.speed_kbps or "", "ip_type": r.ip_type or "",
                "country": r.country or "", "country_code": r.country_code or "",
                "city": r.city or "", "isp": r.isp or "", "org": r.org or "",
                "asn": r.asn or "", "known_proxy": r.known_proxy,
                "error": r.error or "", "leaks": ",".join(r.leaks),
                "checked_at": r.checked_at, "source_line": p.source_line,
            })
    written["results.csv"] = str(csv_path)

    return written


def load_results(path: Path) -> tuple[dict, list[ProxyResult]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    results = [ProxyResult.from_dict(d) for d in data.get("results", [])]
    return data, results
