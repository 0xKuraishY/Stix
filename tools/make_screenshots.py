#!/usr/bin/env python3
"""Regenerate the README screenshots (docs/*.svg) from the real UI code.

    python tools/make_screenshots.py
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console

from styx.models import Anonymity, Proxy, ProxyResult, Status
from styx.ui import Dashboard, final_summary

random.seed(42)

SCHEMES = ["socks5"] * 14 + ["http"] * 9 + ["socks4"] * 3
ANON = [Anonymity.ELITE, Anonymity.ELITE, Anonymity.ELITE, Anonymity.ANONYMOUS,
        Anonymity.ANONYMOUS, Anonymity.TRANSPARENT]
COUNTRIES = [("France", "FR", "Paris"), ("Germany", "DE", "Frankfurt"),
             ("Netherlands", "NL", "Amsterdam"), ("United States", "US", "Ashburn"),
             ("United Kingdom", "GB", "London"), ("Canada", "CA", "Montreal")]


def make_result(i: int) -> ProxyResult:
    host = f"{random.randint(11, 199)}.{random.randint(20, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"
    port = random.choice([1080, 1080, 8080, 3128, 4145, 9050])
    if random.random() < 0.3:
        proxy = Proxy(host, port, f"user{random.randint(1, 9)}", f"pass{random.randint(10, 99)}",
                      source_line=f"{host}:{port}")
    else:
        proxy = Proxy(host, port, source_line=f"{host}:{port}")
    if i % 7 == 3:
        return ProxyResult(proxy=proxy, status=Status.DEAD,
                           error=random.choice(["tcp unreachable / filtered",
                                                "connection reset by peer",
                                                "all protocols failed"]))
    scheme = SCHEMES[i % len(SCHEMES)]
    country, cc, city = random.choice(COUNTRIES)
    r = ProxyResult(
        proxy=proxy, status=Status.ALIVE, detected_scheme=scheme,
        latency_ms=random.randint(18, 2400), exit_ip=host,
        anonymity=random.choice(ANON),
        https_capable=scheme != "socks4" or random.random() < 0.5,
        speed_kbps=random.choice([None, 420.0, 980.5, 2600.0, 8100.0, 23800.0]),
        country=country, country_code=cc, city=city,
        isp=random.choice(["M247 Ltd", "OVH SAS", "Orange S.A.", "Hetzner Online",
                           "Free SAS", "DigitalOcean"]),
        asn=f"AS{random.randint(9000, 210000)}",
        ip_type=random.choice(["hosting", "residential/isp", "hosting", "mobile"]),
    )
    r.compute_grade()
    return r


def main() -> None:
    docs = Path(__file__).resolve().parent.parent / "docs"
    docs.mkdir(exist_ok=True)

    results = [make_result(i) for i in range(52)]
    alive = [r for r in results if r.alive]

    # --- live dashboard frame ------------------------------------------------
    dash = Dashboard(18402, source="proxies.txt", workers=500, timeout=8)
    dash.done = 12137
    dash.alive = len(alive) * 23
    dash.dead = dash.done - dash.alive
    dash.by_scheme.update({"socks5": 812, "http": 447, "socks4": 96})
    dash.by_anon.update({"elite": 621, "anonymous": 388, "transparent": 346})
    dash.tls = 1109
    dash._lat_sum = 812 * 620 + 447 * 890 + 96 * 1450
    dash._lat_n = dash.alive
    for r in alive[:6] + [results[3]]:
        dash.recent.appendleft(r)
    dash.progress.update(dash._task_id, completed=12137, eta="38s")
    console = Console(record=True, width=112)
    console.print(dash.frame())
    (docs / "screenshot-dashboard.svg").write_text(
        console.export_svg(title="styx — live dashboard"), encoding="utf-8")

    # --- final summary ---------------------------------------------------------
    full = [make_result(i) for i in range(52)] + [make_result(i) for i in range(20, 40)]
    exports = {
        "results.json": "styx_output/results.json",
        "alive.txt": "styx_output/alive.txt",
        "alive-legacy.txt": "styx_output/alive-legacy.txt",
        "dead.txt": "styx_output/dead.txt",
        "by-type/socks5.txt": "styx_output/by-type/socks5.txt",
        "by-type/socks4.txt": "styx_output/by-type/socks4.txt",
        "by-type/http.txt": "styx_output/by-type/http.txt",
        "elite.txt": "styx_output/elite.txt",
        "results.csv": "styx_output/results.csv",
    }
    console2 = Console(record=True, width=112)
    console2.print(final_summary(full, exports=exports, elapsed=214.6))
    (docs / "screenshot-summary.svg").write_text(
        console2.export_svg(title="styx — crossing complete"), encoding="utf-8")

    print(f"wrote {docs / 'screenshot-dashboard.svg'}")
    print(f"wrote {docs / 'screenshot-summary.svg'}")


if __name__ == "__main__":
    main()
