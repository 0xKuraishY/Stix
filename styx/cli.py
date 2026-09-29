"""Command line interface — check, recheck, report, demo."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from aiohttp import web

from . import __version__
from .engine import Engine, EngineOptions, fetch_real_ip
from .exporter import load_results, write_exports
from .geoip import enrich as geo_enrich
from .models import GRADE_RANK, ProxyResult
from .parser import parse_lines
from .ui import Dashboard, final_summary

console = Console()


def _add_engine_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-w", "--workers", type=int, default=250, help="concurrent checks (default: 250)")
    p.add_argument("-t", "--timeout", type=float, default=8.0, help="per-request timeout, seconds (default: 8)")
    p.add_argument("--tcp-timeout", type=float, default=4.0, help="TCP probe timeout (default: 4)")
    p.add_argument("--judge", help="custom judge URL for IP echo")
    p.add_argument("--header-judge", help="custom header-echo judge URL — enables full "
                                          "elite/anonymous/transparent grading (see `styx judge`)")
    p.add_argument("--scheme", choices=("auto", "socks5", "socks4", "http", "https"),
                   default="auto", help="force a protocol instead of auto-detection")
    p.add_argument("--geo", action="store_true", help="enrich alive proxies with GeoIP/ASN data (ip-api.com)")
    p.add_argument("--speed", action="store_true", help="measure download speed through each alive proxy")
    p.add_argument("--speed-size", type=int, default=1024, help="speed test payload, KiB (default: 1024)")
    p.add_argument("--no-anonymity", action="store_true", help="skip the anonymity judge (faster)")
    p.add_argument("-q", "--quiet", action="store_true", help="no live dashboard, final summary only")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="styx",
        description="Styx — the proxy intelligence framework. Cross the river. Leave no trace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"styx {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="test a proxy list",
                           description="Test every proxy in a list and identify its protocol.")
    check.add_argument("file", help="proxy list file, one per line, any dialect")
    check.add_argument("-o", "--output", default="styx_output", help="output directory (default: styx_output)")
    _add_engine_flags(check)

    recheck = sub.add_parser("recheck", help="retest results from a previous run",
                             description="Reload results.json and retest a subset, then merge.")
    recheck.add_argument("results", help="results.json from a previous run")
    recheck.add_argument("--only", choices=("dead", "alive"), default="dead",
                         help="which subset to retest (default: dead)")
    recheck.add_argument("-o", "--output", help="output directory (default: next to results.json)")
    _add_engine_flags(recheck)

    report = sub.add_parser("report", help="render a results.json as a summary")
    report.add_argument("results", help="results.json from a previous run")
    report.add_argument("--top", type=int, default=12, help="how many top proxies to show (default: 12)")

    demo = sub.add_parser("demo", help="self-test against 4 local proxy spirits (no list needed)",
                          description="Raise a local SOCKS5 and three HTTP proxies with different "
                                      "anonymity personalities, then run the full crossing against them.")
    demo.add_argument("-o", "--output", default="styx_demo_output", help="output directory")
    _add_engine_flags(demo)

    judge = sub.add_parser("judge", help="serve your own IP/header echo judge",
                           description="Run a local judge for court-grade anonymity grading, "
                                       "free of CDN header meddling.")
    judge.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    judge.add_argument("-p", "--port", type=int, default=8388, help="port (default: 8388)")

    return parser


# ---------------------------------------------------------------------------
# shared execution pipeline

def _engine_opts(args) -> EngineOptions:
    schemes = ("http",) if args.scheme == "https" else \
        (tuple((args.scheme,)) if args.scheme != "auto" else ("socks5", "socks4", "http"))
    return EngineOptions(
        workers=args.workers,
        timeout=args.timeout,
        tcp_timeout=args.tcp_timeout,
        schemes=schemes,
        judge=args.judge,
        header_judge=args.header_judge,
        speed_test=args.speed,
        speed_kbytes=args.speed_size,
        skip_anonymity=args.no_anonymity,
    )


class _NullLive:
    def update(self, _) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


async def _run_engine(proxies, opts: EngineOptions, live, dash: Dashboard,
                      state: dict) -> list[ProxyResult]:
    engine = Engine(opts, real_ip=state.get("real_ip"))
    state["engine"] = engine

    def on_result(result: ProxyResult) -> None:
        dash.add(result)
        now = time.monotonic()
        if now - state.get("last_render", 0.0) > 0.05:
            state["last_render"] = now
            live.update(dash.frame())

    engine.on_result = on_result
    return await engine.run(proxies)


async def _execute_async(proxies: list[Proxy], args, source: str, outdir: Path,
                         real_ip: str | None, holder: dict) -> list[ProxyResult]:
    """Run the crossing for a parsed proxy list and export everything."""
    opts = _engine_opts(args)
    dash = Dashboard(len(proxies), source=source, workers=opts.workers, timeout=opts.timeout)
    state = holder
    state["real_ip"] = real_ip
    state.setdefault("last_render", 0.0)
    start = time.monotonic()
    live_ctx = _NullLive() if args.quiet else Live(
        dash.frame(), console=console, refresh_per_second=15, screen=False)
    with live_ctx as live:
        results = await _run_engine(proxies, opts, live, dash, state)
    elapsed = time.monotonic() - start

    alive = [r for r in results if r.alive]
    if args.geo and alive:
        exits = len({r.exit_ip for r in alive if r.exit_ip})
        with console.status(f"[cyan]consulting the oracle about {exits} exit IPs…[/]"):
            enriched = await geo_enrich(results)
        console.print(f"[dim]geo: {enriched} proxies enriched[/]")

    exports = write_exports(results, outdir, source=source, real_ip=real_ip,
                            config=vars(args), elapsed_s=elapsed)
    console.print(final_summary(results, exports=exports, elapsed=elapsed))
    holder["results"] = results
    return results


def _execute(proxies: list[Proxy], args, source: str, outdir: Path,
             real_ip: str | None) -> list[ProxyResult]:
    holder: dict = {}
    try:
        return asyncio.run(_execute_async(proxies, args, source, outdir, real_ip, holder))
    except KeyboardInterrupt:
        console.print("\n[yellow]! the ferryman was interrupted — exporting partial results[/]")
        engine = holder.get("engine")
        results = list(engine.results) if engine else holder.get("results", [])
        exports = write_exports(results, outdir, source=source, real_ip=real_ip,
                                config=vars(args), elapsed_s=None)
        console.print(final_summary(results, exports=exports))
        return results


def _parse_target_file(path: str) -> list[Proxy]:
    file_path = Path(path)
    if not file_path.is_file():
        console.print(f"[red]✖[/] no such file: {path}")
        sys.exit(2)
    report = parse_lines(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
    if report.skipped:
        console.print(f"[dim]parser: {report.seen} recognized, {report.skipped} junk lines ignored, "
                      f"{report.duplicates} duplicates removed[/]")
    if not report.proxies:
        console.print("[red]✖[/] no usable proxies found — check the input format")
        sys.exit(2)
    return report.proxies


# ---------------------------------------------------------------------------
# commands

def cmd_check(args) -> None:
    proxies = _parse_target_file(args.file)
    console.print(f"[dim]styx v{__version__} — {len(proxies)} proxies to ferry across the river[/]")
    with console.status("[cyan]finding out who we are…[/]", spinner="dots2"):
        real_ip = asyncio.run(fetch_real_ip())
    if real_ip:
        console.print(f"[dim]reference identity: [cyan]{real_ip}[/] (judge comparison)[/]")
    else:
        console.print("[yellow]! could not determine our own IP — anonymity grading falls back to headers only[/]")
    _execute(proxies, args, source=Path(args.file).name, outdir=Path(args.output),
             real_ip=real_ip)


def cmd_recheck(args) -> None:
    data_path = Path(args.results)
    if not data_path.is_file():
        console.print(f"[red]✖[/] no such file: {args.results}")
        sys.exit(2)
    data, results = load_results(data_path)
    subset = [r for r in results
              if (args.only == "dead" and not r.alive) or (args.only == "alive" and r.alive)]
    if not subset:
        console.print(f"[yellow]nothing to recheck — no '{args.only}' proxies in that file[/]")
        return

    proxies = [r.proxy for r in subset]
    console.print(f"[dim]rechecking {len(proxies)} {args.only} proxies from {data_path.name}[/]")

    opts = _engine_opts(args)
    dash = Dashboard(len(proxies), source=data_path.name, workers=opts.workers, timeout=opts.timeout)
    state = {"real_ip": data.get("real_ip"), "last_render": 0.0}
    start = time.monotonic()
    live_ctx = _NullLive() if args.quiet else Live(
        dash.frame(), console=console, refresh_per_second=15, screen=False)
    with live_ctx as live:
        fresh = asyncio.run(_run_engine(proxies, opts, live, dash, state))
    elapsed = time.monotonic() - start

    fresh_by_key = {r.proxy.key(): r for r in fresh}
    merged = [fresh_by_key.pop(r.proxy.key(), r) for r in results]
    merged.extend(fresh_by_key.values())
    merged.sort(key=lambda r: (0 if r.alive else 1, GRADE_RANK.get(r.grade, 9),
                               r.latency_ms or 9_999_999))

    outdir = Path(args.output) if args.output else data_path.parent
    if args.geo:
        with console.status("[cyan]consulting the oracle…[/]"):
            asyncio.run(geo_enrich(merged))
    exports = write_exports(merged, outdir, source=data.get("source", ""),
                            real_ip=data.get("real_ip"), config=vars(args), elapsed_s=elapsed)
    console.print(final_summary(merged, exports=exports, elapsed=elapsed,
                                heading="THE CROSSING HAS BEEN RECKONED"))


def cmd_report(args) -> None:
    data_path = Path(args.results)
    if not data_path.is_file():
        console.print(f"[red]✖[/] no such file: {args.results}")
        sys.exit(2)
    data, results = load_results(data_path)
    console.print(final_summary(results, exports=None,
                                elapsed=data.get("elapsed_s"),
                                heading="RECKONING OF A PAST CROSSING"))


def cmd_demo(args) -> None:
    """Raise local proxy spirits and cross them — all in one event loop."""
    from .judge_server import make_app
    from .locals import LocalSpirits

    async def _demo() -> None:
        console.print("[dim]the ferryman raised 4 local proxy spirits and a local judge:[/]")
        judge_app = make_app()
        judge_runner = None
        spirits = None
        try:
            judge_runner = web.AppRunner(judge_app)
            await judge_runner.setup()
            site = web.TCPSite(judge_runner, "127.0.0.1", 0)
            await site.start()
            judge_port = site._server.sockets[0].getsockname()[1]
            args.judge = f"http://127.0.0.1:{judge_port}/ip"
            args.header_judge = f"http://127.0.0.1:{judge_port}/echo"

            spirits = await LocalSpirits().__aenter__()
            for entry in spirits.entries:
                console.print(f"  [cyan]{entry}[/]")
            console.print(f"[dim]judge:      http://127.0.0.1:{judge_port}[/]")
            console.print("[dim]all spirits exit from YOUR public IP — anonymity grades reflect "
                          "their header personalities (elite / anonymous / transparent).[/]")
            report = parse_lines(spirits.entries)
            await _execute_async(report.proxies, args, source="local demo spirits",
                                 outdir=Path(args.output), real_ip=None, holder={})
        finally:
            if spirits is not None:
                await spirits.__aexit__(None, None, None)
            if judge_runner is not None:
                await judge_runner.cleanup()

    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        console.print("\n[yellow]! demo interrupted[/]")


def cmd_judge(args) -> None:
    from .judge_server import serve

    base = f"http://{args.host}:{args.port}"
    console.print(f"[bold cyan]styx judge[/] listening on [bold]{base}[/]")
    console.print(f"  [dim]IP echo[/]    {base}/ip")
    console.print(f"  [dim]headers[/]    {base}/echo")
    console.print("[dim]point the checker at it:  styx check list.txt "
                  f"--judge {base}/ip --header-judge {base}/echo[/]")
    try:
        asyncio.run(serve(args.host, args.port))
    except KeyboardInterrupt:
        console.print("[dim]judge silenced[/]")


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "check":
        cmd_check(args)
    elif args.command == "recheck":
        cmd_recheck(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "judge":
        cmd_judge(args)
    elif args.command == "demo":
        cmd_demo(args)


if __name__ == "__main__":
    main()
