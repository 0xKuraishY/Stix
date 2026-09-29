"""Terminal experience — a live dashboard worthy of the underworld."""

from __future__ import annotations

import time
from collections import Counter, deque
from typing import Any, Optional

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from . import __version__
from .exporter import build_summary
from .models import Anonymity, GRADE_RANK, ProxyResult, Status

# ---------------------------------------------------------------------------
# style constants

SCHEME_STYLE = {
    "socks5": "bold bright_magenta",
    "socks4": "bold yellow",
    "http": "bold bright_cyan",
    "https": "bold bright_green",
}
ANON_STYLE = {
    "elite": "bold #ffd700",
    "anonymous": "bold bright_cyan",
    "transparent": "bold dark_orange",
    "unknown": "dim",
}
GRADE_STYLE = {
    "S": "bold #ffd700", "A": "bold bright_green", "B": "green",
    "C": "yellow", "D": "dark_orange", "F": "red",
}
STATUS_STYLE = {Status.ALIVE: "bold bright_green", Status.DEAD: "red"}

BANNER = """[bold bright_cyan]██████   ███████[/]   [bold bright_magenta]██   ██   ██   ██[/]
[bold bright_cyan]██       ██   [/]   [bold bright_magenta]██   ██    ██ ██ [/]
[bold bright_cyan]██████   ██████ [/]   [bold bright_magenta] █████      ███  [/]
[bold bright_cyan]     ██  ██     [/]   [bold bright_magenta]   ██      ██ ██ [/]
[bold bright_cyan]██████   ██     [/]   [bold bright_magenta]   ██     ██   ██[/]"""

TAGLINE = "cross the river. leave no trace."


def scheme_chip(scheme: Optional[str]) -> Text:
    label = (scheme or "?").upper()
    return Text(label, style=SCHEME_STYLE.get(scheme or "", "dim"))


def anon_chip(anonymity: Anonymity) -> Text:
    return Text(anonymity.value.upper(), style=ANON_STYLE.get(anonymity.value, "dim"))


def grade_chip(grade: str) -> Text:
    return Text(f" {grade} ", style=GRADE_STYLE.get(grade, "dim"))


def fmt_ms(ms: Optional[int]) -> str:
    if ms is None:
        return "-"
    if ms < 1000:
        return f"{ms}ms"
    return f"{ms / 1000:.1f}s"


def fmt_kbps(kbps: Optional[float]) -> str:
    if not kbps:
        return "-"
    return f"{kbps / 1000:.1f} MB/s" if kbps >= 1000 else f"{kbps:.0f} KB/s"


def _bar(count: int, peak: int, width: int = 24) -> str:
    if peak <= 0:
        return ""
    return "█" * max(1, round(count / peak * width)) if count else ""


# ---------------------------------------------------------------------------
# live dashboard

class Dashboard:
    """State + renderable frame for the live crossing."""

    def __init__(self, total: int, source: str = "", workers: int = 0,
                 timeout: float = 0, quiet_meta: Optional[str] = None):
        self.total = total
        self.source = source
        self.meta = quiet_meta or (
            f"[dim]v{__version__}[/]   [dim]{source}[/]   "
            f"[dim]{workers} oars[/]   [dim]{timeout:g}s timeout[/]"
        )
        self.done = 0
        self.alive = 0
        self.dead = 0
        self.by_scheme: Counter = Counter()
        self.by_anon: Counter = Counter()
        self.tls = 0
        self._lat_sum = 0
        self._lat_n = 0
        self.recent: deque[ProxyResult] = deque(maxlen=9)
        self.start_ts = time.monotonic()
        self.progress = Progress(
            SpinnerColumn("dots2", style="bright_cyan"),
            BarColumn(bar_width=None, complete_style="bright_cyan", finished_style="bright_green"),
            TextColumn("[progress.percentage]"),
            TextColumn("[cyan]{task.completed}[/]/{task.total}"),
            TimeElapsedColumn(),
            TextColumn("[dim]eta {task.fields[eta]}[/]"),
            expand=True,
        )
        self._task_id = self.progress.add_task("crossing", total=total, eta="-")

    # -- state ----------------------------------------------------------------

    def add(self, result: ProxyResult) -> None:
        self.done += 1
        self.recent.appendleft(result)
        if result.alive:
            self.alive += 1
            self.by_scheme[result.detected_scheme or "?"] += 1
            self.by_anon[result.anonymity.value] += 1
            if result.https_capable:
                self.tls += 1
            if result.latency_ms is not None:
                self._lat_sum += result.latency_ms
                self._lat_n += 1
        else:
            self.dead += 1

        elapsed = max(time.monotonic() - self.start_ts, 0.001)
        rate = self.done / elapsed
        remaining = self.total - self.done
        eta = f"{remaining / rate:0.0f}s" if rate > 0 else "-"
        self.progress.update(self._task_id, completed=self.done, eta=eta)

    # -- frame ------------------------------------------------------------------

    def _stats_grid(self) -> Table:
        avg = round(self._lat_sum / self._lat_n) if self._lat_n else None
        cells = [
            ("done", f"{self.done}/{self.total}", "white"),
            ("alive", f"{self.alive}", "bright_green"),
            ("dead", f"{self.dead}", "red"),
            ("elite", f"{self.by_anon.get('elite', 0)}", "#ffd700"),
            ("anon", f"{self.by_anon.get('anonymous', 0)}", "bright_cyan"),
            ("transp", f"{self.by_anon.get('transparent', 0)}", "dark_orange"),
            ("socks5", f"{self.by_scheme.get('socks5', 0)}", "bright_magenta"),
            ("socks4", f"{self.by_scheme.get('socks4', 0)}", "yellow"),
            ("http", f"{self.by_scheme.get('http', 0)}", "bright_cyan"),
            ("tun", f"{self.tls}", "bright_green"),
            ("avg ms", fmt_ms(avg), "white"),
            ("exits", f"{len({r.exit_ip for r in self.recent if r.exit_ip})}", "dim"),
        ]
        grid = Table.grid(padding=(0, 2))
        for _ in cells:
            grid.add_column(justify="center")
        grid.add_row(*[Text(label.upper(), style="dim") for label, _, _ in cells])
        grid.add_row(*[Text(value, style=style) for _, value, style in cells])
        return grid

    def _recent_table(self) -> Table:
        table = Table(box=None, header_style="bold dim", padding=(0, 1), expand=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("PROXY", style="white", overflow="crop", max_width=32)
        table.add_column("TYPE", width=7)
        table.add_column("TLS", width=4)
        table.add_column("RESULT", width=6)
        table.add_column("LATENCY", width=8, justify="right")
        table.add_column("ANONYMITY", width=12)
        table.add_column("EXIT IP", style="dim", overflow="crop")
        for i, r in enumerate(self.recent, 1):
            p = r.proxy
            shown = p.endpoint + (f" @{p.username}" if p.username else "")
            if r.alive:
                tls = Text("✔", style="bright_green") if r.https_capable else Text("-", style="dim")
                table.add_row(
                    str(i), shown[:38], scheme_chip(r.detected_scheme), tls,
                    Text("ALIVE", style=STATUS_STYLE[Status.ALIVE]),
                    fmt_ms(r.latency_ms), anon_chip(r.anonymity), r.exit_ip or "-",
                )
            else:
                table.add_row(
                    str(i), shown[:38], Text("-", style="dim"), Text("-", style="dim"),
                    Text("DEAD", style=STATUS_STYLE[Status.DEAD]), "-",
                    Text("-", style="dim"), Text((r.error or "")[:24], style="red"),
                )
        return table

    def frame(self) -> Group:
        header = Panel(
            Group(Text.from_markup(BANNER), Text("")),
            subtitle=f"[dim italic]{TAGLINE}[/]",
            subtitle_align="right",
            border_style="bright_cyan",
            padding=(1, 2),
        )
        return Group(
            header,
            Text.from_markup(self.meta),
            Text(""),
            self.progress,
            Text(""),
            self._stats_grid(),
            Text(""),
            self._recent_table(),
        )


# ---------------------------------------------------------------------------
# final summary / report

def _big_numbers(summary: dict) -> Table:
    alive_pct = f"{summary['alive'] / summary['total'] * 100:.1f}%" if summary["total"] else "0%"
    cells = [
        ("crossed", f"{summary['alive']}/{summary['total']}", "bright_green"),
        ("survival", alive_pct, "white"),
        ("elite", str(summary["anonymity"].get("elite", 0)), "#ffd700"),
        ("avg latency", fmt_ms(summary["avg_latency_ms"]), "white"),
        ("avg speed", fmt_kbps(summary["avg_speed_kbps"]), "bright_cyan"),
        ("unique exits", str(summary["unique_exit_ips"]), "white"),
    ]
    grid = Table.grid(padding=(1, 3))
    for _ in cells:
        grid.add_column(justify="center")
    grid.add_row(*[Text(value, style=style) for _, value, style in cells])
    grid.add_row(*[Text(label.upper(), style="dim") for label, _, _ in cells])
    return grid


def _grade_panel(summary: dict) -> Panel:
    grades = summary["grades"]
    peak = max(grades.values()) if grades else 0
    lines = []
    for g in ("S", "A", "B", "C", "D", "F"):
        n = grades.get(g, 0)
        line = Text()
        line.append(f" {g} ", style=GRADE_STYLE[g])
        line.append(" ")
        line.append(_bar(n, peak), style=GRADE_STYLE[g])
        line.append(f" {n}")
        lines.append(line)
    return Panel(Group(*lines), title="[bold]GRADES[/]", border_style="grey37", padding=(1, 2))


def _dist_table(title: str, data: dict, palette: dict) -> Panel:
    table = Table(box=None, padding=(0, 1))
    table.add_column(style="bold")
    table.add_column(justify="right")
    for key, n in sorted(data.items(), key=lambda kv: -kv[1]):
        label = str(key).upper() if key else "?"
        style = palette.get(str(key), "white")
        table.add_row(Text(label, style=style), str(n))
    return Panel(table, title=f"[bold]{title}[/]", border_style="grey37", padding=(1, 2))


def _top_table(results: list[ProxyResult], limit: int = 12) -> Panel:
    alive = [r for r in results if r.alive]
    alive.sort(key=lambda r: (GRADE_RANK.get(r.grade, 9), r.latency_ms or 9_999_999))
    table = Table(box=None, header_style="bold dim", padding=(0, 1), expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("GRADE", width=5)
    table.add_column("PROXY")
    table.add_column("TYPE", width=7)
    table.add_column("LATENCY", justify="right", width=8)
    table.add_column("ANONYMITY", width=12)
    table.add_column("SPEED", justify="right", width=10)
    table.add_column("GEO", style="dim")
    for i, r in enumerate(alive[:limit], 1):
        geo = ", ".join(filter(None, [r.city, r.country_code])) or "-"
        table.add_row(
            str(i), grade_chip(r.grade), r.proxy.url(r.detected_scheme)[:52],
            scheme_chip(r.detected_scheme), fmt_ms(r.latency_ms),
            anon_chip(r.anonymity), fmt_kbps(r.speed_kbps), geo,
        )
    return Panel(table, title="[bold]BEST OF THE CROSSING[/]",
                 border_style="bright_cyan", padding=(1, 2))


def final_summary(results: list[ProxyResult], exports: Optional[dict[str, str]] = None,
                  elapsed: Optional[float] = None, heading: str = "THE CROSSING IS COMPLETE") -> Group:
    summary = build_summary(results)
    parts: list[Any] = [
        Panel(Text.from_markup(BANNER), subtitle=f"[dim italic]{TAGLINE}[/]", subtitle_align="right",
              border_style="bright_cyan", padding=(1, 2)),
        Panel(_big_numbers(summary), border_style="grey37", padding=(1, 2)),
        Columns([
            _grade_panel(summary),
            _dist_table("PROTOCOLS", summary["schemes"], SCHEME_STYLE),
            _dist_table("ANONYMITY", summary["anonymity"], ANON_STYLE),
        ], equal=True, expand=True),
        _top_table(results),
    ]
    if elapsed is not None:
        parts.append(Text(f" elapsed {elapsed:0.1f}s", style="dim"))
    if exports:
        listing = "\n".join(f" [dim]{name:<22}[/] [cyan]{path}[/]" for name, path in exports.items())
        parts.append(Panel(Text.from_markup(listing), title="[bold]ARTIFACTS[/]",
                           border_style="grey37", padding=(1, 2)))
    parts.append(Text(f" {heading} — styx v{__version__}", style="bold #ffd700"))
    return Group(*parts)
