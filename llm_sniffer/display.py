"""AFL-fuzz style terminal display for LLM traffic captures."""

import time
import threading
from datetime import datetime, timedelta
from collections import deque
from .capture import LLMCapture
from .filter import FilterConfig

try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.console import Console, Group
    from rich.text import Text
    from rich import box
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ─── AFL-fuzz style color scheme ─────────────────────────────────────────────
# afl-fuzz uses a dark terminal with green/red/yellow highlights
# Main colors: green (good), red (crashes/errors), yellow (warnings), cyan (info)

BANNER = r"""
    ██╗     ██╗     ███╗   ███╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
    ██║     ██║     ████╗ ████║    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
    ██║     ██║     ██╔████╔██║    ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
    ██║     ██║     ██║╚██╔╝██║    ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
    ███████╗███████╗██║ ╚═╝ ██║    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝     ╚═╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
"""

HEADER_BAR = """
┌─ process timing ────────────────────────────────────┬─ overall results ─────┬─ model breakdown ────────────────────────────────────┐
│        run time : {uptime:<33s}│  requests done : {total_reqs:<5}  │ {model_lines} │
│   last new find : {last_find:<33s}│  total tokens  : {total_tokens:<5}  │                                                     │
│  capture speed : {speed:<33s}│  errors        : {total_errors:<5}  │                                                     │
└─────────────────────────────────────────────────────┴───────────────────────┴─────────────────────────────────────────────────────┘
"""


class DisplayManager:
    """Manages the afl-fuzz style terminal display."""

    def __init__(self, filter_config: FilterConfig, no_tui: bool = False):
        self.filter_config = filter_config
        self.no_tui = no_tui
        self.console = Console() if RICH_AVAILABLE else None
        self._live = None
        self._recent_captures: deque = deque(maxlen=100)
        self._last_find_time: float = time.time()
        self._lock = threading.Lock()
        self._running = False
        self._refresh_thread = None

    def start(self):
        """Start the live display."""
        if self.no_tui or not RICH_AVAILABLE:
            if not RICH_AVAILABLE:
                print("  [WARN] 'rich' library not installed. Install with: pip install rich")
            print("  [INFO] Running in plain-text mode.")
            self._running = True
            return

        self._running = True
        self._live = Live(
            self._build_layout({}),
            console=self.console,
            refresh_per_second=4,
            screen=True,
        )
        self._live.start()

    def stop(self):
        """Stop the live display."""
        self._running = False
        if self._live:
            self._live.stop()

    def add_capture(self, cap: LLMCapture, stats: dict):
        """Add a capture to the recent list for display."""
        with self._lock:
            self._recent_captures.appendleft(cap)  # newest first
            if not cap.error:
                self._last_find_time = time.time()

        # Print to stdout in plain-text mode
        if self.no_tui and self._running:
            status = f"[{cap.status_code}]" if cap.status_code else "[...]"
            latency = f"{cap.latency_ms:.0f}ms" if cap.latency_ms else "---"
            tokens = str(cap.total_tokens) if cap.total_tokens else "---"
            if cap.error:
                summary = f"ERROR: {cap.error[:100]}"
            elif cap.response_choices:
                summary = cap.response_choices[0].get("content", "")[:100].replace("\n", " ")
            else:
                user_msgs = [m.get("content", "") for m in cap.request_messages if m.get("role") == "user"]
                summary = (user_msgs[-1][:100] if user_msgs else "(streaming)").replace("\n", " ")
            print(f"  [{cap.id}] {status} {cap.model} | {latency} | {tokens}tok | {summary}")

    def refresh(self, stats: dict):
        """Refresh the display with latest stats."""
        if not self._running:
            return
        if self._live:
            self._live.update(self._build_layout(stats))

    def _build_layout(self, stats: dict) -> Layout:
        """Build the full afl-fuzz style layout."""
        layout = Layout()

        # Split into sections
        layout.split(
            Layout(name="header", size=3),
            Layout(name="banner", size=8),
            Layout(name="stats_bar", size=9),
            Layout(name="spacer", size=1),
            Layout(name="captures"),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self._build_header())
        layout["banner"].update(self._build_banner(stats))
        layout["stats_bar"].update(self._build_stats_bar(stats))
        layout["spacer"].update(Text(""))
        layout["captures"].update(self._build_captures_table())
        layout["footer"].update(self._build_footer(stats))

        return layout

    def _build_header(self) -> Panel:
        """Build the top header bar."""
        text = Text(" LLM Sniffer v0.1.0 ", style="bold white on dark_green")
        text.append(" - LLM API traffic capture tool", style="green")
        text.append(" | ", style="dim")
        text.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="cyan")
        return Panel(text, box=box.HEAVY, style="green")

    def _build_banner(self, stats: dict) -> Panel:
        """Build the banner display."""
        banner_text = Text(BANNER, style="bold green")
        return Panel(banner_text, box=box.SQUARE, style="green")

    def _build_stats_bar(self, stats: dict) -> Panel:
        """Build the main stats bar - afl-fuzz style."""
        uptime_sec = stats.get("uptime", 0)
        uptime_str = str(timedelta(seconds=int(uptime_sec)))
        last_find = str(timedelta(seconds=int(time.time() - self._last_find_time))) + " ago"

        total_reqs = stats.get("total_requests", 0)
        speed = f"{total_reqs / max(1, uptime_sec):.2f}/sec"

        total_tokens = stats.get("total_tokens", 0)
        total_errors = stats.get("total_errors", 0)

        # Model breakdown
        models = stats.get("models_seen", {})
        model_items = sorted(models.items(), key=lambda x: x[1], reverse=True)[:4]
        model_lines = []
        for i, (model, count) in enumerate(model_items):
            bar_len = min(20, count * 2)
            bar = "█" * bar_len
            model_lines.append(f"  {model:<20s} : {count:<4} {bar}")

        # Pad model_lines to 4
        while len(model_lines) < 4:
            model_lines.append(" " * 55)

        # Use a simple Table for the stats bar to match afl-fuzz density
        table = Table(
            show_header=False,
            box=box.HEAVY_EDGE,
            style="green",
            padding=0,
            collapse_padding=True,
        )
        table.add_column("timing", width=55)
        table.add_column("results", width=25)
        table.add_column("models", width=55)

        timing_lines = [
            f"  run time     : {uptime_str}",
            f"  last capture : {last_find}",
            f"  speed        : {speed}",
        ]
        result_lines = [
            f"  captures : {total_reqs}",
            f"  tokens   : {total_tokens:,}",
            f"  errors   : {total_errors}",
        ]

        for i in range(4):
            t = timing_lines[i] if i < len(timing_lines) else ""
            r = result_lines[i] if i < len(result_lines) else ""
            m = model_lines[i] if i < len(model_lines) else ""
            table.add_row(t, r, m)

        return Panel(table, box=box.SQUARE, style="green", title="process timing / overall results / model breakdown")

    def _build_captures_table(self) -> Panel:
        """Build the scrollable captures table."""
        table = Table(
            show_header=True,
            box=box.SQUARE,
            style="green",
            header_style="bold white on dark_green",
            padding=0,
        )
        table.add_column("#", width=9, style="dim")
        table.add_column("Time", width=15, style="cyan")
        table.add_column("Model", width=22, style="yellow")
        table.add_column("Status", width=8)
        table.add_column("Latency", width=10)
        table.add_column("Tokens", width=10)
        table.add_column("Messages", width=10)
        table.add_column("API", width=28, style="dim")
        table.add_column("Summary", width=40)

        with self._lock:
            display_captures = list(self._recent_captures)[:30]  # show last 30

        for cap in display_captures:
            time_str = datetime.fromtimestamp(cap.timestamp).strftime("%H:%M:%S")

            # Status with color
            if cap.error:
                status = Text(str(cap.status_code or "ERR"), style="bold red")
            elif cap.status_code and cap.status_code >= 400:
                status = Text(str(cap.status_code), style="bold red")
            elif cap.status_code == 200:
                status = Text("200 OK", style="bold green")
            else:
                status = Text(str(cap.status_code or "---"), style="yellow")

            # Latency
            latency_str = f"{cap.latency_ms:.0f}ms" if cap.latency_ms else "---"

            # Tokens
            token_str = str(cap.total_tokens) if cap.total_tokens else "---"

            # Message count
            msg_str = str(len(cap.request_messages))

            # Summary (first response choice or error)
            if cap.error:
                summary = Text(cap.error[:60], style="red")
            elif cap.response_choices:
                content = cap.response_choices[0].get("content", "")[:60]
                summary = Text(content.replace("\n", " ")[:60], style="white")
            else:
                # Show last user message as summary
                user_msgs = [
                    m.get("content", "")
                    for m in cap.request_messages
                    if m.get("role") == "user"
                ]
                if user_msgs:
                    summary = Text(
                        user_msgs[-1][:60].replace("\n", " "), style="dim white"
                    )
                else:
                    summary = Text("(streaming)", style="dim")

            table.add_row(
                cap.id,
                time_str,
                cap.model[:20],
                status,
                latency_str,
                token_str,
                msg_str,
                cap.base_url[:26],
                summary,
            )

        return Panel(
            table,
            box=box.SQUARE,
            style="green",
            title=f"captures (showing last {len(display_captures)})",
        )

    def _build_footer(self, stats: dict) -> Panel:
        """Build the footer with controls and filter info."""
        filter_info = stats.get("filter_summary", "none")
        listen_addr = stats.get("listen_addr", "---")
        log_dir = stats.get("log_dir", "---")

        text = Text()
        text.append(f"  Listening: {listen_addr}  ", style="bold green")
        text.append(f"|  Filters: {filter_info}  ", style="yellow")
        text.append(f"|  Logs: {log_dir}  ", style="dim")
        text.append(f"|  Press ", style="white")
        text.append("Ctrl+C", style="bold red")
        text.append(" to stop  ", style="white")

        return Panel(text, box=box.HEAVY, style="green")
