"""Non-intrusive mode using mitmproxy as HTTP/HTTPS forward proxy.

Usage:
    llm-sniffer --mode mitm

Then set environment variables in the client:
    export HTTPS_PROXY=http://localhost:8888
    export HTTP_PROXY=http://localhost:8888

No application code changes needed. All LLM SDKs (OpenAI, Anthropic,
LangChain, etc.) automatically route through the proxy.
"""

import asyncio
import json
import sys
import time
import queue
import threading
from pathlib import Path

from .capture import (
    LLMCapture,
    create_capture,
    update_capture_with_response,
    extract_api_key,
)
from .filter import FilterConfig
from .logger import CaptureLogger
from .display import DisplayManager

# ── mitmproxy addon ──────────────────────────────────────────────────────────


class LLMSnifferMitmAddon:
    """mitmproxy addon that intercepts LLM API calls.

    This addon runs inside mitmproxy's event loop. It detects LLM API
    requests/responses and pushes parsed captures into a thread-safe queue.
    """

    def __init__(self, capture_queue: queue.Queue):
        self.capture_queue = capture_queue

    def request(self, flow) -> None:
        """Called when mitmproxy receives a request."""
        # Store the start time for latency calculation
        flow.metadata["llm_sniff_start"] = time.time()

    def response(self, flow) -> None:
        """Called when mitmproxy receives a response."""
        if not self._is_llm_call(flow):
            return

        cap = self._parse_flow(flow)
        if cap:
            self.capture_queue.put(cap)

    def _is_llm_call(self, flow) -> bool:
        """Check if this HTTP flow is an LLM API call."""
        path = flow.request.path or ""

        # OpenAI compatible paths
        llm_paths = [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/messages",  # Anthropic format
            "/chat/completions",
            "/completions",
            "/embeddings",
            "/messages",
        ]
        for p in llm_paths:
            if p in path:
                return True

        # Also check if it looks like an LLM API by content-type and body
        content_type = flow.request.headers.get("content-type", "").lower()
        if "json" in content_type and flow.request.content:
            try:
                body = json.loads(flow.request.content)
                # Has model + messages = likely LLM call
                if "model" in body and "messages" in body:
                    return True
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        return False

    def _parse_flow(self, flow) -> LLMCapture:
        """Convert a mitmproxy flow into an LLMCapture."""
        req = flow.request
        resp = flow.response

        start_time = flow.metadata.get("llm_sniff_start", time.time())
        latency_ms = (time.time() - start_time) * 1000

        # Extract target base URL
        base_url = f"{req.scheme}://{req.host}:{req.port}" if req.port else f"{req.scheme}://{req.host}"

        # Create capture from request
        headers = dict(req.headers)
        body = req.content or b"{}"

        cap = create_capture(
            method=req.method,
            path=req.path,
            headers=headers,
            body=body,
            base_url=base_url,
        )

        # Update with response
        resp_body = resp.content or b"{}"
        update_capture_with_response(cap, resp.status_code, resp_body, latency_ms)

        return cap


# ── mitmproxy runner ─────────────────────────────────────────────────────────


class MitmProxyRunner:
    """Runs mitmproxy in a background thread, with TUI in the main thread."""

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8888,
        filter_config: FilterConfig = None,
        log_dir: str = "./llm_sniffer_logs",
        no_tui: bool = False,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.filter_config = filter_config or FilterConfig()
        self.logger = CaptureLogger(log_dir)
        self.display = DisplayManager(self.filter_config, no_tui=no_tui)
        self._capture_queue: queue.Queue = queue.Queue()
        self._running = False
        self._master = None

        # Stats tracking
        self._start_time = time.time()
        self._total_requests = 0
        self._total_errors = 0
        self._total_tokens = 0
        self._models_seen: dict[str, int] = {}
        self._urls_seen: dict[str, int] = {}

    def _get_stats_snapshot(self) -> dict:
        return {
            "uptime": time.time() - self._start_time,
            "total_requests": self._total_requests,
            "total_errors": self._total_errors,
            "total_tokens": self._total_tokens,
            "models_seen": dict(self._models_seen),
            "urls_seen": dict(self._urls_seen),
            "filter_summary": self.filter_config.summary(),
            "listen_addr": f"{self.listen_host}:{self.listen_port}",
            "log_dir": str(self.logger.log_dir),
            "capture_count": self._total_requests,
        }

    def _process_capture(self, cap: LLMCapture):
        """Process a capture from the queue."""
        self._total_requests += 1
        if cap.error:
            self._total_errors += 1
        self._total_tokens += cap.total_tokens
        self._models_seen[cap.model] = self._models_seen.get(cap.model, 0) + 1
        self._urls_seen[cap.base_url] = self._urls_seen.get(cap.base_url, 0) + 1

        # Log to file (always, regardless of filter)
        self.logger.log_capture(cap, self.filter_config)

        # Update display
        self.display.add_capture(cap, self._get_stats_snapshot())

    def run(self):
        """Start the mitmproxy-based sniffer (blocking call)."""
        try:
            from mitmproxy.options import Options
            from mitmproxy.master import Master as MitmMaster
            from mitmproxy.addons import default_addons
        except ImportError:
            print("\n  ERROR: mitmproxy is required for --mode mitm")
            print("  Install with: pip install mitmproxy")
            print("  Then run: llm-sniffer --mode mitm\n")
            sys.exit(1)

        self._running = True

        # --- Start mitmproxy in background thread ---
        # mitmproxy needs its own event loop. We create everything
        # inside the thread to satisfy asyncio requirements.
        addon = LLMSnifferMitmAddon(self._capture_queue)

        def _run_mitm():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            opts = Options(
                listen_host=self.listen_host,
                listen_port=self.listen_port,
                mode=["regular"],
            )
            master = MitmMaster(opts, event_loop=loop)
            master.addons.add(*default_addons())  # Required by mitmproxy
            master.addons.add(addon)
            self._master = master
            loop.run_until_complete(master.run())

        mitm_thread = threading.Thread(target=_run_mitm, daemon=True, name="mitmproxy")
        mitm_thread.start()

        # Wait for mitmproxy to start
        time.sleep(1)

        print(f"\n  LLM Sniffer [mitm mode] listening on http://{self.listen_host}:{self.listen_port}")
        print(f"  Set in your client environment:")
        print(f"    export HTTPS_PROXY=http://localhost:{self.listen_port}")
        print(f"    export HTTP_PROXY=http://localhost:{self.listen_port}")
        print(f"  Then run your LLM application normally - no code changes needed!")
        print(f"  Logs: {self.logger.log_dir}")
        print(f"  Press Ctrl+C to stop\n")

        # --- Start TUI on main thread ---
        self.display.start()

        try:
            while self._running:
                # Process captures from queue
                try:
                    cap = self._capture_queue.get(timeout=1)
                    self._process_capture(cap)
                except queue.Empty:
                    pass

                # Refresh TUI
                self.display.refresh(self._get_stats_snapshot())

        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self.display.stop()
            if self._master:
                self._master.shutdown()
            print("\n\n  LLM Sniffer stopped.")
