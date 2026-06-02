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
import signal
import socket
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
from .system_proxy import (
    available as sysproxy_available,
    enable_system_proxy as sysproxy_enable,
    disable_system_proxy as sysproxy_disable,
    print_client_instructions,
)

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
        resp_body = resp.content or b""
        if not resp_body:
            cap.error = "Empty response body (possibly interrupted stream)"
            cap.status_code = resp.status_code
            cap.latency_ms = latency_ms
        else:
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
        system_proxy: bool = False,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.filter_config = filter_config or FilterConfig()
        self.logger = CaptureLogger(log_dir)
        self.system_proxy = system_proxy
        self.display = DisplayManager(
            self.filter_config, mode="mitm",
            listen_port=listen_port, no_tui=no_tui,
        )
        self._capture_queue: queue.Queue = queue.Queue()
        self._running = False
        self._master = None
        self._mitm_error: Exception | None = None

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

    def _setup_mitm_cert(self):
        """Ensure mitmproxy CA cert exists and is trusted everywhere.

        macOS `security add-trusted-cert` handles system keychain
        (Safari, curl, etc.) but Python's ssl module uses its own
        trust bundle (certifi). We handle both.
        """
        import os
        import subprocess

        cert_dir = Path.home() / ".mitmproxy"
        cert_path = cert_dir / "mitmproxy-ca-cert.pem"

        # mitmproxy auto-generates the cert on first run
        if not cert_path.exists():
            print("  Generating mitmproxy CA certificate ...")
            cert_dir.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    [sys.executable, "-m", "mitmproxy", "--version"],
                    capture_output=True, timeout=10,
                )
            except Exception:
                pass

        if not cert_path.exists():
            return  # cert will be generated when mitm thread starts

        needs_macos = False
        needs_python = False

        # -- Check macOS keychain --
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["security", "verify-cert", "-c", str(cert_path)],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    needs_macos = True
            except Exception:
                needs_macos = True

        # -- Check Python certifi bundle --
        try:
            import certifi
            certifi_bundle = Path(certifi.where())
            mitm_cert_pem = cert_path.read_bytes()
            if mitm_cert_pem not in certifi_bundle.read_bytes():
                needs_python = True
        except ImportError:
            needs_python = True  # no certifi → fall back to SSL_CERT_FILE

        if needs_macos or needs_python:
            self._print_cert_trust_instructions(cert_path, needs_macos, needs_python)

    def _print_cert_trust_instructions(self, cert_path, needs_macos: bool, needs_python: bool):
        """Print OS-appropriate cert trust instructions."""
        cert_path_str = str(cert_path)

        print(f"\n  ╔══════════════════════════════════════════════════════════════════╗")
        print(f"  ║  mitmproxy CA cert needs to be trusted                         ║")
        print(f"  ╚══════════════════════════════════════════════════════════════════╝")

        if needs_macos:
            print(f"\n  ── macOS system trust (curl, Safari, Go apps, etc.) ──")
            print(f"  sudo security add-trusted-cert -d -p ssl {cert_path_str}")

        if needs_python:
            print(f"\n  ── Python trust (openai SDK, requests, urllib) ──")
            try:
                import certifi
                certifi_path = Path(certifi.where())
                mitm_cert_pem = Path(cert_path).read_bytes()
                existing = certifi_path.read_bytes()
                if mitm_cert_pem not in existing:
                    certifi_path.write_bytes(existing + b"\n" + mitm_cert_pem)
                    print(f"  ✓ Automatically added to certifi: {certifi_path}")
                else:
                    print(f"  ✓ Already in certifi: {certifi_path}")
            except (ImportError, PermissionError, OSError):
                print(f"  export SSL_CERT_FILE={cert_path_str}")

        # Node.js trust (Claude Code CLI — you are HERE)
        print(f"\n  ── Node.js trust (Claude Code CLI ⬅ you need this!) ──")
        print(f"  export NODE_EXTRA_CA_CERTS={cert_path_str}")

        print()

    @staticmethod
    def _wait_for_enter():
        """Block until user presses Enter."""
        print()
        try:
            input("  Press ENTER after you've set up the environment and certificates ...")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        print()

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

        # --- Ensure mitmproxy CA cert exists and is trusted ---
        self._setup_mitm_cert()

        # --- Optionally set macOS system proxy (catches desktop apps) ---
        if self.system_proxy and sysproxy_available():
            sysproxy_enable(self.listen_port)
        elif self.system_proxy:
            print("  ⚠ --system-proxy is only supported on macOS")

        # --- Start mitmproxy in background thread ---
        # mitmproxy needs its own event loop. We create everything
        # inside the thread to satisfy asyncio requirements.
        addon = LLMSnifferMitmAddon(self._capture_queue)

        def _run_mitm():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
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
            except Exception as e:
                self._mitm_error = e

        mitm_thread = threading.Thread(target=_run_mitm, daemon=True, name="mitmproxy")
        mitm_thread.start()

        # Wait for mitmproxy to start — socket health check instead of blind sleep
        self._wait_for_mitm_health(mitm_thread)

        if self._mitm_error:
            print(f"\n  ERROR: mitmproxy failed to start: {self._mitm_error}")
            sys.exit(1)

        print(f"\n  LLM Sniffer [mitm mode] listening on http://{self.listen_host}:{self.listen_port}")
        print(f"  Logs: {self.logger.log_dir}")
        # --- Show client setup guide ---
        print_client_instructions(self.listen_port)
        # --- Wait for user confirmation ---
        self._wait_for_enter()

        # --- Start TUI on main thread ---
        self.display.start()

        # Handle SIGTERM like SIGINT so cleanup runs in Docker/systemd contexts
        signal.signal(signal.SIGTERM, lambda signum, frame: self._handle_sigterm())

        try:
            while self._running:
                # Check if mitm thread is still alive
                if not mitm_thread.is_alive():
                    error_msg = f"mitmproxy thread died unexpectedly"
                    if self._mitm_error:
                        error_msg += f": {self._mitm_error}"
                    print(f"\n  ERROR: {error_msg}")
                    break

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
            if self.system_proxy and sysproxy_available():
                sysproxy_disable()
            print("\n\n  LLM Sniffer stopped.")

    def _wait_for_mitm_health(self, mitm_thread: threading.Thread):
        """Poll socket to confirm mitmproxy is listening, or detect early failure."""
        for attempt in range(10):
            if self._mitm_error:
                return  # thread failed, will be caught by caller
            if not mitm_thread.is_alive():
                return  # thread died before starting
            try:
                with socket.create_connection(
                    (self.listen_host, self.listen_port), timeout=0.5
                ):
                    return  # proxy is accepting connections
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
        # Timeout — check once more for a deferred error
        if not self._mitm_error and not mitm_thread.is_alive():
            self._mitm_error = RuntimeError("mitmproxy thread died before binding")

    def _handle_sigterm(self):
        """Trigger graceful shutdown on SIGTERM (Docker, systemd, CI)."""
        raise KeyboardInterrupt()
