"""Core reverse proxy server - intercepts LLM API traffic."""

import asyncio
import time
import aiohttp
from aiohttp import web
from .capture import (
    LLMCapture,
    create_capture,
    update_capture_with_response,
)
from .filter import FilterConfig
from .logger import CaptureLogger
from .display import DisplayManager


class LLMProxy:
    """Async reverse proxy that captures LLM API calls."""

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8888,
        default_target: str = "https://api.openai.com",
        filter_config: FilterConfig = None,
        log_dir: str = "./llm_sniffer_logs",
        no_tui: bool = False,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.default_target = default_target
        self.filter_config = filter_config or FilterConfig()
        self.logger = CaptureLogger(log_dir)
        self.display = DisplayManager(self.filter_config, no_tui=no_tui)

        # Stats tracking
        self._captures: list[LLMCapture] = []
        self._lock = asyncio.Lock()
        self._start_time = time.time()
        self._total_requests = 0
        self._total_errors = 0
        self._total_tokens = 0
        self._models_seen: dict[str, int] = {}
        self._urls_seen: dict[str, int] = {}

    async def _update_stats(self, cap: LLMCapture):
        async with self._lock:
            self._captures.append(cap)
            self._total_requests += 1
            if cap.error:
                self._total_errors += 1
            self._total_tokens += cap.total_tokens
            self._models_seen[cap.model] = self._models_seen.get(cap.model, 0) + 1
            self._urls_seen[cap.base_url] = self._urls_seen.get(cap.base_url, 0) + 1

            # Keep only last 1000 captures in memory
            if len(self._captures) > 1000:
                self._captures = self._captures[-500:]

            # Update display with new capture
            self.display.add_capture(cap, self._get_stats_snapshot())

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
            "capture_count": len(self._captures),
        }

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        """Handle incoming proxy request."""
        start_time = time.time()

        # Read request body
        body = await request.read()

        # Determine target URL
        # The client sends requests to us with the path like /v1/chat/completions
        # We need to forward to the actual API
        # The actual base_url is extracted from the request - we try to detect it
        target_base_url = self._detect_target_url(request, body)
        target_url = target_base_url.rstrip("/") + "/" + request.path.lstrip("/")

        # For OpenAI-compatible APIs, the path usually starts with /v1/
        # We need the query string too
        if request.query_string:
            target_url += "?" + request.query_string

        # Create capture record
        cap = create_capture(
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            body=body,
            base_url=target_base_url,
        )

        # Forward the request
        try:
            async with aiohttp.ClientSession() as session:
                # Prepare headers (remove host, add forwarding info)
                fwd_headers = dict(request.headers)
                fwd_headers.pop("Host", None)
                # Don't forward hop-by-hop headers
                for h in ["Connection", "Transfer-Encoding", "Upgrade"]:
                    fwd_headers.pop(h, None)
                # Ensure content-type is set
                if body and "Content-Type" not in fwd_headers:
                    fwd_headers["Content-Type"] = "application/json"

                async with session.request(
                    method=request.method,
                    url=target_url,
                    headers=fwd_headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=300),
                ) as resp:
                    # Check if this is a streaming response
                    content_type = resp.headers.get("Content-Type", "").lower()
                    is_stream = "text/event-stream" in content_type or cap.stream

                    # Build response headers for client
                    resp_headers = {
                        k: v
                        for k, v in resp.headers.items()
                        if k.lower()
                        not in (
                            "transfer-encoding",
                            "content-encoding",
                            "connection",
                        )
                    }
                    client_resp = web.StreamResponse(
                        status=resp.status,
                        headers=resp_headers,
                    )
                    await client_resp.prepare(request)

                    if is_stream:
                        # Stream: forward chunks as they arrive, buffer for logging
                        chunks = []
                        async for chunk in resp.content.iter_chunked(8192):
                            chunks.append(chunk)
                            await client_resp.write(chunk)
                        await client_resp.write_eof()
                        resp_body = b"".join(chunks)
                    else:
                        # Non-streaming: read entire response, then forward
                        resp_body = await resp.read()
                        await client_resp.write(resp_body)
                        await client_resp.write_eof()

                    latency = (time.time() - start_time) * 1000

                    # Update capture with response
                    update_capture_with_response(cap, resp.status, resp_body, latency)

        except asyncio.TimeoutError:
            cap.error = "Timeout after 300s"
            cap.latency_ms = (time.time() - start_time) * 1000
            cap.status_code = 504
            client_resp = web.StreamResponse(status=504)
            await client_resp.prepare(request)
            await client_resp.write(b'{"error": "Gateway Timeout"}')
            await client_resp.write_eof()

        except aiohttp.ClientError as e:
            cap.error = f"Connection error: {str(e)}"
            cap.latency_ms = (time.time() - start_time) * 1000
            cap.status_code = 502
            client_resp = web.StreamResponse(status=502)
            await client_resp.prepare(request)
            await client_resp.write(b'{"error": "Bad Gateway"}')
            await client_resp.write_eof()

        except Exception as e:
            cap.error = f"Proxy error: {str(e)}"
            cap.latency_ms = (time.time() - start_time) * 1000
            cap.status_code = 500
            client_resp = web.StreamResponse(status=500)
            await client_resp.prepare(request)
            await client_resp.write(b'{"error": "Internal Proxy Error"}')
            await client_resp.write_eof()

        # Update stats and log
        await self._update_stats(cap)
        self.logger.log_capture(cap, self.filter_config)

        return client_resp

    def _detect_target_url(self, request: web.Request, body: bytes) -> str:
        """Detect the target LLM API base URL from the request."""
        # Strategy 1: Check for custom header
        x_target = request.headers.get("X-LLM-Target") or request.headers.get("x-llm-target")
        if x_target:
            return x_target

        # Strategy 2: Check for x-base-url header (used by some proxies)
        x_base = request.headers.get("X-Base-URL") or request.headers.get("x-base-url")
        if x_base:
            return x_base

        # Strategy 3: Use the configured default target
        return self.default_target

    async def start(self):
        """Start the proxy server."""
        app = web.Application()
        # Catch all routes - we proxy everything
        app.router.add_route("*", "/{tail:.*}", self.handle_request)

        # Start display
        self.display.start()

        print(f"\n  LLM Sniffer listening on http://{self.listen_host}:{self.listen_port}")
        print(f"  Set your LLM client base_url to: http://localhost:{self.listen_port}/v1")
        print(f"  Add header 'X-LLM-Target: https://your-api.com' to specify target API")
        print(f"  (Default target: {self.default_target})")
        print(f"  Logs: {self.logger.log_dir}")
        print(f"  Press Ctrl+C to stop\n")

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.listen_host, self.listen_port)
        await site.start()

        try:
            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)
                self.display.refresh(self._get_stats_snapshot())
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()
            self.display.stop()

    def run(self):
        """Run the proxy server (blocking)."""
        try:
            asyncio.run(self.start())
        except KeyboardInterrupt:
            self.display.stop()
            print("\n\n  LLM Sniffer stopped.")
