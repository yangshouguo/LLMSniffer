"""Entry point and CLI for LLM Sniffer."""

import argparse
import sys
from .proxy import LLMProxy
from .mitm_mode import MitmProxyRunner
from .filter import FilterConfig
from .system_proxy import (
    available as sysproxy_available,
    enable_system_proxy as sysproxy_enable,
    disable_system_proxy as sysproxy_disable,
    print_client_instructions,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="llm-sniffer",
        description="LLM Sniffer - Capture and display LLM API traffic (like wireshark for LLMs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reverse proxy mode (change client base_url)
  llm-sniffer                       # default: forward to api.openai.com
  llm-sniffer -p 9999 -t https://api.anthropic.com

  # Non-intrusive mitm mode + auto system proxy (catches ALL desktop apps)
  llm-sniffer --mode mitm --system-proxy
  # Now Claude Desktop, Cursor, Copilot all route through the sniffer
  # automatically - no per-app configuration needed!

  # Filter to only show gpt-4 calls
  llm-sniffer --filter-model "gpt-4*"

  # Exclude certain models
  llm-sniffer --exclude-model "gpt-3.5*"

  # Regex mode
  llm-sniffer --pattern-mode regex --filter-model "gpt-4|claude"

Client Setup (reverse mode):
  1. Set your LLM client's base_url to: http://localhost:8888/v1
  2. The proxy forwards to --target (default: https://api.openai.com)
  3. Or add header 'X-LLM-Target: https://your-api.com' to override

Client Setup (mitm mode):
  1. export HTTPS_PROXY=http://localhost:8888
  2. Run your LLM app normally - NO code changes needed!
  3. Add --system-proxy to catch desktop apps automatically
""",
    )

    # Server options
    server = parser.add_argument_group("Server Options")
    server.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to listen on (default: 0.0.0.0)",
    )
    server.add_argument(
        "-p", "--port",
        type=int,
        default=8888,
        help="Port to listen on (default: 8888)",
    )
    server.add_argument(
        "-t", "--target",
        default="https://api.openai.com",
        help="Default target API base URL (reverse mode only, default: https://api.openai.com)",
    )
    server.add_argument(
        "-m", "--mode",
        choices=["reverse", "mitm"],
        default="reverse",
        help="Proxy mode: 'reverse' (change base_url) or 'mitm' (set HTTPS_PROXY, zero code changes) (default: reverse)",
    )
    server.add_argument(
        "--system-proxy",
        action="store_true",
        help="[mitm mode] Set macOS system proxy automatically - catches desktop apps (Claude Desktop, Cursor, Copilot, etc.)",
    )

    # Filter options
    filt = parser.add_argument_group("Filter Options")
    filt.add_argument(
        "--filter-url",
        default="",
        help="Only show captures matching this base URL pattern (glob/regex)",
    )
    filt.add_argument(
        "--filter-model",
        default="",
        help="Only show captures matching this model name pattern (glob/regex)",
    )
    filt.add_argument(
        "--filter-apikey",
        default="",
        help="Only show captures matching this API key pattern (glob/regex)",
    )
    filt.add_argument(
        "--exclude-url",
        default="",
        help="Hide captures matching this base URL pattern",
    )
    filt.add_argument(
        "--exclude-model",
        default="",
        help="Hide captures matching this model pattern",
    )
    filt.add_argument(
        "--exclude-apikey",
        default="",
        help="Hide captures matching this API key pattern",
    )
    filt.add_argument(
        "--pattern-mode",
        choices=["glob", "regex", "exact"],
        default="glob",
        help="Pattern matching mode for filters (default: glob)",
    )

    # Logging options
    log = parser.add_argument_group("Logging Options")
    log.add_argument(
        "-o", "--output",
        default="./llm_sniffer_logs",
        help="Directory for log files (default: ./llm_sniffer_logs)",
    )

    # Display options
    disp = parser.add_argument_group("Display Options")
    disp.add_argument(
        "--no-tui",
        action="store_true",
        help="Disable TUI, only print to stdout",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Build filter config
    filter_config = FilterConfig.from_args(args)

    if args.mode == "mitm":
        runner = MitmProxyRunner(
            listen_host=args.host,
            listen_port=args.port,
            filter_config=filter_config,
            log_dir=args.output,
            no_tui=args.no_tui,
            system_proxy=args.system_proxy,
        )
    else:
        runner = LLMProxy(
            listen_host=args.host,
            listen_port=args.port,
            default_target=args.target,
            filter_config=filter_config,
            log_dir=args.output,
            no_tui=args.no_tui,
        )

    runner.run()


if __name__ == "__main__":
    main()
