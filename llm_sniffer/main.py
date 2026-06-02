"""Entry point and CLI for LLM Sniffer."""

import argparse
import sys
from .proxy import LLMProxy
from .filter import FilterConfig


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="llm-sniffer",
        description="LLM Sniffer - Capture and display LLM API traffic (like wireshark for LLMs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with defaults (proxies to api.openai.com)
  llm-sniffer

  # Custom port and target
  llm-sniffer --port 9999 --target https://api.anthropic.com

  # Filter to only show gpt-4 calls
  llm-sniffer --filter-model "gpt-4*"

  # Filter by API URL
  llm-sniffer --filter-url "*openai*"

  # Exclude certain models
  llm-sniffer --exclude-model "gpt-3.5*"

  # Regex mode
  llm-sniffer --pattern-mode regex --filter-model "gpt-4|claude"

Client Setup:
  1. Set your LLM client's base_url to: http://localhost:8888/v1
  2. The proxy will forward to --target (default: https://api.openai.com)
  3. Add header 'X-LLM-Target: https://your-api.com' for per-request override

  For OpenAI Python SDK:
    client = OpenAI(base_url="http://localhost:8888/v1", api_key="sk-...")

  For curl:
    curl http://localhost:8888/v1/chat/completions \\
      -H "Content-Type: application/json" \\
      -H "Authorization: Bearer sk-..." \\
      -H "X-LLM-Target: https://api.openai.com" \\
      -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
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
        help="Default target API base URL to forward requests to (default: https://api.openai.com)",
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

    # Build and run proxy
    proxy = LLMProxy(
        listen_host=args.host,
        listen_port=args.port,
        default_target=args.target,
        filter_config=filter_config,
        log_dir=args.output,
        no_tui=args.no_tui,
    )

    proxy.run()


if __name__ == "__main__":
    main()
