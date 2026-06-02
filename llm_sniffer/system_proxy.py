"""macOS system proxy management and transparent proxy (pf).

Set the system-wide HTTP/HTTPS proxy on macOS so desktop clients
like Claude Desktop, Cursor, VS Code, etc. automatically route
through the sniffer — no per-app configuration needed.
"""

import sys
import subprocess
import atexit
from typing import Optional
from pathlib import Path

_SYSTEM_PROXY_ACTIVE = False
_SYSTEM_PROXY_PORT = 0
# Saved previous proxy config so we can restore it on disable
_saved_proxy_config: dict = {}


def available() -> bool:
    """Check if we can manage system proxy on this platform."""
    return sys.platform == "darwin"


def _run_networksetup(*args: str) -> tuple[int, str]:
    """Run networksetup and return (returncode, stderr)."""
    try:
        result = subprocess.run(
            ["networksetup", *args],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode, result.stderr.strip()
    except (subprocess.TimeoutError, FileNotFoundError) as e:
        return -1, str(e)


def get_active_network_service() -> Optional[str]:
    """Detect the currently active network service name (e.g. 'Wi-Fi')."""
    try:
        result = subprocess.run(
            ["networksetup", "-listnetworkserviceorder"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.splitlines()
        # Prefer service on the default route
        route_result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        # Extract interface name (e.g. en0) from route table
        iface = None
        for line in route_result.stdout.splitlines():
            if "interface:" in line:
                iface = line.split(":")[1].strip()
                break
        if not iface:
            return "Wi-Fi"  # fallback to Wi-Fi

        # Map interface to service name
        for i, line in enumerate(lines):
            if f"({iface})" in line and i > 0:
                # Service name is on the previous line
                prev = lines[i - 1]
                if ":" in prev:
                    return prev.split(":")[1].strip()
        return "Wi-Fi"
    except Exception:
        return "Wi-Fi"


def _get_current_proxy_config(service: str) -> dict:
    """Read current proxy host/port/state for HTTP and HTTPS proxies."""
    config = {"web": {}, "secureweb": {}}
    for proxy_type in ("web", "secureweb"):
        try:
            result = subprocess.run(
                ["networksetup", f"-get{proxy_type}proxy", service],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    config[proxy_type][key.strip()] = val.strip()
        except Exception:
            pass
    return config


def enable_system_proxy(port: int = 8888) -> bool:
    """Set macOS system HTTP/HTTPS proxy.

    Saves the existing proxy configuration so it can be restored
    on disable. Returns True if both HTTP and HTTPS proxies were set.
    """
    global _SYSTEM_PROXY_ACTIVE, _SYSTEM_PROXY_PORT, _saved_proxy_config

    if not available():
        return False

    service = get_active_network_service()

    # Save current proxy config before overwriting
    _saved_proxy_config = _get_current_proxy_config(service)
    had_proxy = _saved_proxy_config.get("web", {}).get("Enabled") == "Yes"

    print(f"\n  Setting system proxy on \"{service}\" to localhost:{port} ...")

    rc1, err1 = _run_networksetup("-setwebproxy", service, "127.0.0.1", str(port))
    rc2, err2 = _run_networksetup("-setsecurewebproxy", service, "127.0.0.1", str(port))

    if rc1 != 0 or rc2 != 0:
        print(f"  ⚠ Failed to set system proxy: {err1 or err2}")
        return False

    # Turn it on (may be off)
    _run_networksetup("-setwebproxystate", service, "on")
    _run_networksetup("-setsecurewebproxystate", service, "on")

    # Only set flags after ALL commands succeed
    _SYSTEM_PROXY_ACTIVE = True
    _SYSTEM_PROXY_PORT = port

    print(f"  ✓ System proxy set to 127.0.0.1:{port}")
    if had_proxy:
        old_host = _saved_proxy_config.get("web", {}).get("Server", "?")
        old_port = _saved_proxy_config.get("web", {}).get("Port", "?")
        print(f"    (saved previous proxy {old_host}:{old_port} for restoration)")
    print(f"    Now Claude Desktop, Cursor, VS Code, and all macOS apps")
    print(f"    will route through the sniffer automatically.")
    return True


def disable_system_proxy() -> bool:
    """Restore macOS system proxy to previous state."""
    global _SYSTEM_PROXY_ACTIVE, _saved_proxy_config

    if not available() or not _SYSTEM_PROXY_ACTIVE:
        return False

    service = get_active_network_service()
    print(f"\n  Restoring system proxy on \"{service}\" ...")

    saved = _saved_proxy_config
    if saved and saved.get("web", {}).get("Enabled") == "Yes":
        # Restore previous proxy host/port
        web_host = saved.get("web", {}).get("Server", "127.0.0.1")
        web_port = saved.get("web", {}).get("Port", "8888")
        _run_networksetup("-setwebproxy", service, web_host, web_port)
        _run_networksetup("-setwebproxystate", service, "on")

        sec_host = saved.get("secureweb", {}).get("Server", web_host)
        sec_port = saved.get("secureweb", {}).get("Port", web_port)
        _run_networksetup("-setsecurewebproxy", service, sec_host, sec_port)
        _run_networksetup("-setsecurewebproxystate", service, "on")

        print(f"  ✓ Restored previous proxy ({web_host}:{web_port})")
    else:
        # No previous proxy — just disable
        _run_networksetup("-setwebproxystate", service, "off")
        _run_networksetup("-setsecurewebproxystate", service, "off")
        print(f"  ✓ System proxy disabled")

    _SYSTEM_PROXY_ACTIVE = False
    return True


def _cleanup():
    """Restore system proxy on exit."""
    if _SYSTEM_PROXY_ACTIVE:
        disable_system_proxy()


# Register cleanup
atexit.register(_cleanup)


# ── Transparent proxy via macOS pfctl ─────────────────────────────────────────


def enable_transparent_proxy(port: int = 8888) -> bool:
    """Redirect all outbound TCP/443 traffic to our proxy via pf.

    This catches apps that ignore proxy settings entirely (some statically
    linked Go binaries, Electron apps with --no-proxy-server, etc.).

    Usage:
        enable_transparent_proxy(8888)   # as root

    Requires root (sudo). The proxy must be in 'transparent' mode.
    """
    pf_anchor = "llm-sniffer"
    rdr_rule = (
        f"rdr pass on lo0 inet proto tcp from any to any port 443 "
        f"-> 127.0.0.1 port {port}"
    )

    try:
        # Load the redirect rule
        rule = f"anchor \"{pf_anchor}\"\n{rdr_rule}\n"
        result = subprocess.run(
            ["sudo", "pfctl", "-a", pf_anchor, "-f", "-"],
            input=rule, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False

        # Enable pf and the anchor
        subprocess.run(
            ["sudo", "pfctl", "-e"],
            capture_output=True, timeout=5,
        )
        print(f"  ✓ Transparent proxy active on 127.0.0.1:{port}")
        print(f"    All outbound HTTPS traffic redirected to sniffer")
        return True
    except Exception as e:
        print(f"  ⚠ Transparent proxy setup failed: {e}")
        return False


def disable_transparent_proxy():
    """Remove pf rdr rules and disable pf."""
    anchor = "llm-sniffer"
    try:
        # Clear anchor rules
        subprocess.run(
            ["sudo", "pfctl", "-a", anchor, "-F", "all"],
            capture_output=True, timeout=5,
        )
        # Disable pf if we were the only ones using it
        subprocess.run(
            ["sudo", "pfctl", "-d"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def print_client_instructions(port: int):
    """Print instructions for configuring common LLM desktop clients."""

    print(f"""
  ┌─ Client Setup Guide ─────────────────────────────────────────┐
  │                                                               │
  │  macOS system proxy (automatic, all apps):                    │
  │    use the --system-proxy flag (already active)               │
  │                                                               │
  │  Claude Code (CLI) / Node.js apps:                            │
  │    export HTTPS_PROXY=http://localhost:{port}
  │    export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
  │                                                               │
  │  Python apps (openai SDK, urllib, etc.):                     │
  │    ✓ auto-trusted via certifi                                 │
  │    export HTTPS_PROXY=http://localhost:{port}
  │    export HTTP_PROXY=http://localhost:{port}
  │                                                               │
  │  Claude Desktop:                                              │
  │    Settings → Advanced → Proxy → Manual                       │
  │      HTTP Proxy:   http://localhost:{port}
  │      HTTPS Proxy:  http://localhost:{port}
  │                                                               │
  │  Cursor / VS Code / Copilot:                                  │
  │    Settings → Http: Proxy → http://localhost:{port}
  │                                                               │
  │  Go / curl apps (trust macOS keychain):                       │
  │    ✓ auto-trusted after: security add-trusted-cert            │
  │    export HTTPS_PROXY=http://localhost:{port}
  │                                                               │
  │  Java apps:                                                   │
  │    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem    │
  │    export HTTPS_PROXY=http://localhost:{port}
  │                                                               │
  │  💡 Pro tip: ~/.zshrc alias for quick setup:                  │
  │    alias llm-sniff='export HTTPS_PROXY=http://localhost:{port}
  │      && export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem'
  │                                                               │
  │  Any app ignoring proxy settings?                             │
  │    Use transparent proxy: llm-sniffer --mode mitm --transparent│
  │    (requires sudo, captures ALL HTTPS traffic)                │
  └───────────────────────────────────────────────────────────────┘
""")
