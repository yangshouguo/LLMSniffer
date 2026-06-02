#!/usr/bin/env python3
"""Simple LLM test app — makes one chat completion call.

Usage:
  # Reverse mode (sniffer on :8888, change base_url)
  BASE_URL=http://localhost:8888/v1 API_KEY=sk-xxx python test_app.py

  # mitm mode (sniffer on :8888, set proxy env var)
  HTTPS_PROXY=http://localhost:8888 BASE_URL=https://api.deepseek.com API_KEY=sk-xxx python test_app.py
"""

import json
import os
import ssl
import urllib.request

BASE_URL = os.getenv("BASE_URL")
API_KEY = os.getenv("API_KEY")

if not BASE_URL or not API_KEY:
    print("Please set BASE_URL and API_KEY environment variables.")
    print()
    print("Reverse mode (change base_url):")
    print("  BASE_URL=http://localhost:8888/v1 API_KEY=sk-xxx python test_app.py")
    print()
    print("mitm mode (set proxy env, zero code changes):")
    print("  HTTPS_PROXY=http://localhost:8888 BASE_URL=https://api.deepseek.com API_KEY=sk-xxx python test_app.py")
    exit(1)

body = json.dumps({
    "model": "deepseek-v4-flash",
    "messages": [
        {"role": "user", "content": "What is the capital of France?"},
    ],
}).encode()

req = urllib.request.Request(
    f"{BASE_URL}/chat/completions",
    data=body,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    },
)

# When going through mitmproxy, the proxy presents its own cert.
# Python's ssl module doesn't use macOS keychain — it uses certifi.
# We auto-append mitmproxy's CA to certifi on `llm-sniffer --mode mitm` startup.
# This fallback skips verification if proxy is detected and the auto-append didn't work.
ctx = None
if os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

try:
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        data = json.loads(resp.read())
        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens", 0)
        print(f"[OK] {resp.status} | {tokens} tokens")
        print(content)
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", errors="replace")
    print(f"[ERR] HTTP {e.code}: {body[:300]}")
except ssl.SSLCertVerificationError as e:
    print(f"[ERR] SSL cert verify failed: {e}")
    print()
    print("This happens when Python can't verify the server certificate.")
    print("If using mitm mode, make sure:")
    print("  1. llm-sniffer --mode mitm is running")
    print("  2. HTTPS_PROXY env var is set:")
    print(f"     export HTTPS_PROXY=http://localhost:8888")
    print("  3. The mitmproxy CA cert is trusted by Python:")
    print("     Restart llm-sniffer --mode mitm (it auto-appends to certifi)")
except Exception as e:
    print(f"[ERR] {e}")
