#!/usr/bin/env python3
"""Simple LLM test app — makes one chat completion call."""

import json
import os
import ssl
import urllib.request

BASE_URL = os.getenv("BASE_URL")
API_KEY = os.getenv("API_KEY")

if not BASE_URL or not API_KEY:
    print("Please set BASE_URL and API_KEY environment variables.")
    print("Usage: BASE_URL=http://localhost:8888/v1 API_KEY=sk-xxx python test_app.py")
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

# When going through mitmproxy, skip cert verification since mitmproxy
# uses its own CA. For real usage, install mitmproxy's CA cert instead:
#   sudo security add-trusted-cert -d -p ssl ~/.mitmproxy/mitmproxy-ca-cert.pem
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
except Exception as e:
    print(f"[ERR] {e}")
