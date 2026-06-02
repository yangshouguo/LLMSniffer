"""Traffic capture data models and LLM message parsing."""

import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMCapture:
    """Represents a single LLM API request/response pair."""
    id: str
    timestamp: float
    base_url: str
    model: str
    api_key_prefix: str  # first 8 chars of hashed key
    request_messages: list  # parsed messages from request
    request_body: str  # raw request body
    response_body: Optional[str] = None
    response_choices: Optional[list] = None
    status_code: Optional[int] = None
    latency_ms: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    error: Optional[str] = None
    stream: bool = False

    @property
    def message_count(self) -> int:
        return len(self.request_messages)

    @property
    def summary(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        if self.response_choices:
            content = str(self.response_choices[0])[:80]
            return content
        return "(no response yet)"


def generate_capture_id() -> str:
    """Generate a short unique ID for a capture."""
    return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]


def extract_api_key(headers: dict) -> str:
    """Extract and mask API key from request headers."""
    auth = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth.startswith("Bearer "):
        key = auth[7:]
        if len(key) > 12:
            return key[:4] + "****" + key[-4:]
        return key[:4] + "****"
    # Try x-api-key or other common headers
    for h in ["x-api-key", "X-Api-Key", "api-key"]:
        val = headers.get(h, "")
        if val:
            if len(val) > 12:
                return val[:4] + "****" + val[-4:]
            return val[:4] + "****"
    return "no-key"


def parse_request_body(body: bytes) -> dict:
    """Parse the request body and extract LLM-relevant fields."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"raw": body[:500].decode("utf-8", errors="replace")}

    result = {
        "model": data.get("model", "unknown"),
        "stream": data.get("stream", False),
        "messages": data.get("messages", []),
        "temperature": data.get("temperature"),
        "max_tokens": data.get("max_tokens"),
        "top_p": data.get("top_p"),
    }

    # Count tokens roughly (4 chars ≈ 1 token for English)
    total_chars = sum(
        len(msg.get("content", ""))
        for msg in result["messages"]
        if isinstance(msg, dict)
    )
    result["estimated_tokens"] = max(1, total_chars // 4)

    return result


def parse_response_body(body: bytes) -> dict:
    """Parse the response body and extract LLM-relevant fields."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"raw": body[:500].decode("utf-8", errors="replace")}

    result = {
        "id": data.get("id", ""),
        "object": data.get("object", ""),
        "model": data.get("model", ""),
        "choices": [],
        "usage": data.get("usage", {}),
    }

    for choice in data.get("choices", []):
        msg = choice.get("message", {}) or choice.get("delta", {})
        result["choices"].append({
            "index": choice.get("index", 0),
            "role": msg.get("role", "assistant"),
            "content": msg.get("content", "") or "",
            "finish_reason": choice.get("finish_reason"),
        })

    usage = data.get("usage", {})
    result["prompt_tokens"] = usage.get("prompt_tokens", 0)
    result["completion_tokens"] = usage.get("completion_tokens", 0)
    result["total_tokens"] = usage.get("total_tokens", 0)

    return result


def create_capture(
    method: str,
    path: str,
    headers: dict,
    body: bytes,
    base_url: str,
) -> LLMCapture:
    """Create an LLMCapture from an incoming request."""
    parsed = parse_request_body(body)
    cap = LLMCapture(
        id=generate_capture_id(),
        timestamp=time.time(),
        base_url=base_url,
        model=parsed.get("model", "unknown"),
        api_key_prefix=extract_api_key(headers),
        request_messages=parsed.get("messages", []),
        request_body=body.decode("utf-8", errors="replace"),
        stream=parsed.get("stream", False),
    )
    return cap


def update_capture_with_response(
    cap: LLMCapture,
    status: int,
    body: bytes,
    latency_ms: float,
):
    """Update a capture with response data."""
    cap.status_code = status
    cap.latency_ms = latency_ms
    cap.response_body = body.decode("utf-8", errors="replace")

    parsed = parse_response_body(body)
    cap.response_choices = parsed.get("choices", [])
    cap.prompt_tokens = parsed.get("prompt_tokens", 0)
    cap.completion_tokens = parsed.get("completion_tokens", 0)
    cap.total_tokens = parsed.get("total_tokens", 0)

    if status >= 400:
        cap.error = f"HTTP {status}: {cap.response_body[:200]}"
