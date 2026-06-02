"""Traffic capture data models and LLM message parsing."""

import json
import re
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


def _parse_sse_body(body_str: str) -> dict:
    """Parse an SSE streaming response body into structured capture data.

    Handles both OpenAI-style chat completion chunks and Anthropic-style
    Messages API SSE events::

        OpenAI::

            data: {"id":"...","choices":[{"delta":{"content":"Hello"}}]}
            data: [DONE]

        Anthropic::

            event: content_block_delta
            data: {"type":"content_block_delta","index":0,
                   "delta":{"type":"text_delta","text":"Hello"}}

    Splits by ``\\n\\n`` (the SSE frame delimiter) rather than
    ``splitlines()``, so that chunk-split frames are correctly
    re-assembled at the byte level before JSON parsing.

    Concatenates all delta content and extracts usage from appropriate
    SSE events (``message_start``, ``message_delta``, or the final
    OpenAI chunk).
    """
    result = {
        "id": "",
        "object": "",
        "model": "",
        "choices": [],
        "usage": {},
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "_truncated": False,
    }

    content_parts = []
    finish_reason = None
    role = "assistant"
    lines_parsed = 0

    # Normalise line endings so we can split on \n\n
    normalised = body_str.replace("\r\n", "\n")
    for raw_frame in normalised.split("\n\n"):
        frame = raw_frame.strip()
        if not frame:
            continue

        # Try to strip "data: " prefix from the whole frame first
        payload = _strip_data_prefix(frame)
        if payload is None:
            # Multi-line SSE frame (e.g. event: xxx\n data: {...})
            # Scan each line for a data: line
            for line in frame.split("\n"):
                candidate = _strip_data_prefix(line)
                if candidate is not None:
                    payload = candidate
                    break
        if payload is None:
            continue  # not an SSE data line
        if payload == "[DONE]":
            continue

        try:
            chunk = json.loads(payload)
        except json.JSONDecodeError:
            continue  # incomplete frame — skip (bytes are safe in the next frame)
        lines_parsed += 1

        chunk_type = chunk.get("type")

        if chunk_type:
            # --- Anthropic SSE event handling ---
            if chunk_type == "message_start":
                msg = chunk.get("message", {}) or {}
                if not result["id"] and msg.get("id"):
                    result["id"] = msg["id"]
                if not result["model"] and msg.get("model"):
                    result["model"] = msg["model"]
                if msg.get("role"):
                    role = msg["role"]
                msg_usage = msg.get("usage", {}) or {}
                if msg_usage.get("input_tokens"):
                    result["prompt_tokens"] = msg_usage["input_tokens"]
            elif chunk_type == "content_block_start":
                cb = chunk.get("content_block", {}) or {}
                if cb.get("text"):
                    content_parts.append(cb["text"])
                if cb.get("thinking"):
                    content_parts.append(cb["thinking"])
            elif chunk_type == "content_block_delta":
                delta = chunk.get("delta", {}) or {}
                delta_type = delta.get("type", "")
                if delta_type == "text_delta" and delta.get("text"):
                    content_parts.append(delta["text"])
                elif delta_type == "thinking_delta" and delta.get("thinking"):
                    content_parts.append(delta["thinking"])
            elif chunk_type == "content_block_stop":
                pass  # marker only, no data to extract
            elif chunk_type == "message_delta":
                inner_delta = chunk.get("delta", {}) or {}
                if inner_delta.get("stop_reason"):
                    finish_reason = inner_delta["stop_reason"]
                msg_usage = chunk.get("usage", {}) or {}
                if msg_usage.get("output_tokens"):
                    result["completion_tokens"] = msg_usage["output_tokens"]
                result["total_tokens"] = result["prompt_tokens"] + result["completion_tokens"]
            elif chunk_type == "message_stop":
                pass  # marker only, no data to extract
            elif chunk_type == "ping":
                pass  # keepalive, nothing to extract
            # Unknown event types are silently ignored
        else:
            # --- OpenAI-style chat completion chunk ---
            if chunk.get("id"):
                result["id"] = chunk["id"]
            if chunk.get("object"):
                result["object"] = chunk["object"]
            if chunk.get("model"):
                result["model"] = chunk["model"]

            for choice in chunk.get("choices", []):
                delta = choice.get("delta", {}) or {}
                if delta.get("content"):
                    content_parts.append(delta["content"])
                if delta.get("role"):
                    role = delta["role"]
                if choice.get("finish_reason"):
                    finish_reason = choice["finish_reason"]

            # Some providers include usage in the final chunk
            usage = chunk.get("usage", {})
            if usage:
                result["usage"] = usage
                result["prompt_tokens"] = usage.get("prompt_tokens", 0)
                result["completion_tokens"] = usage.get("completion_tokens", 0)
                result["total_tokens"] = usage.get("total_tokens", 0)

    # Detect truncated streams (no finish_reason received)
    if finish_reason is None and lines_parsed > 0:
        result["_truncated"] = True

    # Build a single synthetic choice from concatenated deltas
    full_content = "".join(content_parts)
    result["choices"] = [{
        "index": 0,
        "role": role,
        "content": full_content,
        "finish_reason": finish_reason,
    }]

    return result


def _strip_data_prefix(line: str) -> Optional[str]:
    """Strip ``data: `` (or ``data:``) prefix from *line*.

    Returns the payload string, or ``None`` if the line is not an SSE
    data line.
    """
    if line.startswith("data: "):
        return line[6:]
    if line.startswith("data:"):
        return line[5:]
    if line.startswith("data:\t"):
        return line[6:]
    return None


def parse_response_body(body: bytes) -> dict:
    """Parse the response body and extract LLM-relevant fields.

    Handles:
    - Standard JSON responses (OpenAI chat completions format)
    - SSE streaming responses (OpenAI chat completions chunk format)
    - SSE streaming responses (Anthropic Messages API event format)
    - Standard JSON responses (Anthropic Messages API format)
    """
    body_str = body.decode("utf-8", errors="replace")

    # Detect SSE streaming format: body lines start with "data: " or "event: "
    stripped = body_str.lstrip()
    if stripped.startswith("data: ") or stripped.startswith("data:") or stripped.startswith("event: "):
        return _parse_sse_body(body_str)

    # Standard JSON response
    try:
        data = json.loads(body_str)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"raw": body_str[:500]}

    result = {
        "id": data.get("id", ""),
        "object": data.get("object", ""),
        "model": data.get("model", ""),
        "choices": [],
        "usage": data.get("usage", {}),
    }

    if "choices" in data:
        # OpenAI-style: choices array with message/delta objects
        for choice in data["choices"]:
            msg = choice.get("message", {}) or choice.get("delta", {})
            result["choices"].append({
                "index": choice.get("index", 0),
                "role": msg.get("role", "assistant"),
                "content": msg.get("content", "") or "",
                "finish_reason": choice.get("finish_reason"),
            })
    elif "content" in data and isinstance(data["content"], list):
        # Anthropic-style: content is an array of content blocks
        texts = []
        for block in data["content"]:
            if isinstance(block, dict):
                if block.get("type") == "text" and block.get("text"):
                    texts.append(block["text"])
                elif block.get("type") == "thinking" and block.get("thinking"):
                    texts.append(block["thinking"])
        result["choices"].append({
            "index": 0,
            "role": data.get("role", "assistant"),
            "content": "".join(texts),
            "finish_reason": data.get("stop_reason"),
        })

    usage = data.get("usage", {})
    result["prompt_tokens"] = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
    result["completion_tokens"] = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
    result["total_tokens"] = usage.get("total_tokens", 0) or (
        result["prompt_tokens"] + result["completion_tokens"]
    )

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
