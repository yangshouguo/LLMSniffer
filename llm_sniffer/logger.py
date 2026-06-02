"""File-based logging for LLM captures."""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from .capture import LLMCapture
from .filter import FilterConfig


class CaptureLogger:
    """Handles writing LLM captures to log files."""

    def __init__(self, log_dir: str = "./llm_sniffer_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._current_file: str = ""
        self._capture_count: int = 0
        self._rotate_file()

    def _rotate_file(self):
        """Start a new log file."""
        self._capture_count = 0
        self._current_file = str(
            self.log_dir / f"llm_capture_{self.session_id}.jsonl"
        )

    def log_capture(self, cap: LLMCapture, filter_config: FilterConfig = None):
        """Write a single capture to the log file."""
        # Always log to file regardless of filter (filter is for display)
        record = {
            "id": cap.id,
            "timestamp": datetime.fromtimestamp(cap.timestamp).isoformat(),
            "base_url": cap.base_url,
            "model": cap.model,
            "api_key_prefix": cap.api_key_prefix,
            "stream": cap.stream,
            "latency_ms": round(cap.latency_ms, 2),
            "status_code": cap.status_code,
            "error": cap.error,
            "prompt_tokens": cap.prompt_tokens,
            "completion_tokens": cap.completion_tokens,
            "total_tokens": cap.total_tokens,
            "request_messages": cap.request_messages,
            "response_choices": cap.response_choices,
            "request_body": cap.request_body,
            "response_body": cap.response_body,
        }

        with open(self._current_file, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        self._capture_count += 1

        # Rotate file every 1000 captures
        if self._capture_count >= 1000:
            self._rotate_file()

    def log_raw(self, direction: str, data: bytes, peer: str = ""):
        """Log raw bytes for debugging."""
        raw_file = str(self.log_dir / f"raw_{self.session_id}.bin")
        timestamp = time.time()
        header = f"\n=== {direction} | {datetime.fromtimestamp(timestamp).isoformat()} | {peer} ===\n"
        with open(raw_file, "ab") as f:
            f.write(header.encode("utf-8"))
            f.write(data)
            f.write(b"\n")

    def get_stats(self) -> dict:
        """Get summary statistics for this session."""
        return {
            "log_dir": str(self.log_dir),
            "session_id": self.session_id,
            "current_file": self._current_file,
            "captures_in_file": self._capture_count,
        }
