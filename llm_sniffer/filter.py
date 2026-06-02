"""Filter system for LLM captures - filter by base_url, model, apikey."""

import re
import fnmatch
from dataclasses import dataclass, field
from .capture import LLMCapture


@dataclass
class FilterConfig:
    """Filter configuration for LLM captures."""
    # Include filters - if set, only matching captures pass
    include_base_url: str = ""
    include_model: str = ""
    include_apikey: str = ""

    # Exclude filters - matching captures are dropped
    exclude_base_url: str = ""
    exclude_model: str = ""
    exclude_apikey: str = ""

    # Display only (still log everything)
    display_only: bool = False

    # Pattern mode: "exact", "glob", "regex"
    pattern_mode: str = "glob"

    def _match(self, value: str, pattern: str) -> bool:
        """Match value against pattern using the configured mode."""
        if not pattern:
            return True
        if self.pattern_mode == "exact":
            return value == pattern
        elif self.pattern_mode == "regex":
            return bool(re.search(pattern, value, re.IGNORECASE))
        else:  # glob
            return fnmatch.fnmatch(value.lower(), pattern.lower())

    def matches(self, cap: LLMCapture) -> bool:
        """Check if a capture matches the filter criteria."""
        # Check exclude filters first
        if self.exclude_base_url and self._match(cap.base_url, self.exclude_base_url):
            return False
        if self.exclude_model and self._match(cap.model, self.exclude_model):
            return False
        if self.exclude_apikey and self._match(cap.api_key_prefix, self.exclude_apikey):
            return False

        # Check include filters (all must match if set)
        if self.include_base_url and not self._match(cap.base_url, self.include_base_url):
            return False
        if self.include_model and not self._match(cap.model, self.include_model):
            return False
        if self.include_apikey and not self._match(cap.api_key_prefix, self.include_apikey):
            return False

        return True

    @classmethod
    def from_args(cls, args) -> "FilterConfig":
        """Create FilterConfig from parsed CLI args."""
        return cls(
            include_base_url=getattr(args, "filter_url", "") or "",
            include_model=getattr(args, "filter_model", "") or "",
            include_apikey=getattr(args, "filter_apikey", "") or "",
            exclude_base_url=getattr(args, "exclude_url", "") or "",
            exclude_model=getattr(args, "exclude_model", "") or "",
            exclude_apikey=getattr(args, "exclude_apikey", "") or "",
            pattern_mode=getattr(args, "pattern_mode", "glob") or "glob",
        )

    def summary(self) -> str:
        """Return a human-readable summary of active filters."""
        parts = []
        if self.include_base_url:
            parts.append(f"url={self.include_base_url}")
        if self.include_model:
            parts.append(f"model={self.include_model}")
        if self.include_apikey:
            parts.append(f"key={self.include_apikey}")
        if self.exclude_base_url:
            parts.append(f"!url={self.exclude_base_url}")
        if self.exclude_model:
            parts.append(f"!model={self.exclude_model}")
        if self.exclude_apikey:
            parts.append(f"!key={self.exclude_apikey}")
        return ", ".join(parts) if parts else "none"
