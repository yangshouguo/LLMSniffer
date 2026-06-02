# LLM Sniffer

A Wireshark-like traffic capture tool for LLM API calls. Intercepts, displays, and logs all LLM API requests and responses in real-time with an afl-fuzz style terminal UI.

## Features

- **Traffic Interception**: Acts as a reverse proxy, capturing all LLM API calls
- **AFL-Fuzz Style TUI**: Real-time terminal display showing captures, stats, and model breakdown
- **Flexible Filtering**: Filter captures by base_url, model name, or API key (glob/regex/exact)
- **File Logging**: All captures saved to JSONL files for later analysis
- **Multi-Provider**: Works with any OpenAI-compatible API (OpenAI, Anthropic, Groq, local models, etc.)

## Installation

```bash
# Clone and install
cd LLMDump
pip install -e .

# Or just install dependencies
pip install -r requirements.txt
```

## Quick Start

```bash
# Start the sniffer (default: listen on :8888, forward to api.openai.com)
llm-sniffer

# Custom port and target
llm-sniffer --port 9999 --target https://api.anthropic.com

# With filters
llm-sniffer --filter-model "gpt-4*" --filter-url "*openai*"
```

Then configure your LLM client to use the sniffer as a proxy:

**OpenAI Python SDK:**
```python
from openai import OpenAI
client = OpenAI(
    base_url="http://localhost:8888/v1",
    api_key="sk-your-key-here"
)
```

**Any OpenAI-compatible client:**
Set `base_url` or `OPENAI_BASE_URL` to `http://localhost:8888/v1`

**curl:**
```bash
curl http://localhost:8888/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-..." \
  -H "X-LLM-Target: https://api.openai.com" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## How It Works

```
LLM Client ──→ LLM Sniffer (:8888) ──→ Actual API (api.openai.com)
                  │
                  ├── TUI Display (afl-fuzz style)
                  └── Log Files (JSONL)
```

1. The sniffer runs as a reverse proxy on your local machine
2. Your LLM client sends requests to the sniffer instead of directly to the API
3. The sniffer forwards requests to the real API and captures everything
4. All traffic is displayed in the terminal and saved to JSONL log files

## CLI Options

### Server Options
| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Listen address |
| `-p`, `--port` | `8888` | Listen port |
| `-t`, `--target` | `https://api.openai.com` | Default upstream API URL |

### Filter Options
| Flag | Description |
|------|-------------|
| `--filter-url` | Only show captures matching this URL pattern |
| `--filter-model` | Only show captures matching this model pattern |
| `--filter-apikey` | Only show captures matching this API key pattern |
| `--exclude-url` | Hide captures matching this URL pattern |
| `--exclude-model` | Hide captures matching this model pattern |
| `--exclude-apikey` | Hide captures matching this API key pattern |
| `--pattern-mode` | `glob` (default), `regex`, or `exact` |

### Logging Options
| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | `./llm_sniffer_logs` | Log output directory |

## TUI Display

The terminal UI shows (afl-fuzz style):
- **Banner**: Tool name and version
- **Process Timing**: Uptime, last capture, capture rate
- **Overall Results**: Total captures, tokens, errors
- **Model Breakdown**: Per-model request counts with bars
- **Capture Table**: Live-scrolling list of recent captures with ID, time, model, status, latency, tokens, summary
- **Footer**: Active filters, log directory, controls

## Log Format

Captures are saved as JSONL files in the log directory:

```json
{
  "id": "a1b2c3d4",
  "timestamp": "2026-06-01T20:00:00",
  "base_url": "https://api.openai.com",
  "model": "gpt-4",
  "api_key_prefix": "sk-a***b1c2",
  "stream": false,
  "latency_ms": 1234.56,
  "status_code": 200,
  "prompt_tokens": 100,
  "completion_tokens": 50,
  "total_tokens": 150,
  "request_messages": [...],
  "response_choices": [...]
}
```

## License

MIT
