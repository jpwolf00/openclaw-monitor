# openclaw-monitor

Real-time agent activity dashboard for [OpenClaw](https://openclaw.ai).

Combines three data sources to give you visibility into whether your agents are
working, waiting, or stuck — without having to dig through log files.

![Dashboard showing agents, connections, and alerts sections](screenshot-placeholder.png)

## What It Shows

| Section | Data source | Key metrics |
|---|---|---|
| **Agents** | JSONL session files | Last tool call, model used, token counts, idle time |
| **Connections** | Linux kernel (`ss -tiep`) | Bytes in/out per endpoint, `lastrcv` timing, TX queue |
| **Child Processes** | `ps` | Any `exec` tool calls still running + elapsed time |
| **Alerts** | All three combined | Automatic stall detection with configurable thresholds |

### Why `lastrcv` matters

`lastrcv` is how long ago the kernel last received **any** data from a remote host.
On a model API connection it's the most reliable stall signal:

- **< 30s** — normal, model is responding or thinking
- **30s – 3min** — waiting; fine for complex tasks
- **> 3min** — warning; may be stuck
- **> 8min** — critical; almost certainly stuck

A connection with large `bytes_sent` but zero `bytes_received` means a request
was sent and nothing has come back — the primary stall signature.

## Requirements

- Python 3.7+, stdlib only (no pip installs)
- Linux (uses `ss -tiep` and `ps`)
- OpenClaw installed at `~/.openclaw` (or set `OPENCLAW_DIR`)

## Usage

```bash
python3 monitor.py
```

Open **http://localhost:7890** in a browser. The dashboard auto-refreshes every 2 seconds via SSE.

```bash
# Options
python3 monitor.py --port 8080             # different port
python3 monitor.py --dir /data/.openclaw   # custom openclaw dir
python3 monitor.py --interval 1            # 1s refresh
```

The script auto-discovers the openclaw directory, gateway PID, and provider IP
addresses from `openclaw.json` — no configuration needed on a new host.

## Configuration

All tunables are in the `CONFIG` dict at the top of `monitor.py`:

```python
CONFIG = {
    "port": 7890,
    "update_interval": 2,          # seconds between refreshes

    # Stall thresholds for model API connections
    "stall_warning_sec":  180,     # 3 min  → yellow alert
    "stall_critical_sec": 480,     # 8 min  → red alert

    # Stall thresholds for child processes (exec tool calls)
    "child_warning_sec":  120,     # 2 min  → yellow
    "child_critical_sec": 300,     # 5 min  → red

    # IP prefix → service name (auto-extended from openclaw.json providers)
    "known_services": {
        "149.154.": "Telegram",
        "47.89.":   "MiniMax",
        ...
    },
}
```

Provider IPs from your `openclaw.json` are also resolved and added automatically,
so new providers appear with friendly names without editing the script.

## Stall Patterns

### `tokens_in=0, tokens_out=0`
The model returned a response but produced no tokens. Usually an ollama issue
(context overflow, model incompatibility, or silent failure). The agent will loop
retrying the same message. Fix: switch to a cloud model and restart the gateway.

### Large `bytes_sent`, zero `bytes_received` on model API
Request sent, nothing came back. Common causes: model provider is down, request
timed out server-side, or the connection is silently dropped by a firewall.

### Child process running > 5 min
Usually a shell command (curl, sleep, build step) that is hanging. Often a `curl`
without `--max-time` hitting a port that is down. Check the command in the
Processes section and kill the PID if needed.

### `memorySearch` blocking
If OpenClaw's semantic search is pointed at a local ollama instance and that
instance is down, every memory lookup will hang. Check that ollama is running,
or set `memorySearch.fallback` in `openclaw.json` to a non-blocking option.

## How It Works

```
monitor.py
├── Auto-detect openclaw dir + gateway PID
├── Load provider IP map from openclaw.json
├── Background thread: collect + broadcast every N seconds
│   ├── ss -tiep → parse per-connection TCP stats
│   ├── ps --ppid <gateway> → child processes
│   └── agents/*/sessions/*.jsonl → tail + parse last events
├── Stall detector: flag connections/processes over threshold
└── HTTP server
    ├── GET /        → single-page dashboard (HTML+JS embedded)
    ├── GET /events  → SSE stream (auto-reconnecting)
    └── GET /api/state → JSON snapshot
```

## License

MIT
