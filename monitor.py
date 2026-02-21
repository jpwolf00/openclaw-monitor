#!/usr/bin/env python3
"""
OpenClaw Monitor
================
Real-time dashboard for monitoring OpenClaw agent activity.

Combines three data sources:

  1. Kernel network stats via `ss -tiep`
       - Bytes sent/received per TCP connection
       - lastsnd/lastrcv timings (the primary stall indicator)
       - TX/RX queue depth (unacknowledged data)

  2. Process tree
       - Child processes of openclaw-gateway
       - Command text and elapsed runtime

  3. OpenClaw JSONL session files
       - Token counts per turn (input / output / cache)
       - Last tool call name and timestamp
       - Which model and provider responded

Stall Detection
---------------
  A model API connection is flagged as:
    WARNING   if no data received in > stall_warning_sec
    CRITICAL  if no data received in > stall_critical_sec

  A child process (exec tool call) is flagged as:
    WARNING   if running for > child_warning_sec
    CRITICAL  if running for > child_critical_sec

Portability
-----------
  Auto-detects openclaw directory and gateway PID so this script
  works without changes when you move to a new host. Run it once,
  point a browser at http://localhost:<port>.

Usage
-----
  python3 monitor.py                         # use all defaults
  python3 monitor.py --port 8080
  python3 monitor.py --dir /data/.openclaw
  python3 monitor.py --port 8080 --interval 1

Dependencies
------------
  Python 3.7+ stdlib only. No pip installs required.
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
#
# All tunable values live here. CLI args (--port, --dir, --interval) override
# the corresponding entries at startup. Everything else is edited in place.
# ─────────────────────────────────────────────────────────────────────────────

CONFIG: Dict[str, Any] = {

    # Dashboard web server port
    "port": 7890,

    # Bind address. "0.0.0.0" listens on all interfaces so the dashboard
    # is reachable from other machines on your network (recommended).
    # Change to "127.0.0.1" to restrict to localhost only.
    "bind": "0.0.0.0",

    # Seconds between data refreshes
    "update_interval": 2,

    # ── Stall thresholds for model API connections ────────────────────────
    # lastrcv is how long ago (ms) the kernel last received data on a socket.
    # A large lastrcv on an open model-API connection means we're waiting.
    "stall_warning_sec":  180,   # 3 min  → yellow
    "stall_critical_sec": 480,   # 8 min  → red

    # ── Stall thresholds for child processes (exec tool calls) ────────────
    "child_warning_sec":  120,   # 2 min  → yellow
    "child_critical_sec": 300,   # 5 min  → red

    # ── Bytes to read from the tail of each session file ─────────────────
    # Larger = more history visible, but slightly more I/O per tick.
    "session_tail_bytes": 10000,

    # ── IP prefix → human-readable service name ───────────────────────────
    # Checked in order; first match wins. Extend with your own providers.
    # Provider base URLs from openclaw.json are also auto-added at startup.
    "known_services": {
        "149.154.":  "Telegram",
        "91.108.":   "Telegram",
        "47.89.":    "MiniMax",
        "216.150.":  "MiniMax",
        "47.236.":   "MiniMax",
        "nano-gpt":  "NanoGPT",   # matched against hostname too
        "openai":    "OpenAI",
        "anthropic": "Anthropic",
        "127.0.0.1": "Localhost",
    },

    # ── Process name of the openclaw gateway ─────────────────────────────
    "gateway_process_name": "openclaw-gateway",

    # ── Token history ─────────────────────────────────────────────────────
    # How often to recompute full token history by scanning all session files.
    # 300s (5 min) balances freshness against disk I/O on large installs.
    "history_cache_ttl_sec": 300,

    # ── Runaway token detection ───────────────────────────────────────────
    # Absolute spike: flag if this many tokens are used in the last 5 minutes.
    # 50k is a reasonable ceiling for normal agent activity; a tight loop will
    # blow past this quickly.
    "runaway_abs_threshold": 50000,

    # Rate anomaly multiplier: flag if last-hour token rate exceeds
    # N × the agent's average hourly rate over the past week.
    # Only fires when there is enough weekly history to compute a baseline.
    "runaway_multiplier": 5.0,

    # Consecutive assistant turns with zero output tokens → likely stuck in a
    # silent retry loop (e.g. a local model returning empty responses).
    "runaway_zero_output_turns": 5,
}


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def find_openclaw_dir(override: Optional[str] = None) -> Path:
    """
    Locate the openclaw data directory.

    Search order:
      1. `override` argument (from --dir CLI flag)
      2. OPENCLAW_DIR environment variable
      3. ~/.openclaw  (default install location)

    Raises RuntimeError if none of the candidates exist.
    """
    candidates = []
    if override:
        candidates.append(Path(override))
    if "OPENCLAW_DIR" in os.environ:
        candidates.append(Path(os.environ["OPENCLAW_DIR"]))
    candidates.append(Path.home() / ".openclaw")

    for path in candidates:
        if path.is_dir():
            return path

    raise RuntimeError(
        f"Could not find openclaw directory. Tried: {candidates}\n"
        "Set OPENCLAW_DIR or pass --dir <path>."
    )


def find_gateway_pid() -> Optional[int]:
    """
    Find the PID of the running openclaw-gateway process.

    Linux truncates comm names to 15 characters in /proc, so
    'openclaw-gateway' becomes 'openclaw-gatewa'. We use `pgrep -f`
    (full command-line match) to work around this reliably.
    Returns None if the process is not running.
    """
    try:
        result = subprocess.run(
            ["pgrep", "-f", CONFIG["gateway_process_name"]],
            capture_output=True, text=True
        )
        pids = [int(p) for p in result.stdout.strip().split() if p.isdigit()]
        # pgrep -f can match this script itself — exclude our own PID
        own_pid = os.getpid()
        pids = [p for p in pids if p != own_pid]
        return pids[0] if pids else None
    except Exception:
        return None


def load_agent_list(openclaw_dir: Path) -> List[Dict]:
    """
    Read the agent definitions from openclaw.json.

    Returns a list of dicts with at least {"id": str, "name": str}.
    Falls back to scanning the agents/ directory if the config is
    unreadable so the monitor still works on a misconfigured install.
    """
    config_path = openclaw_dir / "openclaw.json"
    agents = []

    try:
        with open(config_path) as f:
            cfg = json.load(f)
        for agent in cfg.get("agents", {}).get("list", []):
            agents.append({
                "id":   agent.get("id", "unknown"),
                "name": agent.get("name", agent.get("id", "unknown")),
            })
    except Exception:
        pass

    # Fallback: scan the filesystem
    if not agents:
        agents_dir = openclaw_dir / "agents"
        if agents_dir.is_dir():
            for entry in agents_dir.iterdir():
                if entry.is_dir() and (entry / "sessions").is_dir():
                    agents.append({"id": entry.name, "name": entry.name})

    return agents


def build_ip_service_map(openclaw_dir: Path) -> Dict[str, str]:
    """
    Build an IP-prefix → service-name map by merging:
      1. CONFIG["known_services"]  (hardcoded / hand-tuned)
      2. Provider baseUrls from openclaw.json  (auto-discovered)

    This means new providers added to openclaw.json are automatically
    labelled in the dashboard without editing this script.
    """
    mapping = dict(CONFIG["known_services"])

    config_path = openclaw_dir / "openclaw.json"
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        providers = cfg.get("models", {}).get("providers", {})
        for provider_id, provider_cfg in providers.items():
            base_url = provider_cfg.get("baseUrl", "")
            # Strip scheme and path to get just the host
            host = re.sub(r"^https?://", "", base_url).split("/")[0].split(":")[0]
            if host:
                # Try to resolve to IP and add both host and IP prefix
                mapping[host] = provider_id
                try:
                    ip = socket.gethostbyname(host)
                    # Use first two octets as a prefix for range matching
                    prefix = ".".join(ip.split(".")[:2]) + "."
                    if prefix not in mapping:
                        mapping[prefix] = provider_id
                except Exception:
                    pass
    except Exception:
        pass

    return mapping


# ─────────────────────────────────────────────────────────────────────────────
# NETWORK COLLECTOR  (ss -tiep)
# ─────────────────────────────────────────────────────────────────────────────

def resolve_service(remote_addr: str, ip_service_map: Dict[str, str]) -> str:
    """
    Translate a remote IP:port into a human-readable service name.

    Tries:
      1. Exact key match in ip_service_map
      2. Prefix match (e.g. "149.154." for Telegram)
      3. Reverse DNS lookup (cached in memory by the OS resolver)
      4. Falls back to the raw IP string
    """
    host = remote_addr.rsplit(":", 1)[0]  # strip :port

    # Direct match
    if host in ip_service_map:
        return ip_service_map[host]

    # Prefix match
    for prefix, name in ip_service_map.items():
        if host.startswith(prefix):
            return name

    # Reverse DNS  (non-blocking because we've set a short timeout)
    try:
        socket.setdefaulttimeout(0.3)
        hostname = socket.gethostbyaddr(host)[0]
        socket.setdefaulttimeout(None)
        # Check hostname fragments against map keys
        for fragment, name in ip_service_map.items():
            if fragment.lower() in hostname.lower():
                return name
        return hostname
    except Exception:
        socket.setdefaulttimeout(None)

    return host


def parse_ss_output(raw: str, gateway_pid: int, ip_service_map: Dict[str, str]) -> List[Dict]:
    """
    Parse the output of `ss -tiep` into a list of connection dicts.

    `ss -tiep` produces two lines per connection:
      Line 1:  State  RecvQ  SendQ  Local  Remote  users:((...))  timer:(...)
      Line 2:  (indented)  ts sack ... bytes_sent:N bytes_received:N lastsnd:N lastrcv:N ...

    We filter for connections belonging to:
      - openclaw-gateway (by gateway_pid)
      - Any process whose name contains "openclaw"

    Returned dict keys:
      state, local, remote, service, pid, fd,
      tx_queue, rx_queue,
      bytes_sent, bytes_received,
      lastsnd_ms, lastrcv_ms,
      timer, raw_detail
    """
    connections = []
    lines = raw.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        # Skip header and blank lines
        if not line or line.startswith("State") or line.startswith("Netid"):
            i += 1
            continue

        # Grab the detail line (indented, follows the main line)
        detail = ""
        if i + 1 < len(lines) and lines[i + 1].startswith("\t"):
            detail = lines[i + 1].strip()
            i += 2
        else:
            i += 1

        # ── Filter: only keep openclaw-gateway connections ────────────────
        # users field looks like: users:(("openclaw-gatewa",pid=359082,fd=30))
        if str(gateway_pid) not in line and "openclaw" not in line.lower():
            continue

        # ── Parse main line ───────────────────────────────────────────────
        parts = line.split()
        if len(parts) < 5:
            continue

        state     = parts[0]
        rx_queue  = int(parts[1]) if parts[1].isdigit() else 0
        tx_queue  = int(parts[2]) if parts[2].isdigit() else 0
        local     = parts[3]
        remote    = parts[4]

        # Extract pid and fd from users:(("name",pid=N,fd=N))
        pid_match = re.search(r"pid=(\d+)", line)
        fd_match  = re.search(r"fd=(\d+)",  line)
        pid = int(pid_match.group(1)) if pid_match else None
        fd  = int(fd_match.group(1))  if fd_match  else None

        # Extract timer type (keepalive, on, off)
        timer_match = re.search(r"timer:\(([^,)]+)", line)
        timer = timer_match.group(1) if timer_match else ""

        # ── Parse detail line (TCP internals) ────────────────────────────
        def extract_int(pattern: str, text: str) -> Optional[int]:
            m = re.search(pattern, text)
            return int(m.group(1)) if m else None

        bytes_sent     = extract_int(r"bytes_sent:(\d+)",     detail)
        bytes_received = extract_int(r"bytes_received:(\d+)", detail)
        lastsnd_ms     = extract_int(r"lastsnd:(\d+)",        detail)
        lastrcv_ms     = extract_int(r"lastrcv:(\d+)",        detail)

        service = resolve_service(remote, ip_service_map)

        connections.append({
            "state":          state,
            "local":          local,
            "remote":         remote,
            "service":        service,
            "pid":            pid,
            "fd":             fd,
            "tx_queue":       tx_queue,
            "rx_queue":       rx_queue,
            "bytes_sent":     bytes_sent,
            "bytes_received": bytes_received,
            "lastsnd_ms":     lastsnd_ms,
            "lastrcv_ms":     lastrcv_ms,
            "timer":          timer,
        })

    return connections


def collect_network(gateway_pid: Optional[int], ip_service_map: Dict[str, str]) -> List[Dict]:
    """
    Run `ss -tiep` and return parsed connection list.

    Filters out connections on the monitor's own port (self-connections
    from browsers hitting the dashboard) so they don't pollute the view.
    Returns empty list if gateway is not running or ss fails.
    """
    if gateway_pid is None:
        return []
    try:
        result = subprocess.run(
            ["ss", "-tiep"],
            capture_output=True, text=True, timeout=5
        )
        conns = parse_ss_output(result.stdout, gateway_pid, ip_service_map)
        monitor_port = str(CONFIG["port"])
        return [c for c in conns if not c["local"].endswith(f":{monitor_port}")]
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# PROCESS COLLECTOR
# ─────────────────────────────────────────────────────────────────────────────

def collect_processes(gateway_pid: Optional[int]) -> List[Dict]:
    """
    Find child processes of openclaw-gateway and return their details.

    These are typically bash commands launched by the agent's `exec` tool.
    Long-running children are the most common source of stalls.

    Returned dict keys:
      pid, ppid, stat, elapsed_sec, elapsed_str, command
    """
    if gateway_pid is None:
        return []

    processes = []
    try:
        result = subprocess.run(
            ["ps", "--ppid", str(gateway_pid), "-o", "pid,ppid,stat,etimes,comm,args",
             "--no-headers"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            pid     = int(parts[0])
            ppid    = int(parts[1])
            stat    = parts[2]
            elapsed = int(parts[3]) if parts[3].isdigit() else 0
            command = parts[5] if len(parts) > 5 else parts[4]

            # Format elapsed time as human-readable
            if elapsed < 60:
                elapsed_str = f"{elapsed}s"
            elif elapsed < 3600:
                elapsed_str = f"{elapsed // 60}m {elapsed % 60}s"
            else:
                elapsed_str = f"{elapsed // 3600}h {(elapsed % 3600) // 60}m"

            processes.append({
                "pid":         pid,
                "ppid":        ppid,
                "stat":        stat,
                "elapsed_sec": elapsed,
                "elapsed_str": elapsed_str,
                "command":     command[:120],  # cap length for display
            })
    except Exception:
        pass

    return processes


# ─────────────────────────────────────────────────────────────────────────────
# SESSION COLLECTOR  (JSONL files)
# ─────────────────────────────────────────────────────────────────────────────

def find_active_session(sessions_dir: Path) -> Optional[Path]:
    """
    Return the path of the most recently modified active session file.

    Excludes .lock, .deleted, and .reset files. The most recently
    modified .jsonl file is the one the agent is currently writing to.
    """
    if not sessions_dir.is_dir():
        return None

    best: Optional[Tuple[float, Path]] = None
    for f in sessions_dir.iterdir():
        name = f.name
        # Skip metadata and soft-deleted files
        if not name.endswith(".jsonl"):
            continue
        if any(x in name for x in [".deleted", ".reset", ".lock"]):
            continue
        if name == "sessions.json":
            continue
        mtime = f.stat().st_mtime
        if best is None or mtime > best[0]:
            best = (mtime, f)

    return best[1] if best else None


def parse_session_tail(session_file: Path, tail_bytes: int) -> Dict:
    """
    Read the last `tail_bytes` bytes of a JSONL session file and extract:
      - last_tool:       name of the most recent tool call
      - last_tool_ts:    ISO timestamp of that tool call
      - last_model:      model name from the most recent assistant message
      - last_provider:   provider name from the most recent assistant message
      - tokens_in:       input token count from the most recent turn
      - tokens_out:      output token count from the most recent turn
      - tokens_cache:    cache-read token count from the most recent turn
      - last_event_ts:   timestamp of the very last line in the file
      - session_id:      derived from the filename

    Parsing only the tail keeps I/O fast even for multi-MB session files.
    """
    result = {
        "last_tool":          None,
        "last_tool_ts":       None,
        "last_model":         None,
        "last_provider":      None,
        "tokens_in":          None,
        "tokens_out":         None,
        "tokens_cache":       None,
        "last_event_ts":      None,
        "session_id":         session_file.stem[:8],  # first 8 chars of UUID
        "last_thought":       None,
        # How many consecutive assistant turns had zero output tokens.
        # A non-zero streak indicates a silent retry loop.
        "zero_output_streak": 0,
    }

    try:
        size = session_file.stat().st_size
        offset = max(0, size - tail_bytes)

        with open(session_file, "rb") as f:
            f.seek(offset)
            raw = f.read().decode("utf-8", errors="replace")

        # If we seeked into the middle of a line, skip the partial first line
        if offset > 0:
            raw = raw[raw.find("\n") + 1:]

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = msg.get("timestamp")
            if ts:
                result["last_event_ts"] = ts

            inner = msg.get("message", {})
            role = inner.get("role")
            content = inner.get("content", [])

            if role == "assistant":
                # Capture model/provider/usage from every assistant turn
                # (last one wins, which is what we want)
                if inner.get("model"):
                    result["last_model"]    = inner["model"]
                    result["last_provider"] = inner.get("provider", "")
                usage = inner.get("usage", {})
                if usage:
                    result["tokens_in"]    = usage.get("input")
                    result["tokens_out"]   = usage.get("output")
                    result["tokens_cache"] = usage.get("cacheRead")

                    # Track consecutive zero-output streak.
                    # Reset on any turn that produces real output.
                    if (usage.get("output") or 0) == 0:
                        result["zero_output_streak"] += 1
                    else:
                        result["zero_output_streak"] = 0

                # Capture last text (thinking) and last tool call
                if isinstance(content, list):
                    for block in content:
                        if block.get("type") == "text":
                            text = (block.get("text") or "").strip()
                            if text:
                                result["last_thought"] = text
                        elif block.get("type") == "toolCall":
                            result["last_tool"]    = block.get("name")
                            result["last_tool_ts"] = ts

    except Exception:
        pass

    return result


def collect_sessions(openclaw_dir: Path, agents: List[Dict]) -> List[Dict]:
    """
    For each known agent, find its active session and parse recent state.

    Returns a list of dicts combining agent metadata with session data.
    Agents with no session files are still included (with null fields)
    so the dashboard always shows all configured agents.
    """
    now = time.time()
    sessions = []

    for agent in agents:
        agent_id = agent["id"]
        sessions_dir = openclaw_dir / "agents" / agent_id / "sessions"
        active = find_active_session(sessions_dir)

        entry: Dict = {
            "agent_id":   agent_id,
            "agent_name": agent.get("name", agent_id),
            "session_id": None,
            "file_mtime": None,
            "idle_sec":   None,
        }

        if active:
            mtime = active.stat().st_mtime
            entry["file_mtime"] = mtime
            entry["idle_sec"]   = int(now - mtime)
            parsed = parse_session_tail(active, CONFIG["session_tail_bytes"])
            entry.update(parsed)
        else:
            # No session file yet — agent has never run
            entry.update({
                "last_tool":     None,
                "last_tool_ts":  None,
                "last_model":    None,
                "last_provider": None,
                "tokens_in":     None,
                "tokens_out":    None,
                "tokens_cache":  None,
                "last_event_ts": None,
                "session_id":    None,
                "last_thought":  None,
            })

        sessions.append(entry)

    return sessions


# ─────────────────────────────────────────────────────────────────────────────
# STALL DETECTION
# ─────────────────────────────────────────────────────────────────────────────

# Service names that represent model API endpoints (not infra connections).
# Connections to these services are what we watch for response stalls.
MODEL_API_FRAGMENTS = [
    "minimax", "openai", "anthropic", "nanogpt", "nano-gpt",
    "ollama", "together", "groq", "mistral", "gemini",
]

def is_model_api(service: str) -> bool:
    """Return True if this connection looks like a model API endpoint."""
    s = service.lower()
    return any(frag in s for frag in MODEL_API_FRAGMENTS)


def detect_stalls(
    connections: List[Dict],
    processes:   List[Dict],
    sessions:    List[Dict],
) -> List[Dict]:
    """
    Analyse collected data and return a list of stall alerts.

    Each alert dict has:
      level:    "warning" | "critical"
      category: "network" | "process" | "session"
      message:  human-readable description
      detail:   extra context string

    Logic:
      Network:  Model API connection with lastrcv > threshold
      Process:  Child process running for > threshold
      Session:  Session file not updated for > threshold (corroborating signal)
    """
    alerts = []
    warn_sec = CONFIG["stall_warning_sec"]
    crit_sec = CONFIG["stall_critical_sec"]
    child_warn = CONFIG["child_warning_sec"]
    child_crit = CONFIG["child_critical_sec"]

    # ── Network stalls ────────────────────────────────────────────────────
    for conn in connections:
        if not is_model_api(conn["service"]):
            continue
        lastrcv_ms = conn.get("lastrcv_ms")
        if lastrcv_ms is None:
            continue
        lastrcv_sec = lastrcv_ms / 1000

        if lastrcv_sec >= crit_sec:
            alerts.append({
                "level":    "critical",
                "category": "network",
                "message":  f"No response from {conn['service']} for {fmt_duration(lastrcv_sec)}",
                "detail":   f"{conn['remote']}  sent={fmt_bytes(conn.get('bytes_sent'))}",
            })
        elif lastrcv_sec >= warn_sec:
            alerts.append({
                "level":    "warning",
                "category": "network",
                "message":  f"Slow response from {conn['service']} ({fmt_duration(lastrcv_sec)})",
                "detail":   f"{conn['remote']}",
            })

    # ── Process stalls ────────────────────────────────────────────────────
    for proc in processes:
        elapsed = proc["elapsed_sec"]
        if elapsed >= child_crit:
            alerts.append({
                "level":    "critical",
                "category": "process",
                "message":  f"Child process stuck for {proc['elapsed_str']}",
                "detail":   proc["command"][:80],
            })
        elif elapsed >= child_warn:
            alerts.append({
                "level":    "warning",
                "category": "process",
                "message":  f"Long-running child process ({proc['elapsed_str']})",
                "detail":   proc["command"][:80],
            })

    # ── Session freshness ─────────────────────────────────────────────────
    # Flag agents whose session file has gone cold while the gateway is alive.
    # This is a corroborating signal — not a stall by itself, but suspicious.
    for sess in sessions:
        idle = sess.get("idle_sec")
        if idle is None:
            continue
        if idle >= crit_sec:
            alerts.append({
                "level":    "warning",      # session staleness is advisory only
                "category": "session",
                "message":  f"Agent '{sess['agent_name']}' session file unchanged for {fmt_duration(idle)}",
                "detail":   f"session: {sess.get('session_id', '?')}",
            })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN HISTORY  (periodic full scan of all session files)
# ─────────────────────────────────────────────────────────────────────────────

# Cache so we don't rescan potentially hundreds of JSONL files every 2 seconds.
_token_history_cache: Dict      = {}
_token_history_lock              = threading.Lock()
_token_history_computed_at: float = 0.0


def compute_token_history(openclaw_dir: Path, agents: List[Dict]) -> Dict:
    """
    Scan every session JSONL file for every agent and aggregate token usage
    into five time buckets: last 5 min, 1 hour, 24 hours, 7 days, 30 days.

    Only files modified within the last 31 days are opened to bound I/O.
    Lines are streamed one at a time — large files are handled gracefully.

    Returns a dict with:
      "entries"  — list of per-agent-model rows (for the table)
      "totals"   — overall sums across all agents per bucket
      "computed_at" — unix timestamp of this computation
    """
    import datetime

    now = time.time()

    # Time bucket cutoffs (seconds since epoch)
    buckets = {
        "5m":    now - 5   * 60,
        "1h":    now - 60  * 60,
        "day":   now - 24  * 60 * 60,
        "week":  now - 7   * 24 * 60 * 60,
        "month": now - 31  * 24 * 60 * 60,
    }

    def empty_bucket() -> Dict:
        return {"input": 0, "output": 0, "cache": 0, "turns": 0}

    # { "agent_id/model": { agent_id, agent_name, model, provider, 5m, 1h, ... } }
    results: Dict[str, Dict] = {}

    for agent in agents:
        agent_id   = agent["id"]
        agent_name = agent.get("name", agent_id)
        sessions_dir = openclaw_dir / "agents" / agent_id / "sessions"
        if not sessions_dir.is_dir():
            continue

        for session_file in sessions_dir.iterdir():
            name = session_file.name
            if not name.endswith(".jsonl"):
                continue
            if any(x in name for x in [".deleted", ".reset", ".lock"]):
                continue
            if name == "sessions.json":
                continue

            # Skip files older than 31 days — nothing useful in them
            try:
                if session_file.stat().st_mtime < buckets["month"]:
                    continue
            except OSError:
                continue

            try:
                with open(session_file, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        inner = msg.get("message", {})
                        if inner.get("role") != "assistant":
                            continue
                        usage = inner.get("usage")
                        if not usage:
                            continue

                        # Parse the message timestamp
                        ts_str = msg.get("timestamp", "")
                        try:
                            ts = datetime.datetime.fromisoformat(
                                ts_str.rstrip("Z").split(".")[0]
                            ).timestamp()
                        except Exception:
                            continue

                        # Skip anything outside our oldest bucket
                        if ts < buckets["month"]:
                            continue

                        model    = inner.get("model", "unknown")
                        provider = inner.get("provider", "")
                        key      = f"{agent_id}/{model}"

                        if key not in results:
                            results[key] = {
                                "agent_id":   agent_id,
                                "agent_name": agent_name,
                                "model":      model,
                                "provider":   provider,
                                **{b: empty_bucket() for b in buckets},
                            }

                        inp = usage.get("input",     0) or 0
                        out = usage.get("output",    0) or 0
                        cac = usage.get("cacheRead", 0) or 0

                        for bucket_name, cutoff in buckets.items():
                            if ts >= cutoff:
                                results[key][bucket_name]["input"]  += inp
                                results[key][bucket_name]["output"] += out
                                results[key][bucket_name]["cache"]  += cac
                                results[key][bucket_name]["turns"]  += 1

            except Exception:
                continue

    # Compute overall totals across all agents
    totals = {b: empty_bucket() for b in buckets}
    for row in results.values():
        for b in buckets:
            for field in ("input", "output", "cache", "turns"):
                totals[b][field] += row[b][field]

    return {
        "computed_at": now,
        "entries":     list(results.values()),
        "totals":      totals,
    }


def get_token_history(openclaw_dir: Path, agents: List[Dict]) -> Dict:
    """
    Return cached token history, recomputing if the cache has expired.
    Thread-safe — safe to call from both the collector and HTTP threads.
    """
    global _token_history_cache, _token_history_computed_at

    ttl = CONFIG["history_cache_ttl_sec"]
    if time.time() - _token_history_computed_at > ttl:
        history = compute_token_history(openclaw_dir, agents)
        with _token_history_lock:
            _token_history_cache      = history
            _token_history_computed_at = time.time()

    with _token_history_lock:
        return dict(_token_history_cache)


# ─────────────────────────────────────────────────────────────────────────────
# RUNAWAY TOKEN DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_runaway(history: Dict, sessions: List[Dict]) -> List[Dict]:
    """
    Detect agents with anomalous token consumption using the token history.

    Three independent checks:

    1. Absolute spike — tokens used in the last 5 minutes exceeds
       CONFIG["runaway_abs_threshold"]. Catches tight loops immediately
       regardless of history.

    2. Rate anomaly — last-hour token rate is more than
       CONFIG["runaway_multiplier"] × the agent's average hourly rate over
       the past week. Only fires when weekly history exists (> 1000 tokens).

    3. Zero-output streak — consecutive assistant turns with no output tokens,
       detected from the session tail. The glm-4.7-flash silent retry pattern.
    """
    alerts = []
    abs_threshold  = CONFIG["runaway_abs_threshold"]
    multiplier     = CONFIG["runaway_multiplier"]
    zero_threshold = CONFIG["runaway_zero_output_turns"]

    # ── Checks 1 & 2: token rate from history ────────────────────────────
    for entry in history.get("entries", []):
        agent_label = f"{entry['agent_name']} / {entry['model']}"

        tokens_5m   = entry["5m"]["input"]   + entry["5m"]["output"]
        tokens_1h   = entry["1h"]["input"]   + entry["1h"]["output"]
        tokens_week = entry["week"]["input"]  + entry["week"]["output"]

        # Check 1: absolute spike in the last 5 minutes
        if tokens_5m >= abs_threshold:
            alerts.append({
                "level":    "critical",
                "category": "runaway",
                "message":  f"Token spike: {agent_label} used {fmt_num(tokens_5m)} tokens in last 5 min",
                "detail":   f"threshold: {fmt_num(abs_threshold)} tokens/5min",
            })

        # Check 2: rate anomaly vs weekly baseline
        # baseline_per_hour = weekly total / (7 days × 24 hours)
        baseline_per_hour = tokens_week / (7 * 24) if tokens_week > 1000 else 0
        if baseline_per_hour > 0 and tokens_1h > baseline_per_hour * multiplier:
            alerts.append({
                "level":    "warning",
                "category": "runaway",
                "message":  f"Above-baseline rate: {agent_label} — {fmt_num(tokens_1h)} tokens/hr (avg: {fmt_num(int(baseline_per_hour))})",
                "detail":   f"{multiplier}× weekly average threshold",
            })

    # ── Check 3: zero-output streak from session tail ─────────────────────
    for sess in sessions:
        streak = sess.get("zero_output_streak", 0)
        if streak >= zero_threshold:
            alerts.append({
                "level":    "critical",
                "category": "runaway",
                "message":  f"Silent retry loop: {sess['agent_name']} — {streak} consecutive turns with zero output",
                "detail":   f"model: {sess.get('last_model', '?')}  session: {sess.get('session_id', '?')}",
            })

    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# FORMATTING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "—"
    if n < 1024:
        return f"{n}B"
    if n < 1_048_576:
        return f"{n/1024:.1f}K"
    return f"{n/1_048_576:.1f}M"


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


def fmt_num(n: Optional[int]) -> str:
    if n is None:
        return "—"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1000:
        return f"{n/1000:.1f}k"
    return str(n)


def seconds_ago(iso_ts: Optional[str]) -> Optional[int]:
    """Convert an ISO-8601 timestamp string to 'seconds ago' (int)."""
    if not iso_ts:
        return None
    try:
        import datetime
        # Handle both with and without fractional seconds / Z suffix
        ts = iso_ts.rstrip("Z").split(".")[0]
        dt = datetime.datetime.fromisoformat(ts)
        utc_now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        return max(0, int((utc_now - dt).total_seconds()))
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# STATE AGGREGATOR
# ─────────────────────────────────────────────────────────────────────────────

# Shared state: updated by the background collector thread, read by HTTP handler
_state_lock = threading.Lock()
_current_state: Dict = {}
_sse_clients: List = []
_sse_clients_lock = threading.Lock()


def build_state(openclaw_dir: Path, agents: List[Dict], ip_map: Dict[str, str]) -> Dict:
    """
    Collect all data sources and return a single JSON-serialisable state dict.
    This is called every update_interval seconds by the background thread.
    """
    gateway_pid = find_gateway_pid()
    network     = collect_network(gateway_pid, ip_map)
    processes   = collect_processes(gateway_pid)
    sessions    = collect_sessions(openclaw_dir, agents)
    alerts      = detect_stalls(network, processes, sessions)

    # Token history is cached (recomputed every history_cache_ttl_sec).
    # detect_runaway adds its alerts to the same alerts list.
    history = get_token_history(openclaw_dir, agents)
    alerts += detect_runaway(history, sessions)

    # Annotate sessions with human-readable "X ago" strings
    for sess in sessions:
        ts = sess.get("last_event_ts")
        sess["last_event_ago"] = seconds_ago(ts)

    return {
        "ts":            int(time.time()),
        "gateway_pid":   gateway_pid,
        "gateway_up":    gateway_pid is not None,
        "network":       network,
        "processes":     processes,
        "sessions":      sessions,
        "alerts":        alerts,
        "token_history": history,
    }


def collector_loop(openclaw_dir: Path, agents: List[Dict], ip_map: Dict[str, str]) -> None:
    """
    Background thread: rebuilds state every update_interval seconds
    and pushes it to all connected SSE clients.
    """
    global _current_state
    while True:
        try:
            state = build_state(openclaw_dir, agents, ip_map)
            payload = json.dumps(state)

            with _state_lock:
                _current_state = state

            # Broadcast to all SSE clients
            with _sse_clients_lock:
                dead = []
                for client in _sse_clients:
                    try:
                        client.send_sse(payload)
                    except Exception:
                        dead.append(client)
                for d in dead:
                    _sse_clients.remove(d)

        except Exception as e:
            print(f"[monitor] collector error: {e}", file=sys.stderr)

        time.sleep(CONFIG["update_interval"])


# ─────────────────────────────────────────────────────────────────────────────
# HTTP SERVER
# ─────────────────────────────────────────────────────────────────────────────

class MonitorHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP handler serving:
      GET /          → the HTML dashboard (single-page app)
      GET /events    → SSE stream of state updates
      GET /api/state → current state as JSON snapshot
    """

    def log_message(self, fmt, *args):
        # Suppress default per-request logging to keep stdout clean
        pass

    def do_GET(self):
        if self.path == "/":
            self._serve_html()
        elif self.path == "/events":
            self._serve_sse()
        elif self.path == "/api/state":
            self._serve_json()
        else:
            self.send_error(404)

    def _serve_html(self):
        body = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self):
        with _state_lock:
            body = json.dumps(_current_state).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection",    "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Send the current state immediately so the page isn't blank
        with _state_lock:
            if _current_state:
                self.send_sse(json.dumps(_current_state))

        with _sse_clients_lock:
            _sse_clients.append(self)

        # Block until the client disconnects
        try:
            while True:
                time.sleep(1)
        except Exception:
            pass
        finally:
            with _sse_clients_lock:
                if self in _sse_clients:
                    _sse_clients.remove(self)

    def send_sse(self, data: str):
        """Write a single SSE data frame."""
        frame = f"data: {data}\n\n".encode("utf-8")
        self.wfile.write(frame)
        self.wfile.flush()


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD HTML  (embedded — no external dependencies)
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenClaw Monitor</title>
<style>
  :root {
    --bg:       #0f1117;
    --bg2:      #1a1d27;
    --bg3:      #22263a;
    --border:   #2e3250;
    --text:     #d0d6f0;
    --muted:    #6b7299;
    --green:    #3ddc84;
    --yellow:   #f0c040;
    --red:      #ff5577;
    --blue:     #5599ff;
    --font:     'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         font-size: 13px; padding: 16px; }

  header { display: flex; align-items: center; justify-content: space-between;
           margin-bottom: 16px; }
  header h1 { font-size: 16px; letter-spacing: 0.05em; color: #fff; }
  #conn-status { font-size: 11px; }
  #conn-dot { display: inline-block; width: 8px; height: 8px;
              border-radius: 50%; margin-right: 6px; background: var(--muted); }
  #conn-dot.live { background: var(--green); }
  #conn-dot.warn { background: var(--yellow); }

  section { background: var(--bg2); border: 1px solid var(--border);
            border-radius: 6px; margin-bottom: 12px; overflow: hidden; }
  section h2 { font-size: 11px; letter-spacing: 0.1em; color: var(--muted);
               padding: 8px 12px; border-bottom: 1px solid var(--border);
               text-transform: uppercase; }

  table { width: 100%; border-collapse: collapse; }
  th { font-size: 10px; color: var(--muted); text-align: left;
       padding: 6px 12px; border-bottom: 1px solid var(--border);
       text-transform: uppercase; letter-spacing: 0.06em; }
  td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg3); }

  .dot { display: inline-block; width: 7px; height: 7px;
         border-radius: 50%; margin-right: 5px; }
  .dot-green  { background: var(--green);  box-shadow: 0 0 6px var(--green); }
  .dot-yellow { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
  .dot-red    { background: var(--red);    box-shadow: 0 0 6px var(--red); }
  .dot-gray   { background: var(--muted); }

  .pill { display: inline-block; padding: 1px 7px; border-radius: 10px;
          font-size: 11px; border: 1px solid; }
  .pill-green  { color: var(--green);  border-color: var(--green);  background: #0d2418; }
  .pill-yellow { color: var(--yellow); border-color: var(--yellow); background: #251e08; }
  .pill-red    { color: var(--red);    border-color: var(--red);    background: #250810; }
  .pill-gray   { color: var(--muted);  border-color: var(--border); background: transparent; }

  .muted { color: var(--muted); }
  .mono  { font-family: var(--font); }

  #alerts-section { display: none; }
  .alert-row td { padding: 8px 12px; }
  .alert-row.critical td:first-child { border-left: 3px solid var(--red); }
  .alert-row.warning  td:first-child { border-left: 3px solid var(--yellow); }

  .empty-row td { color: var(--muted); padding: 10px 12px; font-style: italic; }

  #gateway-badge { font-size: 11px; padding: 2px 8px; border-radius: 4px;
                   margin-left: 10px; }
  footer { color: var(--muted); font-size: 11px; text-align: center;
           margin-top: 8px; }
</style>
</head>
<body>

<header>
  <h1>OpenClaw Monitor
    <span id="gateway-badge" class="pill pill-gray">gateway: —</span>
  </h1>
  <div id="conn-status">
    <span id="conn-dot"></span>
    <span id="conn-label">connecting…</span>
  </div>
</header>

<!-- ALERTS (hidden when empty) -->
<section id="alerts-section">
  <h2>⚠ Alerts</h2>
  <table><tbody id="alerts-body"></tbody></table>
</section>

<!-- AGENTS -->
<section>
  <h2>Agents</h2>
  <table>
    <thead><tr>
      <th>Agent</th><th>Last Event</th><th>Model</th>
      <th>In</th><th>Out</th><th>Cache</th>
      <th>Last Tool</th><th>Thinking</th>
    </tr></thead>
    <tbody id="agents-body"><tr class="empty-row"><td colspan="8">Waiting for data…</td></tr></tbody>
  </table>
</section>

<!-- CONNECTIONS -->
<section>
  <h2>Network Connections</h2>
  <table>
    <thead><tr>
      <th>Service</th><th>Conns</th><th>↑ Sent</th><th>↓ Recv</th>
      <th>Last RX</th><th>Status</th>
    </tr></thead>
    <tbody id="network-body" style="min-height:40px"><tr class="empty-row"><td colspan="6">Waiting for data…</td></tr></tbody>
  </table>
</section>

<!-- CHILD PROCESSES -->
<section>
  <h2>Child Processes</h2>
  <table>
    <thead><tr>
      <th>PID</th><th>Runtime</th><th>State</th><th>Command</th>
    </tr></thead>
    <tbody id="processes-body"><tr class="empty-row"><td colspan="4">No active child processes</td></tr></tbody>
  </table>
</section>

<!-- TOKEN USAGE -->
<section>
  <h2>Token Usage  <span style="font-size:10px;color:var(--muted);font-weight:normal;margin-left:8px">refreshes every 5 min — in / out</span></h2>
  <table>
    <thead><tr>
      <th>Agent</th><th>Model</th>
      <th>Last Hour</th><th>Last Day</th><th>Last Week</th><th>Last Month</th>
    </tr></thead>
    <tbody id="tokens-body"><tr class="empty-row"><td colspan="6">Computing token history…</td></tr></tbody>
  </table>
</section>

<footer id="footer">—</footer>

<script>
// ── Helpers ──────────────────────────────────────────────────────────────────

function dot(cls) {
  return `<span class="dot ${cls}"></span>`;
}

function fmtAgo(sec) {
  if (sec === null || sec === undefined) return '<span class="muted">—</span>';
  if (sec <  60)   return sec + 's ago';
  if (sec < 3600)  return Math.floor(sec/60) + 'm ' + (sec%60) + 's ago';
  return Math.floor(sec/3600) + 'h ' + Math.floor((sec%3600)/60) + 'm ago';
}

function fmtMs(ms) {
  if (ms === null || ms === undefined) return '<span class="muted">—</span>';
  const s = ms / 1000;
  if (s < 1)    return ms + 'ms';
  if (s < 60)   return s.toFixed(1) + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + Math.floor(s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

function esc(s) {
  if (!s) return '<span class="muted">—</span>';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Connection status dot based on lastrcv ────────────────────────────────
const WARN_MS = {{STALL_WARNING_MS}};
const CRIT_MS = {{STALL_CRITICAL_MS}};

function connStatusPill(conn) {
  const rcv = conn.lastrcv_ms;
  if (rcv === null || rcv === undefined) return '<span class="pill pill-gray">idle</span>';
  if (rcv < 5000)   return '<span class="pill pill-green">active</span>';
  if (rcv >= CRIT_MS) return '<span class="pill pill-red">stalled?</span>';
  if (rcv >= WARN_MS) return '<span class="pill pill-yellow">slow</span>';
  return '<span class="pill pill-gray">waiting</span>';
}

function agentStatusDot(sess) {
  const ago = sess.last_event_ago;
  if (ago === null || ago === undefined) return dot('dot-gray');
  if (ago < 10)   return dot('dot-green');
  if (ago < 60)   return dot('dot-yellow');
  return dot('dot-gray');
}

// ── Render functions ─────────────────────────────────────────────────────────

function renderAlerts(alerts) {
  const sec = document.getElementById('alerts-section');
  const tbody = document.getElementById('alerts-body');
  if (!alerts || alerts.length === 0) {
    sec.style.display = 'none';
    return;
  }
  sec.style.display = '';
  tbody.innerHTML = alerts.map(a => `
    <tr class="alert-row ${a.level}">
      <td>${a.level === 'critical' ? dot('dot-red') : dot('dot-yellow')}${esc(a.message)}</td>
      <td class="muted">${esc(a.detail)}</td>
    </tr>`).join('');
}

function renderAgents(sessions) {
  const tbody = document.getElementById('agents-body');
  if (!sessions || sessions.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No agents configured</td></tr>';
    return;
  }
  tbody.innerHTML = sessions.map(s => {
    const thought = s.last_thought || '';
    const thoughtShort = thought.length > 120 ? thought.slice(0,120) + '…' : thought;
    return `<tr>
      <td>${agentStatusDot(s)}<strong>${esc(s.agent_name)}</strong>
          <br><span class="muted" style="font-size:11px">${esc(s.session_id)}</span></td>
      <td class="muted">${s.session_id ? fmtAgo(s.last_event_ago) : '<span class="muted">no session</span>'}</td>
      <td style="font-size:11px">${esc(s.last_model)}<br><span class="muted">${esc(s.last_provider)}</span></td>
      <td class="mono">${esc(s.tokens_in   !== null ? Number(s.tokens_in).toLocaleString()    : null)}</td>
      <td class="mono">${esc(s.tokens_out  !== null ? Number(s.tokens_out).toLocaleString()   : null)}</td>
      <td class="mono">${esc(s.tokens_cache !== null ? Number(s.tokens_cache).toLocaleString() : null)}</td>
      <td style="font-size:11px">${esc(s.last_tool)}</td>
      <td style="font-size:11px;max-width:320px;color:var(--text)"
          title="${thought.replace(/"/g,'&quot;')}">${esc(thoughtShort) || '<span class="muted">—</span>'}</td>
    </tr>`;
  }).join('');
}

function renderNetwork(conns) {
  const tbody = document.getElementById('network-body');
  if (!conns || conns.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No connections (gateway down?)</td></tr>';
    return;
  }

  // Aggregate per-socket data into one stable row per service.
  // Individual sockets open/close constantly; service rows are stable.
  const byService = {};
  for (const c of conns) {
    const svc = c.service || c.remote;
    if (!byService[svc]) {
      byService[svc] = { service: svc, count: 0, bytes_sent: 0, bytes_received: 0, worst_lastrcv: null };
    }
    const g = byService[svc];
    g.count++;
    g.bytes_sent     += c.bytes_sent     || 0;
    g.bytes_received += c.bytes_received || 0;
    if (c.lastrcv_ms !== null && c.lastrcv_ms !== undefined) {
      g.worst_lastrcv = g.worst_lastrcv === null ? c.lastrcv_ms : Math.max(g.worst_lastrcv, c.lastrcv_ms);
    }
  }

  // Stable sort by service name so rows never jump around
  const rows = Object.values(byService).sort((a, b) => a.service.localeCompare(b.service));

  function svcStatusPill(g) {
    const rcv = g.worst_lastrcv;
    if (rcv === null)    return '<span class="pill pill-gray">idle</span>';
    if (rcv < 5000)      return '<span class="pill pill-green">active</span>';
    if (rcv >= CRIT_MS)  return '<span class="pill pill-red">stalled?</span>';
    if (rcv >= WARN_MS)  return '<span class="pill pill-yellow">slow</span>';
    return '<span class="pill pill-gray">waiting</span>';
  }

  tbody.innerHTML = rows.map(g => `
    <tr>
      <td><strong>${esc(g.service)}</strong></td>
      <td class="muted">${g.count}</td>
      <td class="mono">${fmtBytes(g.bytes_sent)}</td>
      <td class="mono">${fmtBytes(g.bytes_received)}</td>
      <td class="mono">${g.worst_lastrcv !== null ? fmtMs(g.worst_lastrcv) : '<span class="muted">—</span>'}</td>
      <td>${svcStatusPill(g)}</td>
    </tr>`).join('');
}

function fmtBytes(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024)       return n + 'B';
  if (n < 1048576)    return (n/1024).toFixed(1) + 'K';
  return (n/1048576).toFixed(1) + 'M';
}

function renderProcesses(procs) {
  const tbody = document.getElementById('processes-body');
  if (!procs || procs.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No active child processes</td></tr>';
    return;
  }
  const CWARN = {{CHILD_WARNING_SEC}};
  const CCRIT = {{CHILD_CRITICAL_SEC}};
  tbody.innerHTML = procs.map(p => {
    const d = p.elapsed_sec >= CCRIT ? 'dot-red' : p.elapsed_sec >= CWARN ? 'dot-yellow' : 'dot-green';
    return `<tr>
      <td class="muted mono">${p.pid}</td>
      <td>${dot(d)}${esc(p.elapsed_str)}</td>
      <td class="muted">${esc(p.stat)}</td>
      <td class="mono" style="font-size:11px;word-break:break-all">${esc(p.command)}</td>
    </tr>`;
  }).join('');
}

// ── Token usage table ────────────────────────────────────────────────────────

function fmtTok(n) {
  if (!n) return '<span class="muted">0</span>';
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000)    return (n/1000).toFixed(1) + 'k';
  return String(n);
}

function renderTokens(history) {
  const tbody = document.getElementById('tokens-body');
  if (!history || !history.entries || history.entries.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No data yet — history scans every 5 min</td></tr>';
    return;
  }
  const entries = history.entries.slice().sort((a, b) =>
    (a.agent_name + a.model).localeCompare(b.agent_name + b.model)
  );
  function cell(e, bucket) {
    const inp = e[bucket] ? e[bucket].input  : 0;
    const out = e[bucket] ? e[bucket].output : 0;
    if (!inp && !out) return '<span class="muted">—</span>';
    return `<span title="${Number(inp).toLocaleString()} in">${fmtTok(inp)}</span>`
         + ' <span class="muted">/</span> '
         + `<span title="${Number(out).toLocaleString()} out">${fmtTok(out)}</span>`;
  }
  tbody.innerHTML = entries.map(e => `
    <tr>
      <td><strong>${esc(e.agent_name)}</strong></td>
      <td class="muted" style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${esc(e.model)}">${esc(e.model)}</td>
      <td class="mono">${cell(e,'1h')}</td>
      <td class="mono">${cell(e,'day')}</td>
      <td class="mono">${cell(e,'week')}</td>
      <td class="mono">${cell(e,'month')}</td>
    </tr>`).join('');
}

// ── SSE connection with auto-reconnect ───────────────────────────────────────

let lastUpdateTs = null;

function connect() {
  const dot   = document.getElementById('conn-dot');
  const label = document.getElementById('conn-label');
  dot.className = '';
  label.textContent = 'connecting…';

  const es = new EventSource('/events');

  es.onmessage = function(e) {
    const state = JSON.parse(e.data);
    lastUpdateTs = Date.now();

    dot.className = 'live';
    label.textContent = 'live';

    // Gateway badge
    const badge = document.getElementById('gateway-badge');
    if (state.gateway_up) {
      badge.className = 'pill pill-green';
      badge.textContent = 'gateway: pid ' + state.gateway_pid;
    } else {
      badge.className = 'pill pill-red';
      badge.textContent = 'gateway: DOWN';
    }

    renderAlerts(state.alerts);
    renderAgents(state.sessions);
    renderNetwork(state.network);
    renderProcesses(state.processes);
    renderTokens(state.token_history);

    const d = new Date(state.ts * 1000);
    document.getElementById('footer').textContent =
      'Last update: ' + d.toLocaleTimeString() + '  ·  ' + state.sessions.length + ' agent(s)  ·  ' +
      state.network.length + ' connection(s)';
  };

  es.onerror = function() {
    dot.className = 'warn';
    label.textContent = 'reconnecting…';
    es.close();
    setTimeout(connect, 3000);
  };
}

connect();

// Stale indicator: if we haven't received an update in 10s, show warning
setInterval(function() {
  if (lastUpdateTs && Date.now() - lastUpdateTs > 10000) {
    document.getElementById('conn-dot').className = 'warn';
    document.getElementById('conn-label').textContent = 'stale';
  }
}, 5000);
</script>
</body>
</html>
"""


def build_html() -> str:
    """Inject Python config values into the HTML template."""
    return (DASHBOARD_HTML
        .replace("{{STALL_WARNING_MS}}",  str(CONFIG["stall_warning_sec"]  * 1000))
        .replace("{{STALL_CRITICAL_MS}}", str(CONFIG["stall_critical_sec"] * 1000))
        .replace("{{CHILD_WARNING_SEC}}",  str(CONFIG["child_warning_sec"]))
        .replace("{{CHILD_CRITICAL_SEC}}", str(CONFIG["child_critical_sec"]))
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OpenClaw real-time monitor dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port",     type=int,   default=None,
                        help=f"HTTP port (default: {CONFIG['port']})")
    parser.add_argument("--dir",      type=str,   default=None,
                        help="Path to openclaw data directory (default: ~/.openclaw)")
    parser.add_argument("--interval", type=float, default=None,
                        help=f"Refresh interval in seconds (default: {CONFIG['update_interval']})")
    args = parser.parse_args()

    # Apply CLI overrides to CONFIG
    if args.port:
        CONFIG["port"] = args.port
    if args.interval:
        CONFIG["update_interval"] = args.interval

    # Auto-detect environment
    try:
        openclaw_dir = find_openclaw_dir(args.dir)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    agents = load_agent_list(openclaw_dir)
    if not agents:
        print("Warning: no agents found in openclaw.json, will scan filesystem",
              file=sys.stderr)

    ip_map = build_ip_service_map(openclaw_dir)

    # Inject config into HTML template
    global DASHBOARD_HTML
    DASHBOARD_HTML = build_html()

    print(f"OpenClaw Monitor")
    print(f"  openclaw dir : {openclaw_dir}")
    print(f"  gateway pid  : {find_gateway_pid() or 'not running'}")
    print(f"  agents       : {[a['id'] for a in agents]}")
    print(f"  interval     : {CONFIG['update_interval']}s")
    # Resolve the machine's LAN IP for a useful clickable URL in the output.
    # Uses a UDP connect trick (no packets sent) to find which local interface
    # would be used to reach the broader network. Falls back gracefully.
    try:
        if CONFIG["bind"] == "127.0.0.1":
            display_host = "localhost"
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            display_host = s.getsockname()[0]
            s.close()
    except Exception:
        display_host = CONFIG["bind"] or "localhost"
    print(f"  bind         : {CONFIG['bind']}:{CONFIG['port']}")
    print(f"  dashboard    : http://{display_host}:{CONFIG['port']}")
    print()

    # Start background data collector
    t = threading.Thread(
        target=collector_loop,
        args=(openclaw_dir, agents, ip_map),
        daemon=True,
    )
    t.start()

    # Start HTTP server (blocking)
    server = HTTPServer((CONFIG["bind"], CONFIG["port"]), MonitorHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
