"""
Wireshark MCP Server for Claude Desktop
----------------------------------------
Bridges Claude Desktop with Wireshark/TShark so Claude can
capture, read, and analyze network traffic in real time.

Transport: stdio (for Claude Desktop)
Requires : TShark installed + added to PATH, Python 3.9+
"""

import asyncio
import json
import subprocess
import os
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    CallToolResult,
)

# ── Configuration ──────────────────────────────────────────────────────────────

# Default TShark path on Windows. Change if yours differs.
TSHARK_PATH = os.environ.get(
    "TSHARK_PATH",
    r"C:\Program Files\Wireshark\tshark.exe",
)

# Where captured .pcap files are saved
# Default: C:\Users\YourUsername\Documents\Wireshark_captures
_default_capture_dir = Path.home() / "Documents" / "Wireshark_captures"
CAPTURE_DIR = Path(os.environ.get("WIRESHARK_CAPTURE_DIR", _default_capture_dir))

# Create the capture directory if it does not already exist
try:
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
except Exception as _dir_err:
    print(f"WARNING: Could not create capture directory {CAPTURE_DIR}: {_dir_err}", file=sys.stderr)
    CAPTURE_DIR = Path.home()
    print(f"WARNING: Falling back to capture directory: {CAPTURE_DIR}", file=sys.stderr)

# Active capture process (only one at a time)
_active_capture: dict[str, Any] = {}

# ── Server Init ────────────────────────────────────────────────────────────────

app = Server("wireshark-mcp")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run_tshark(args: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a TShark command and return (stdout, stderr, returncode)."""
    cmd = [TSHARK_PATH] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"TShark not found at: {TSHARK_PATH}\nSet TSHARK_PATH env var or install Wireshark.", 1
    except subprocess.TimeoutExpired:
        return "", f"TShark command timed out after {timeout}s.", 1


def _format_error(msg: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"❌ ERROR: {msg}")])


def _format_ok(msg: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=msg)])


# ── Tool Definitions ───────────────────────────────────────────────────────────

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_interfaces",
            description=(
                "List all available network interfaces that TShark can capture on. "
                "Run this first to find the correct interface name or number."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="start_capture",
            description=(
                "Start a live packet capture on a specified network interface. "
                "Captures run in the background. Only one capture can run at a time. "
                "Use stop_capture to end it. The capture is saved as a .pcap file."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Interface name or number from list_interfaces (e.g. '1' or 'Ethernet')",
                    },
                    "duration_seconds": {
                        "type": "integer",
                        "description": "How many seconds to capture. Omit for indefinite capture (stop manually).",
                    },
                    "capture_filter": {
                        "type": "string",
                        "description": "BPF capture filter e.g. 'tcp port 80' or 'host 192.168.1.1'. Optional.",
                    },
                    "packet_count": {
                        "type": "integer",
                        "description": "Stop after this many packets. Optional.",
                    },
                    "output_filename": {
                        "type": "string",
                        "description": "Output .pcap filename (no path). Defaults to timestamped name.",
                    },
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="stop_capture",
            description="Stop the currently running live packet capture.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="capture_status",
            description="Check whether a live capture is currently running and get its details.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="read_pcap",
            description=(
                "Read and summarize packets from a .pcap file. "
                "Supports display filters to focus on specific traffic."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Full path to the .pcap or .pcapng file. If only filename given, looks in default capture dir.",
                    },
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter e.g. 'http', 'dns', 'tcp.flags.syn==1'. Optional.",
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Max packets to return (default 50, max 500).",
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Specific fields to extract e.g. ['ip.src','ip.dst','tcp.port']. "
                            "If omitted, returns a human-readable one-line summary per packet."
                        ),
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="pcap_statistics",
            description=(
                "Generate protocol hierarchy statistics and conversation summaries "
                "from a .pcap file. Great for a quick overview of what's in a capture."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap file.",
                    },
                    "stat_type": {
                        "type": "string",
                        "enum": ["protocol_hierarchy", "conversations_ip", "conversations_tcp", "io_stat", "endpoints"],
                        "description": "Type of statistics to generate. Default: protocol_hierarchy.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="detect_suspicious",
            description=(
                "Run heuristic checks on a .pcap file to flag potentially suspicious activity: "
                "port scans, DNS anomalies, cleartext credentials, large data transfers, "
                "and connections to non-standard ports."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the .pcap file to analyze.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="extract_http",
            description=(
                "Extract HTTP requests and responses from a .pcap file, "
                "including URLs, methods, status codes, and User-Agent strings."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the .pcap file."},
                    "show_responses": {
                        "type": "boolean",
                        "description": "Include HTTP response codes. Default true.",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="extract_dns",
            description=(
                "Extract all DNS queries and responses from a .pcap file. "
                "Useful for spotting suspicious domain lookups or DNS tunneling."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the .pcap file."},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_captures",
            description="List all .pcap files saved in the default capture directory.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="tshark_custom",
            description=(
                "Run a custom TShark command with arbitrary arguments. "
                "For advanced users who know TShark CLI flags. "
                "The -r (read file) or -i (interface) must be provided by you."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "TShark CLI arguments e.g. ['-r','capture.pcap','-Y','http','-T','fields','-e','http.request.uri']",
                    },
                },
                "required": ["args"],
            },
        ),
    ]


# ── Tool Handlers ──────────────────────────────────────────────────────────────

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> CallToolResult:
    match name:
        case "list_interfaces":
            return await _list_interfaces()
        case "start_capture":
            return await _start_capture(arguments)
        case "stop_capture":
            return await _stop_capture()
        case "capture_status":
            return await _capture_status()
        case "read_pcap":
            return await _read_pcap(arguments)
        case "pcap_statistics":
            return await _pcap_statistics(arguments)
        case "detect_suspicious":
            return await _detect_suspicious(arguments)
        case "extract_http":
            return await _extract_http(arguments)
        case "extract_dns":
            return await _extract_dns(arguments)
        case "list_captures":
            return await _list_captures()
        case "tshark_custom":
            return await _tshark_custom(arguments)
        case _:
            return _format_error(f"Unknown tool: {name}")


# ── Tool Implementations ───────────────────────────────────────────────────────

async def _list_interfaces() -> CallToolResult:
    stdout, stderr, code = _run_tshark(["-D"])
    if code != 0:
        return _format_error(stderr or "Could not list interfaces.")
    lines = stdout.strip().split("\n")
    out = "📡 Available Network Interfaces:\n\n"
    for line in lines:
        out += f"  {line}\n"
    out += "\nUse the number or name in start_capture."
    return _format_ok(out)


async def _start_capture(args: dict) -> CallToolResult:
    global _active_capture
    if _active_capture.get("process") and _active_capture["process"].poll() is None:
        return _format_error(
            f"A capture is already running on interface '{_active_capture['interface']}'. "
            "Call stop_capture first."
        )

    interface = args["interface"]
    duration = args.get("duration_seconds")
    cap_filter = args.get("capture_filter")
    count = args.get("packet_count")
    filename = args.get("output_filename") or f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    out_path = CAPTURE_DIR / filename

    cmd_args = ["-i", interface, "-w", str(out_path)]
    if duration:
        cmd_args += ["-a", f"duration:{duration}"]
    if cap_filter:
        cmd_args += ["-f", cap_filter]
    if count:
        cmd_args += ["-c", str(count)]

    try:
        proc = subprocess.Popen(
            [TSHARK_PATH] + cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _active_capture = {
            "process": proc,
            "interface": interface,
            "output": str(out_path),
            "started": datetime.now().isoformat(),
            "filter": cap_filter,
        }
        msg = (
            f"✅ Capture started!\n\n"
            f"  Interface : {interface}\n"
            f"  Output    : {out_path}\n"
            f"  Filter    : {cap_filter or 'none'}\n"
            f"  Duration  : {f'{duration}s' if duration else 'until stop_capture'}\n"
            f"  Pkt limit : {count or 'unlimited'}\n\n"
            "Use stop_capture to end it, then read_pcap to analyze."
        )
        return _format_ok(msg)
    except FileNotFoundError:
        return _format_error(f"TShark not found at: {TSHARK_PATH}")
    except Exception as e:
        return _format_error(str(e))


async def _stop_capture() -> CallToolResult:
    global _active_capture
    proc = _active_capture.get("process")
    if not proc or proc.poll() is not None:
        return _format_ok("ℹ️ No active capture is running.")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    out_path = _active_capture.get("output", "unknown")
    _active_capture = {}
    return _format_ok(
        f"🛑 Capture stopped.\n\n"
        f"  File saved: {out_path}\n\n"
        "Use read_pcap or pcap_statistics to analyze."
    )


async def _capture_status() -> CallToolResult:
    proc = _active_capture.get("process")
    if not proc or proc.poll() is not None:
        return _format_ok("ℹ️ No capture is currently running.")
    return _format_ok(
        f"🔴 Capture is ACTIVE\n\n"
        f"  Interface : {_active_capture['interface']}\n"
        f"  Output    : {_active_capture['output']}\n"
        f"  Started   : {_active_capture['started']}\n"
        f"  Filter    : {_active_capture.get('filter') or 'none'}"
    )


def _resolve_pcap(file_path: str) -> Path:
    p = Path(file_path)
    if p.is_absolute():
        return p
    candidate = CAPTURE_DIR / file_path
    if candidate.exists():
        return candidate
    return p


async def _read_pcap(args: dict) -> CallToolResult:
    path = _resolve_pcap(args["file_path"])
    if not path.exists():
        return _format_error(f"File not found: {path}")

    display_filter = args.get("display_filter")
    max_pkts = min(args.get("max_packets", 50), 500)
    fields = args.get("fields")

    cmd_args = ["-r", str(path), "-c", str(max_pkts)]
    if display_filter:
        cmd_args += ["-Y", display_filter]

    if fields:
        cmd_args += ["-T", "fields"]
        for f in fields:
            cmd_args += ["-e", f]
        cmd_args += ["-E", "header=y", "-E", "separator=,"]
    else:
        cmd_args += ["-V" if False else "-P"]   # one-line summary per packet

    stdout, stderr, code = _run_tshark(cmd_args, timeout=60)
    if code != 0 and not stdout:
        return _format_error(stderr or "TShark returned an error.")

    header = (
        f"📦 Packet data from: {path.name}\n"
        f"   Filter : {display_filter or 'none'}\n"
        f"   Showing: up to {max_pkts} packets\n\n"
    )
    if not stdout.strip():
        return _format_ok(header + "No packets matched the filter.")
    return _format_ok(header + stdout)


async def _pcap_statistics(args: dict) -> CallToolResult:
    path = _resolve_pcap(args["file_path"])
    if not path.exists():
        return _format_error(f"File not found: {path}")

    stat_type = args.get("stat_type", "protocol_hierarchy")

    stat_map = {
        "protocol_hierarchy": ["-r", str(path), "-q", "-z", "io,phs"],
        "conversations_ip":   ["-r", str(path), "-q", "-z", "conv,ip"],
        "conversations_tcp":  ["-r", str(path), "-q", "-z", "conv,tcp"],
        "io_stat":            ["-r", str(path), "-q", "-z", "io,stat,1"],
        "endpoints":          ["-r", str(path), "-q", "-z", "endpoints,ip"],
    }

    cmd_args = stat_map.get(stat_type, stat_map["protocol_hierarchy"])
    stdout, stderr, code = _run_tshark(cmd_args, timeout=60)

    if code != 0 and not stdout:
        return _format_error(stderr or "Statistics failed.")

    return _format_ok(f"📊 Statistics [{stat_type}] — {path.name}\n\n{stdout}")


async def _detect_suspicious(args: dict) -> CallToolResult:
    path = _resolve_pcap(args["file_path"])
    if not path.exists():
        return _format_error(f"File not found: {path}")

    findings = []

    # 1. SYN scan detection (many SYN, few SYN-ACK from unique IPs)
    stdout, _, _ = _run_tshark(
        ["-r", str(path), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport"],
        timeout=30,
    )
    if stdout:
        lines = [l for l in stdout.strip().split("\n") if l]
        unique_ports = set()
        for l in lines:
            parts = l.split("\t")
            if len(parts) == 2:
                unique_ports.add(parts[1])
        if len(unique_ports) > 20:
            findings.append(
                f"🚨 POSSIBLE PORT SCAN: {len(lines)} SYN packets to {len(unique_ports)} unique ports detected."
            )

    # 2. DNS anomalies — unusually long hostnames (possible DNS tunneling)
    stdout, _, _ = _run_tshark(
        ["-r", str(path), "-Y", "dns.qry.name",
         "-T", "fields", "-e", "dns.qry.name"],
        timeout=30,
    )
    if stdout:
        domains = [d.strip() for d in stdout.strip().split("\n") if d.strip()]
        long_domains = [d for d in domains if len(d) > 60]
        if long_domains:
            findings.append(
                f"⚠️  DNS TUNNELING INDICATOR: {len(long_domains)} unusually long DNS queries found.\n"
                + "\n".join(f"    • {d[:80]}..." if len(d) > 80 else f"    • {d}" for d in long_domains[:5])
            )

    # 3. Cleartext credentials — HTTP basic auth
    stdout, _, _ = _run_tshark(
        ["-r", str(path), "-Y", 'http.authorization contains "Basic"',
         "-T", "fields", "-e", "ip.src", "-e", "http.authorization"],
        timeout=30,
    )
    if stdout and stdout.strip():
        count = len([l for l in stdout.strip().split("\n") if l])
        findings.append(
            f"🔑 CLEARTEXT CREDENTIALS: {count} HTTP Basic Auth packet(s) detected — credentials sent in cleartext!"
        )

    # 4. Large data transfers
    stdout, _, _ = _run_tshark(
        ["-r", str(path), "-q", "-z", "conv,ip"],
        timeout=30,
    )
    if stdout:
        for line in stdout.split("\n"):
            parts = line.split()
            # Look for byte transfers > 100MB in a single conversation
            for i, p in enumerate(parts):
                try:
                    val = int(p.replace(",", ""))
                    if val > 100_000_000:
                        findings.append(
                            f"📤 LARGE TRANSFER: A single IP conversation transferred >100 MB of data.\n    Line: {line.strip()}"
                        )
                        break
                except ValueError:
                    pass

    # 5. Non-standard port connections (not 80, 443, 53, 22, 25, 21)
    common_ports = {"80", "443", "53", "22", "25", "21", "110", "143", "8080", "3389"}
    stdout, _, _ = _run_tshark(
        ["-r", str(path), "-Y", "tcp",
         "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport"],
        timeout=30,
    )
    if stdout:
        unusual = {}
        for line in stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) == 2 and parts[1] not in common_ports:
                port = parts[1]
                unusual[port] = unusual.get(port, 0) + 1
        if unusual:
            top = sorted(unusual.items(), key=lambda x: -x[1])[:5]
            findings.append(
                "🔌 NON-STANDARD PORTS with TCP traffic:\n"
                + "\n".join(f"    • Port {port}: {cnt} packets" for port, cnt in top)
            )

    if not findings:
        return _format_ok(
            f"✅ No obvious suspicious patterns detected in {path.name}.\n\n"
            "Note: This is a heuristic check only — not a replacement for full forensic analysis."
        )

    report = (
        f"🔍 SUSPICIOUS ACTIVITY REPORT — {path.name}\n"
        f"{'='*60}\n\n"
        + "\n\n".join(findings)
        + "\n\n⚠️  This is an automated heuristic scan. Verify each finding manually."
    )
    return _format_ok(report)


async def _extract_http(args: dict) -> CallToolResult:
    path = _resolve_pcap(args["file_path"])
    if not path.exists():
        return _format_error(f"File not found: {path}")

    show_responses = args.get("show_responses", True)

    # Extract requests
    req_args = [
        "-r", str(path),
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.user_agent",
        "-E", "header=y",
        "-E", "separator=\t",
    ]
    req_out, _, _ = _run_tshark(req_args, timeout=60)

    out = f"🌐 HTTP Traffic in {path.name}\n{'='*60}\n\n"

    if req_out.strip():
        out += "── REQUESTS ──\n" + req_out + "\n"
    else:
        out += "No HTTP requests found.\n"

    if show_responses:
        resp_args = [
            "-r", str(path),
            "-Y", "http.response",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "http.response.code",
            "-e", "http.response.phrase",
            "-e", "http.content_type",
            "-E", "header=y",
            "-E", "separator=\t",
        ]
        resp_out, _, _ = _run_tshark(resp_args, timeout=60)
        if resp_out.strip():
            out += "\n── RESPONSES ──\n" + resp_out

    return _format_ok(out)


async def _extract_dns(args: dict) -> CallToolResult:
    path = _resolve_pcap(args["file_path"])
    if not path.exists():
        return _format_error(f"File not found: {path}")

    cmd_args = [
        "-r", str(path),
        "-Y", "dns",
        "-T", "fields",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-e", "dns.resp.name",
        "-e", "dns.a",
        "-E", "header=y",
        "-E", "separator=\t",
    ]
    stdout, stderr, code = _run_tshark(cmd_args, timeout=60)

    if code != 0 and not stdout:
        return _format_error(stderr or "DNS extraction failed.")

    out = f"🌍 DNS Traffic in {path.name}\n{'='*60}\n\n"
    if stdout.strip():
        out += stdout
    else:
        out += "No DNS traffic found in this capture."
    return _format_ok(out)


async def _list_captures() -> CallToolResult:
    files = sorted(CAPTURE_DIR.glob("*.pcap*"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        return _format_ok(f"📁 No .pcap files found in: {CAPTURE_DIR}")
    out = f"📁 Captures in {CAPTURE_DIR}:\n\n"
    for f in files:
        size_kb = f.stat().st_size / 1024
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        out += f"  {f.name:<40} {size_kb:>8.1f} KB   {mtime}\n"
    return _format_ok(out)


async def _tshark_custom(args: dict) -> CallToolResult:
    cmd_args = args.get("args", [])
    if not cmd_args:
        return _format_error("No arguments provided.")
    stdout, stderr, code = _run_tshark(cmd_args, timeout=120)
    output = stdout or stderr or "(no output)"
    return _format_ok(f"TShark output (exit {code}):\n\n{output}")


# ── Entry Point ────────────────────────────────────────────────────────────────

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
