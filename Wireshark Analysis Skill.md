---
name: wireshark-capture-analysis
description: >
  Use this skill for any task involving network packet capture, traffic analysis, or pcap file inspection using Wireshark/tshark. Trigger this skill whenever the user mentions:
  capturing network traffic, listing network interfaces, analyzing a .pcap or .pcapng file, extracting protocols/DNS/HTTP/TCP/UDP from captures, checking for suspicious network activity, getting protocol breakdowns, following TCP or UDP streams, or exporting packet data.
  Also trigger for phrases like "start a capture", "stop the capture", "analyze my capture", "what protocols were used", "check for suspicious activity", "extract DNS queries", "show HTTP requests", or "give me a protocol breakdown". Always use this skill even if the user only partially describes a network analysis task.
---

# Wireshark Capture & Analysis Skill

A skill for capturing live network traffic and analyzing pcap files using the Wireshark MCP tools.

## Available Tools (all 10)

| Tool | Purpose |
|------|---------|
| `wireshark:list_interfaces` | List all network interfaces available for capture |
| `wireshark:live_capture` | Capture live traffic on a named interface |
| `wireshark:summarize_pcap` | High-level summary: packet count, duration, top protocols, top talkers |
| `wireshark:read_pcap` | Read packets from a pcap file, with optional display filter |
| `wireshark:display_filter` | Apply a Wireshark display filter expression to a pcap file |
| `wireshark:stats_by_proto` | Generate protocol statistics table from a pcap file |
| `wireshark:follow_tcp` | Follow a TCP stream and extract its payload |
| `wireshark:follow_udp` | Follow a UDP stream and extract its payload |
| `wireshark:export_json` | Export packets (with optional filter) to JSON |
| `wireshark:check_installation` | Verify tshark/Wireshark is installed and show version |

---

## Workflow by User Intent

### "List my network interfaces"
```
→ wireshark:list_interfaces
```
Present the list clearly. Note the interface names the user can use for capturing. Windows interfaces often look like "Ethernet 6" or "Wi-Fi"; Linux like "eth0", "wlan0".

---

### "Start a capture on [interface]" / "Capture traffic on [interface]"
```
→ wireshark:live_capture
    interface: <exact interface name from user>
    duration: <seconds, default 60 if unspecified>
    display_filter: <optional, if user specified a filter>
    packet_count: <optional cap>
```
- If the user hasn't listed interfaces first, you can attempt capture with the name they gave.
- After capture completes, tell the user where the file was saved (the tool returns a file path).
- Store the returned file path — it will be needed for subsequent analysis steps.
- Offer to analyze the capture immediately.

---

### "Stop the capture"
Live captures run for a fixed `duration`. There is no mid-capture stop command via MCP.
- If a capture is running, inform the user it will complete at the end of its duration.
- If no capture is currently running, clarify that captures are duration-based.

---

### "Analyze the last capture" / "What protocols were used?"
Run both tools together for a complete picture:
```
→ wireshark:summarize_pcap(file_path)
→ wireshark:stats_by_proto(file_path)
```
Summarize findings: total packets, capture duration, top protocols by count/bytes, top source/destination talkers.

---

### "Check [file] for suspicious activity"
Run a layered analysis:
```
1. wireshark:summarize_pcap(file_path)         — baseline overview
2. wireshark:stats_by_proto(file_path)         — protocol anomalies
3. wireshark:display_filter(file_path, "tcp.flags.syn==1 && tcp.flags.ack==0")  — SYN scans
4. wireshark:display_filter(file_path, "icmp")  — ICMP flood/ping sweep
5. wireshark:display_filter(file_path, "dns")   — DNS tunneling / unusual queries
6. wireshark:display_filter(file_path, "http")  — Cleartext HTTP (potential data leak)
```
Look for:
- **Port scanning**: high SYN count to many ports from one host
- **DNS tunneling**: unusually long DNS query names, high DNS volume
- **Cleartext credentials**: HTTP POST to login endpoints
- **Beaconing**: regular timed connections to external IPs
- **Unusual protocols**: unexpected protocols for the network (e.g. IRC, Telnet)
- **Large data transfers**: single flows with very high byte counts

Summarize risk level (low/medium/high) with specific findings and packet examples.

---

### "Extract all DNS queries from my capture"
```
→ wireshark:display_filter(file_path, filter="dns.qry.name")
```
If that filter isn't supported directly, use:
```
→ wireshark:display_filter(file_path, filter="dns")
```
Present: queried domain names, query types (A, AAAA, MX, TXT), source hosts, response codes.

---

### "Show me all HTTP requests"
```
→ wireshark:display_filter(file_path, filter="http.request")
```
Present: method (GET/POST/etc), URI, Host header, source IP. Flag any POST requests as potentially containing credentials or form data.

---

### "Give me a protocol breakdown of [file]"
```
→ wireshark:stats_by_proto(file_path)
→ wireshark:summarize_pcap(file_path)
```
Present a clean table with protocol names, packet counts, and percentages. Highlight the top 5 protocols.

---

### "Follow TCP/UDP stream [N]"
```
→ wireshark:follow_tcp(file_path, stream_id=N)   # for TCP
→ wireshark:follow_udp(file_path, stream_id=N)   # for UDP
```
Default stream_id is 0 if not specified. Present the payload clearly — note if it contains readable text (HTTP, SMTP, FTP) vs binary.

---

### "Export packets to JSON" / "I need the raw packet data"
```
→ wireshark:export_json(file_path, output_path, display_filter=<optional>)
```
Tell the user where the JSON was saved. Offer to filter first (e.g. only DNS, only HTTP) to reduce file size.

---

## Key Display Filter Reference

| Goal | Filter |
|------|--------|
| DNS queries | `dns` or `dns.qry.name` |
| HTTP requests | `http.request` |
| HTTP responses | `http.response` |
| HTTPS/TLS | `tls` |
| SYN scan detection | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| ICMP traffic | `icmp` |
| Specific IP | `ip.addr == 192.168.1.1` |
| Specific port | `tcp.port == 443` |
| ARP | `arp` |
| FTP | `ftp` |
| SMTP | `smtp` |
| Large packets | `frame.len > 1400` |

---

## File Path Handling

- **Live captures** produce a file path returned by `wireshark:live_capture`. Save it in context for follow-up analysis.
- **User-supplied pcap files** are typically at a path the user specifies (e.g. `capture.pcap`, `/home/user/capture.pcap`, or an uploaded file at `/mnt/user-data/uploads/capture.pcap`).
- If the user says "my capture" or "the last capture" without specifying a path, ask them to confirm the file path or check `/mnt/user-data/uploads/` for recent uploads.

---

## Response Format Guidelines

- **Captures**: confirm interface, duration, packet count, and output file path.
- **Summaries**: use a brief table or bullet list — don't dump raw output verbatim.
- **Suspicious activity**: lead with a risk summary, then detail specific findings with packet examples.
- **Protocol breakdowns**: table with Protocol | Packets | % of traffic.
- **Errors**: if a tool fails, check whether tshark is installed (`wireshark:check_installation`) and report clearly.
