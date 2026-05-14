# 🦈 Wireshark MCP Server for Claude Desktop
### Windows Setup Guide — Connect Claude AI to Wireshark

---

## What This Does

This setup connects **Claude Desktop** to **Wireshark/TShark** using the
`mcp-wireshark` package, giving Claude the ability to:

| Tool | Description |
|---|---|
| `list_interfaces` | Show all network interfaces available for capture |
| `start_capture` | Begin a live packet capture in the background |
| `stop_capture` | Stop an active capture |
| `read_pcap` | Read packets from a .pcap file with optional filters |
| `pcap_statistics` | Protocol hierarchy, conversations, IO stats |
| `detect_suspicious` | Scan for port scans, DNS tunneling, cleartext credentials |
| `extract_http` | Pull all HTTP requests/responses from a capture |
| `extract_dns` | Extract all DNS queries and answers |

---

## What You Need Before Starting

| Requirement | How to Check |
|---|---|
| Windows 10 | You are on it already |
| Wireshark installed | Open Start Menu and search "Wireshark" — it should appear |
| Python 3.9+ | Open Command Prompt and type: python --version |
| Claude Desktop | Download from https://claude.ai/download |

---

## Installation — Step by Step

### Step 1 — Install Python (if not already installed)

1. Go to https://www.python.org/downloads/
2. Click the big yellow "Download Python" button
3. Run the downloaded installer
4. IMPORTANT: Before clicking Install, tick the checkbox at the bottom:
   "Add python.exe to PATH"
5. Click "Install Now" and wait for it to finish

Verify it worked:
- Press Windows key + R, type cmd, press Enter
- Type: python --version
- You should see something like: Python 3.12.4

---

### Step 2 — Install the Wireshark MCP package

Open Command Prompt and type:

    pip install mcp-wireshark

Wait for it to finish. You should see "Successfully installed mcp-wireshark".

---

### Step 3 — Verify TShark is working

In the same Command Prompt window, type:

    tshark -v

You should see a version number. If you get an error:
- Open Wireshark
- Go to Help > About Wireshark and check TShark is listed
- If not, reinstall Wireshark from https://www.wireshark.org/download.html
  and make sure TShark is ticked during installation

---

### Step 4 — Edit the Claude Desktop config file

1. Press Windows key + R
2. Paste this into the box and press Enter:
   %APPDATA%\Claude
3. A folder will open. Find the file called: claude_desktop_config.json
4. Right-click it > Open with > Notepad
5. Select all the text (Ctrl+A) and delete it
6. Paste in EXACTLY the following:

{
  "preferences": {
    "coworkWebSearchEnabled": true,
    "sidebarMode": "chat",
    "coworkScheduledTasksEnabled": true,
    "ccdScheduledTasksEnabled": true
  },
  "mcpServers": {
    "wireshark": {
      "command": "mcp-wireshark",
      "env": {
        "PATH": "C:\\Program Files\\Wireshark;C:\\Windows\\System32"
      }
    }
  }
}

7. Press Ctrl+S to save, then close Notepad

NOTE: The double backslashes \\ in the PATH are required in JSON files.
Do not change them to single backslashes.

---

### Step 5 — Restart Claude Desktop as Administrator

Live packet capture on Windows requires Administrator privileges.

1. Find Claude Desktop in the taskbar (bottom right, near the clock)
2. Right-click it > Quit
3. Find the Claude Desktop shortcut on your Desktop or Start Menu
4. Right-click it > Run as administrator
5. Click Yes on the security prompt

---

### Step 6 — Test the connection

Type this in the Claude Desktop chat:

    List my network interfaces

Claude should respond with a numbered list of your network adapters such as
Wi-Fi and Ethernet. If it does, you are connected and ready to go.

---

## Usage Examples

Once connected, talk to Claude naturally:

    "List my network interfaces"
    "Start a 60 second capture on interface 1"
    "Stop the capture"
    "Analyze the last capture — what protocols were used?"
    "Check my capture.pcap for any suspicious activity"
    "Extract all DNS queries from my capture"
    "Show me all HTTP requests in the capture"
    "Give me a protocol breakdown of capture.pcap"

---

## Where Captures Are Saved

All .pcap files captured by the MCP server are saved to:

    C:\Users\YourUsername\Documents\Wireshark_captures

This folder must exist before captures are run. If you have not created
it yet, do so now:

1. Open File Explorer
2. Navigate to: C:\Users\YourUsername\Documents
3. Right-click > New > Folder
4. Name it exactly: Wireshark_captures

You can open any .pcap file directly in Wireshark for visual inspection
after Claude has analyzed it.

NOTE: Replace YourUsername with your actual Windows login name.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| pip not recognized | Python is not on PATH — reinstall Python and tick "Add to PATH" |
| mcp-wireshark not recognized | Close Command Prompt, reopen it, and retry |
| tshark not found error | Reinstall Wireshark and make sure TShark is ticked |
| Tools not showing in Claude | Check the config JSON for typos, restart Claude as Administrator |
| Permission denied on capture | Make sure Claude Desktop is running as Administrator |
| No packets captured | Wrong interface — use "List my network interfaces" first |

---

## Architecture

    Claude Desktop
         |
         |  MCP (stdio)
         v
    mcp-wireshark package   (installed via pip)
         |
         |  calls
         v
    tshark.exe   (C:\Program Files\Wireshark\tshark.exe)
         |
         |-- reads/writes .pcap files
         |-- captures from live network interfaces

---

## Security Notes

- This MCP server runs locally only — no data leaves your machine
- TShark requires Administrator privileges for live capture on Windows
- Only capture on networks you own or have permission to monitor
- All captured data stays in your local files

---

## Files in This Package

| File | Purpose |
|---|---|
| README.md | This setup guide |
| requirements.txt | Python dependencies reference |
| claude_desktop_config_snippet.json | The JSON to paste into Claude Desktop config |
| wireshark_mcp.py | Advanced custom MCP server (fallback/reference only) |

---

Built for cybersecurity analysts learning agentic AI workflows with Claude Desktop on Windows 10.
