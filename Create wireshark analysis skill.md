# How to Create the Wireshark Skill on Claude

This guide walks you through recreating the `wireshark-capture-analysis` skill from scratch using Claude's built-in skill creator. No coding required.

---

## Prerequisites

- A Claude.ai account (Pro or Team recommended for skill creation)
- The **Wireshark MCP connector** enabled in Claude  
  *(Settings → Integrations → Wireshark → Connect)*
- Basic familiarity with what Wireshark/tshark does

---

## Step 1 — Open Claude and Start a Skill Creation Conversation

Go to [claude.ai](https://claude.ai) and start a new chat. Tell Claude what you want to build:

```
I want to create a Claude skill for Wireshark network capture and analysis.
The skill should handle these user requests:

- "List my network interfaces"
- "Start a 60 second capture on Ethernet 6"
- "Stop the capture"
- "Analyze the last capture — what protocols were used?"
- "Check my capture.pcap for any suspicious activity"
- "Extract all DNS queries from my capture"
- "Show me all HTTP requests in the capture"
- "Give me a protocol breakdown of capture.pcap"

Can you create this skill?
```

Claude will automatically detect the skill creator skill and begin the process.

---

## Step 2 — Let Claude Research the Available Tools

Claude will search for available Wireshark MCP tools using `tool_search`. It will discover all 10 tools:

- `wireshark:list_interfaces`
- `wireshark:live_capture`
- `wireshark:summarize_pcap`
- `wireshark:read_pcap`
- `wireshark:display_filter`
- `wireshark:stats_by_proto`
- `wireshark:follow_tcp`
- `wireshark:follow_udp`
- `wireshark:export_json`
- `wireshark:check_installation`

**You don't need to do anything here** — Claude handles this automatically.

---

## Step 3 — Review the Generated SKILL.md

Claude will produce a `SKILL.md` file with:

1. **YAML frontmatter** — the skill's name and trigger description
2. **Tool reference table** — all 10 tools and their purposes
3. **Intent-to-workflow mappings** — what tools to call for each user phrase
4. **Display filter reference** — common Wireshark filters as a lookup table
5. **File path handling** — how to find pcap files from live captures vs. uploads
6. **Response format guidelines** — how to present results clearly

Read through it. If anything looks wrong or missing, tell Claude:

```
The suspicious activity check should also look for ICMP floods.
Can you add that?
```

Claude will revise the skill accordingly.

---

## Step 4 — Test the Skill

Ask Claude to run through the example prompts using the skill:

```
Can you test the skill with: "Check capture.pcap for suspicious activity"
```

Claude will follow the skill's instructions and walk through the layered analysis workflow. Review the output — does it look right? Is anything missing?

Iterate until you're satisfied:

```
The DNS section should also mention TXT record queries since those 
are often used for tunneling. Can you update the skill?
```

---

## Step 5 — Package the Skill

Once the skill looks good, ask Claude to package it:

```
Package the skill so I can install it.
```

Claude will run the packaging script and produce a `.skill` file you can download.

---

## Step 6 — Install the Skill

1. Download the `.skill` file Claude produces
2. Go to **Claude.ai → Settings → Skills**
3. Drag the `.skill` file into the skills panel, or click **Install Skill**
4. The skill is now active in all your conversations

---

## How Skill Triggering Works

The skill activates when Claude sees the right keywords in your message. The trigger is defined in the YAML `description` field at the top of `SKILL.md`.

The description for this skill includes phrases like:
- "capturing network traffic"
- "listing network interfaces"
- "analyzing a .pcap or .pcapng file"
- "checking for suspicious network activity"
- "extract DNS queries", "show HTTP requests"

When your message matches these, Claude reads the full `SKILL.md` and follows its instructions.

**Tip:** If the skill doesn't trigger when you expect it to, you can prompt Claude directly:

```
Using the Wireshark skill, analyze capture.pcap
```

---

## Customizing the Skill

After installing, you can ask Claude to modify the skill at any time:

```
Update the Wireshark skill to also check for Telnet traffic 
in the suspicious activity analysis.
```

Claude will edit the `SKILL.md`, and you can re-package and reinstall.

---

## Skill File Structure

```
wireshark-capture-analysis/
└── SKILL.md          ← All skill logic lives here
```

This is a simple single-file skill. More complex skills can include:

```
my-skill/
├── SKILL.md
├── scripts/          ← Executable helper scripts
├── references/       ← Additional docs loaded on demand
└── assets/           ← Templates, fonts, etc.
```

---

## Troubleshooting

**The skill isn't triggering**  
→ Make sure the Wireshark MCP connector is enabled in Settings → Integrations  
→ Try explicitly saying "using the Wireshark skill" in your message

**"tshark not found" error**  
→ Install Wireshark on your machine: [wireshark.org/download](https://www.wireshark.org/download.html)  
→ Ensure `tshark` is in your system PATH

**Live capture fails**  
→ Run Claude (or tshark) with administrator/root privileges  
→ On Windows: right-click Claude and "Run as administrator"  
→ On Linux/macOS: tshark may need `sudo` or special capabilities

**Interface name not found**  
→ Run "List my network interfaces" first to get the exact name  
→ Interface names are case-sensitive (e.g., "Ethernet 6" not "ethernet 6")

---

## Going Further

Once you're comfortable with skill creation, you can:

- **Add new intents** — e.g., "show me all ARP requests" or "find duplicate IPs"
- **Add a references/ folder** — with a full Wireshark display filter cheatsheet
- **Chain with other skills** — combine with a reporting skill to auto-generate PDF analysis reports
- **Share your skill** — package it and post to GitHub for others to install

For more on skill creation, ask Claude:
```
Tell me more about how Claude skills work and how to build advanced ones.
```
