# ClaudeTab

> **Claude AI as a native tab inside Burp Suite.**

ClaudeTab embeds Claude directly into Burp Suite — not as an external tool, not as an MCP bridge. As a tab. Claude reads your live proxy traffic, runs autonomous tests, confirms vulnerabilities with real response evidence, and generates a professional pentest report — all without leaving Burp.

*"Stop testing everything. Test what breaks your app."*

---

## Installation

1. Download `releases/ClaudeTab.jar`
2. Burp Suite → **Extensions → Add → Type: Java** → select the JAR
3. A **Claude** tab appears in the top menu bar
4. Paste your `sk-ant-...` Anthropic API key — saved automatically, never asked again

No Python. No config files. No MCP setup. Just the JAR.

---

## Quickstart

```
1. Browse your target through Burp proxy
2. Open the Claude tab
3. Load a CLAUDE.md engagement brief (optional but recommended)
4. Scan ▾ → ⏺ Agent Scan
5. Watch Claude test autonomously — press ⏹ Stop anytime
```

---

## Features

### ⏺ Agent Scan — Autonomous Testing

Claude receives a `send_request` tool and runs an autonomous loop (up to 50 turns). It:

- Ranks all captured endpoints by true-positive likelihood
- Sends baseline requests to understand normal behavior
- Fires targeted payloads (IDOR, SQLi, SSRF, auth bypass, mass assignment, CORS, etc.)
- Reads each response and decides the next move
- Only reports findings confirmed with real HTTP response evidence
- Automatically adds confirmed findings to **Burp Scanner → Issue activity** after the loop

Press **⏹ Stop** at any point to cancel. ESC also works while the Claude tab is active.

---

### 🔍 Scan Menu (Scan ▾)

| Option | What it does |
|---|---|
| **Full Vulnerability Scan** | Claude analyzes all proxy traffic and outputs CRITICAL/HIGH/MEDIUM/LOW report |
| **⏺ Agent Scan** | Autonomous 50-turn loop — Claude sends and chains requests independently |
| **Passive Scan** | Analyzes captured traffic without sending requests — findings added to Burp Scanner |
| **Active Scan** | Sends targeted test payloads, verifies results — confirmed findings added to Scanner |
| **Verify Burp Findings** | Claude reviews all Burp Scanner issues and marks false positives |
| **Detect Tech Stack** | Identifies framework, language, server, and auth mechanism from traffic |

---

### ⏹ Stop — Cancel Any Operation

The **⏹ Stop** button is always visible in the toolbar. It works for:

- Regular chat messages — stops mid-stream
- Passive / Active / Verify scans — cancels before next API call
- Agent Scan — stops cleanly after the current turn
- Any prompt mid-generation

Press **ESC** as an alternative while the Claude tab is active.

---

### 🗂 CLAUDE.md — Engagement Brief

Load a short brief about your target via **📁 CLAUDE.md** button. Claude reads this before every call — scope, tech stack, auth mechanism, testing goals.

The brief is injected into every Claude request for the session. It does **not** list vulnerable endpoints — you discover those during testing.

Example (`examples/CLAUDE.md.template` included):
```markdown
# Engagement Brief
Target: https://app.example.com
Scope: /api/*, /admin/*
Auth: JWT Bearer token
Stack: Node.js, MongoDB
Focus: Payment flows, IDOR on user resources
```

---

### 🎨 Color-Coded HTTP History

After any scan, ClaudeTab automatically highlights matching requests in **Proxy → HTTP History** by vulnerability type. Each row also gets an annotation in the Notes column.

| Color | Vulnerability Type |
|---|---|
| 🔴 Red | Injection (SQLi, XSS, SSTI, Command Injection, RCE) |
| 🔵 Blue | IDOR / Broken Access Control / Privilege Escalation |
| 🟠 Orange | SSRF / Open Redirect / Internal Network Access |
| 🟣 Magenta | Auth / Session / JWT / Credential issues |
| 🟡 Yellow | Information Disclosure / Sensitive Data Exposure |
| 🩵 Cyan | CORS / Missing Security Headers |
| ⬛ Gray | Other / Uncategorized |

---

### 📤 Send to Repeater

Select any raw HTTP request in the Claude chat → right-click → **Send selection to Repeater**. ClaudeTab parses the request, infers HTTPS from proxy history, and sends it to Repeater named `"Claude: POST /api/endpoint"`.

Works with any format Claude outputs, including `host:port` combinations.

---

### 🎯 Generate Intruder Payloads

Right-click any request → **Claude: Generate Intruder Payloads**. Claude:
1. Picks the most promising parameter for the attack type
2. Generates targeted payloads (SQLi, IDOR, XSS, etc.)
3. Sends the request to Burp Intruder
4. Prints the payload list in chat

---

### 👤 Session Role Labeling

Right-click any request → **ClaudeTab: Label Session Role** → **Admin / Regular User / Unauthenticated**

Labels are injected into every Claude context call:
```
GET /api/users/dashboard [role:Admin]    200
GET /api/users/dashboard [role:User]     403
```
Enables proper BAC differential analysis.

---

### 📊 Export Report

Click **Export Report** in the Claude tab. Claude formats all session findings as structured JSON:
- CVSS 3.1 score + vector string
- OWASP API Security Top 10 category
- MITRE ATT&CK ID
- Affected asset table
- Summary, Proof of Concept, Impact, Recommendation

Rendered as an HTML report — print to PDF via browser.

---

### 💾 Save / Load Session

- **💾 Save** — serializes full conversation history + engagement brief to JSON
- **📂 Load** — restores a previous session, replays the conversation in the UI

---

### 🔑 API Key Persistence

Your Anthropic API key is saved to Burp's internal preference store on first entry. Survives Burp restarts, extension reloads, and project switches.

---

### 📡 Streaming Responses

Claude's responses stream word-by-word in real time. Press **⏹ Stop** at any point mid-stream to cancel. The response renders with full markdown — tables, headings, code blocks, inline code, bold.

---

### 🔭 Scope Filtering

ClaudeTab respects Burp's native scope (`Target → Scope`). If scope is configured, only in-scope endpoints are sent to Claude. If scope is empty, all traffic is included. CDNs, analytics, and third-parties are filtered automatically when scope is active.

---

### 💬 Smart Context Injection

Short conversational messages (`whoami`, `what does JWT stand for`) don't trigger full proxy context injection. Context is only injected when your message contains security-related keywords (scan, test, vuln, idor, inject, etc.).

---

## Burp Scanner Integration

ClaudeTab writes directly into Burp's native scanner via `api.siteMap().add(AuditIssue)`:

- **Passive Scan** findings → CERTAIN/FIRM/TENTATIVE confidence
- **Active Scan** verified findings → CERTAIN confidence
- **Verify Burp Findings** false positives → `AuditIssueSeverity.FALSE_POSITIVE`
- **Agent Scan** confirmed findings → structured JSON → CERTAIN confidence → visible in Dashboard → Issue activity as `[Claude Agent]` issues

---

## Right-Click Context Menu

Works in Proxy, Repeater, Scanner, and HTTP History.

| Item | What it does |
|---|---|
| **Analyze with Claude** | Full security analysis of the selected request/response |
| **Claude: Find IDOR/BAC** | Focused BAC/IDOR/privilege escalation analysis |
| **Claude: Explain Response** | Explains what the response reveals about auth logic and data structures |
| **Claude: Generate Intruder Payloads** | Generates targeted payloads, sends to Intruder |
| **ClaudeTab: Label Session Role** | Tags request as Admin / User / Unauthenticated |

---

## Notes

**On AI-assisted vs AI-replaced:**
ClaudeTab accelerates pattern recognition and repetitive testing. Judgment, business impact assessment, and final write-ups still require a human. Use it to move faster — not to move out of the loop.

**On scope:**
Always define your scope in Burp (`Target → Scope`) before running scans. ClaudeTab respects it automatically.

**On the engagement brief:**
Keep the brief factual — target URL, tech stack, auth mechanism, testing goals. Don't list expected vulnerabilities. Let Claude discover them.

**On the 50-turn agent limit:**
The limit exists to prevent runaway API usage. Claude typically finishes in 20–35 turns for a well-scoped target. If you need more coverage on a large app, run Agent Scan in sections with different scopes.

---

## Build from Source

Requires Java 17+.

```bash
git clone https://github.com/n0tsaksham/ClaudeTab.git
cd ClaudeTab/burp-extension
./gradlew jar
# Output: build/libs/ClaudeTab.jar
```

---

## Built on Montoya API

ClaudeTab is built on [PortSwigger's Montoya API](https://portswigger.net/burp/extender/api/index.html) — the modern Java extension API for Burp Suite. Without it, none of this would be possible: access to proxy history, site map, scanner issue writing, Repeater/Intruder integration, HTTP History annotations, and scope checks all come from Montoya.

## Architecture

| Component | Detail |
|---|---|
| **Model** | `claude-opus-4-5` via Anthropic API |
| **API** | `https://api.anthropic.com/v1/messages` |
| **Auth** | API key persisted in `api.persistence().preferences()` |
| **Agent loop** | Anthropic tool use API — `send_request` tool, up to 50 turns |
| **Streaming** | `HttpResponse.BodyHandlers.ofInputStream()` → SSE line parsing |
| **Stop** | `volatile boolean stopRequested` checked per turn + per SSE chunk |
| **Scanner** | `api.siteMap().add(AuditIssue)` — writes to Burp's issue tracker |
| **History marking** | `annotations().setHighlightColor()` + `setNotes()` |
| **Repeater** | `api.repeater().sendToRepeater(HttpRequest, name)` |
| **Intruder** | `api.intruder().sendToIntruder(HttpRequest, name)` |
| **UI** | Swing dark theme, streaming JTextPane, markdown renderer |

---

## A note on AI in security testing

Everyone's talking about Agentic AI and AI Agents right now. Most of it is hype aimed at enterprises, automation pipelines, or replacing headcount.

This isn't that.

ClaudeTab is about making AI useful for day-to-day testing — the kind of work where you have 4 hours, 120 endpoints, and a scope doc. The reconnaissance phase that eats your first two hours. The pattern recognition across 80 API routes that you're doing in your head anyway. The repetitive baseline → tamper → verify loop you run on every IDOR candidate.

**AI won't replace the pentester.** It can't reason about business impact. It doesn't know why a real-time location API on a fleet management platform is a different severity than the same finding on a demo app. It can't assess whether a finding is exploitable in the client's actual environment. It missed the SSRF on the first try because it didn't know the internal container name.

What it can do is handle the volume — so you can focus on the judgment. That's the only use case I built for.

---

*Built by [n0tsaksham](https://github.com/n0tsaksham)*
*Blog: [I gave Claude a Burp Suite. Here's what happened.](https://github.com/n0tsaksham/ClaudeTab/tree/main#)*
