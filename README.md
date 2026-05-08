# Log Analyzer & Mini SIEM Tool

A command-line cybersecurity tool that parses system log files, detects threats, and generates security alerts — similar to how professional SIEM (Security Information and Event Management) tools work.

---

## Features

- **Multi-format log parsing** — SSH auth logs, Apache/Nginx web logs, Windows Event logs
- **Auto-detects log type** — no need to specify the format manually
- **Threat detection** including:
  - Brute-force login attacks (SSH & Windows)
  - SQL Injection attempts
  - Cross-Site Scripting (XSS) attempts
  - Directory traversal attacks
  - Sensitive file probing (.env, wp-config, .git, etc.)
  - Suspicious process execution (mimikatz, netcat, etc.)
  - Privilege escalation
  - New user account creation
  - Audit log clearing (attacker covering tracks)
  - Remote Desktop (RDP) logins
  - Scheduled task creation (persistence technique)
- **Severity levels** — CRITICAL / HIGH / MEDIUM / LOW
- **SIEM-style dashboard** with alert summary, top offending IPs, and category breakdown
- **Exportable report** saved to a `.txt` file
- **Built-in sample logs** for instant demo

---

## Setup

**Requirements:** Python 3.7+ (no external libraries needed — uses only built-in modules)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/log-analyzer-siem.git
cd log-analyzer-siem

# 2. Run the tool
python analyzer.py
```

---

## Usage

```
=======================================================
   Log Analyzer & Mini SIEM Tool
=======================================================
  Supported formats: SSH auth logs, Apache/Nginx, Windows Events

  Options:
  [1] Scan sample logs (built-in demo)
  [2] Scan my own log file
  [3] Scan all files in a folder

  Choose an option (1/2/3):
```

Choose **option 1** to instantly run against the included sample logs and see the tool in action.

---

## Sample Output

```
── Alerts from: auth.log ──

  [CRITICAL] Brute Force Attack | IP: 45.33.32.156
           IP attempted 10 failed logins. First at line 14, last at line 23.

  [HIGH    ] SSH Root Login | IP: 10.0.0.1
           Successful login as ROOT from 10.0.0.1. Verify this is authorised.

  [HIGH    ] Privilege Escalation | Line 25
           User ran sudo command as root: /usr/bin/passwd root

═══════════════════════════════════════════════════════
   🔒 SIEM DASHBOARD — Security Event Summary
═══════════════════════════════════════════════════════
  Files scanned : 3
  Total alerts  : 24

  Alerts by Severity:
  CRITICAL  ████████ 5
  HIGH      ████████████ 9
  MEDIUM    ██████ 7
  LOW       ██ 3

  Top Offending IPs:
    203.0.113.55        8 alert(s)
    91.121.88.99        5 alert(s)
    45.33.32.156        4 alert(s)
```

---

## Project Structure

```
log-analyzer-siem/
├── analyzer.py           # Main tool
├── sample_logs/
│   ├── auth.log          # Sample SSH auth log
│   ├── access.log        # Sample Apache web log
│   └── windows.log       # Sample Windows Event log
└── README.md
```

---

## Threat Detection Rules

| Threat | Log Type | Severity |
|--------|----------|----------|
| 5+ failed SSH logins from same IP | Auth | HIGH |
| 10+ failed SSH logins from same IP | Auth | CRITICAL |
| Successful root login | Auth | HIGH |
| SQL injection in URL | Web | CRITICAL |
| XSS attempt in URL | Web | HIGH |
| Directory traversal (../) | Web | HIGH |
| Sensitive file access (.env, .git) | Web | MEDIUM |
| Mimikatz / credential dumper run | Windows | CRITICAL |
| Audit log cleared (EventID 1102) | Windows | CRITICAL |
| New user account created (EventID 4720) | Windows | HIGH |
| Scheduled task created (EventID 4698) | Windows | HIGH |

---

## What I Learned

- How real SIEM tools ingest and parse log data
- Pattern matching with regular expressions (regex)
- Threat categorisation and severity scoring
- Common attack signatures (brute force, SQLi, XSS, directory traversal)
- How attackers cover their tracks (clearing audit logs)
- Persistence techniques (scheduled tasks, new user creation)
- Building a complete CLI security tool in Python

---

## Disclaimer

This tool is for **educational purposes only**. Only scan log files from systems you own or have permission to analyse.

---

## Author

Your Name — [GitHub Profile](https://github.com/YOUR_USERNAME)
