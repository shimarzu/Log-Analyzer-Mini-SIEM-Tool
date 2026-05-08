"""
Log Analyzer & Mini SIEM Tool
A cybersecurity tool that parses log files, detects threats,
and generates security alerts with severity levels.

Supports: SSH auth logs, Apache/Nginx access logs, Windows Event logs
"""

import re
import os
import sys
from datetime import datetime
from collections import defaultdict


# ── Terminal Colors ───────────────────────────────────────────────────────────
class Color:
    RED      = "\033[91m"
    ORANGE   = "\033[38;5;208m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    BLUE     = "\033[94m"
    MAGENTA  = "\033[95m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RESET    = "\033[0m"


# ── Severity Levels ───────────────────────────────────────────────────────────
# Each alert gets one of these levels, just like a real SIEM
SEVERITY = {
    "LOW"      : {"label": "LOW     ", "color": Color.GREEN},
    "MEDIUM"   : {"label": "MEDIUM  ", "color": Color.YELLOW},
    "HIGH"     : {"label": "HIGH    ", "color": Color.ORANGE},
    "CRITICAL" : {"label": "CRITICAL", "color": Color.RED},
}


# ── Known suspicious processes (Windows) ─────────────────────────────────────
SUSPICIOUS_PROCESSES = [
    "mimikatz", "pwdump", "wce.exe", "fgdump", "gsecdump",
    "procdump", "netcat", "nc.exe", "nmap", "psexec",
]

# ── Sensitive files being probed (Web logs) ──────────────────────────────────
SENSITIVE_PATHS = [
    ".env", "config.php", "wp-config", ".git", "/.git/",
    "etc/passwd", "etc/shadow", "backup.zip", "db_backup",
    "phpmyadmin", "wp-admin", "adminer",
]

# ── SQL injection patterns ────────────────────────────────────────────────────
SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)union\s+select",
    r"(?i)drop\s+table",
    r"(?i)insert\s+into",
    r"(?i)select\s+.*\s+from",
    r"(?i)1\s*=\s*1",
    r"'.*--",
]

# ── XSS patterns ─────────────────────────────────────────────────────────────
XSS_PATTERNS = [
    r"(?i)<script",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)alert\s*\(",
]


# ── Alert class — represents one detected threat ──────────────────────────────
class Alert:
    def __init__(self, severity, category, description, source_ip=None, line_num=None, raw_line=None):
        self.severity    = severity
        self.category    = category
        self.description = description
        self.source_ip   = source_ip
        self.line_num    = line_num
        self.raw_line    = raw_line
        self.timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def __str__(self):
        sev    = SEVERITY[self.severity]
        color  = sev["color"]
        label  = sev["label"]
        ip_str = f" | IP: {self.source_ip}" if self.source_ip else ""
        ln_str = f" | Line {self.line_num}" if self.line_num else ""
        return (
            f"  [{color}{Color.BOLD}{label}{Color.RESET}] "
            f"{Color.CYAN}{self.category}{Color.RESET}"
            f"{ip_str}{ln_str}\n"
            f"           {self.description}"
        )


# ── SSH / Auth Log Parser ─────────────────────────────────────────────────────
def parse_auth_log(filepath: str) -> list:
    """
    Parses Linux SSH auth logs.
    Detects: brute force, root login, invalid users, successful logins.
    """
    alerts  = []
    failed  = defaultdict(list)   # ip -> list of line numbers
    success = []

    # Regex patterns for SSH log entries
    re_failed  = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
    re_success = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
    re_sudo    = re.compile(r"sudo.*USER=root.*COMMAND=(.*)")

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):

        # ── Failed login attempt ──────────────────────────────────────────────
        m = re_failed.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            failed[ip].append(i)

            # Flag single failed attempt for root
            if user == "root":
                alerts.append(Alert(
                    "MEDIUM", "SSH Failed Login",
                    f"Failed login attempt for ROOT account.",
                    source_ip=ip, line_num=i
                ))

        # ── Successful login ──────────────────────────────────────────────────
        m = re_success.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            success.append((user, ip, i))

            # Root login success is suspicious
            if user == "root":
                alerts.append(Alert(
                    "HIGH", "SSH Root Login",
                    f"Successful login as ROOT from {ip}. Verify this is authorised.",
                    source_ip=ip, line_num=i
                ))

        # ── Sudo privilege escalation ─────────────────────────────────────────
        m = re_sudo.search(line)
        if m:
            command = m.group(1).strip()
            alerts.append(Alert(
                "HIGH", "Privilege Escalation",
                f"User ran sudo command as root: {command}",
                line_num=i
            ))

    # ── Brute-force detection — same IP failing 5+ times ─────────────────────
    for ip, line_nums in failed.items():
        if len(line_nums) >= 5:
            severity = "CRITICAL" if len(line_nums) >= 10 else "HIGH"
            alerts.append(Alert(
                severity, "Brute Force Attack",
                f"IP attempted {len(line_nums)} failed logins. "
                f"First at line {line_nums[0]}, last at line {line_nums[-1]}.",
                source_ip=ip
            ))

    return alerts


# ── Apache / Nginx Web Access Log Parser ─────────────────────────────────────
def parse_access_log(filepath: str) -> list:
    """
    Parses Apache/Nginx access logs (Combined Log Format).
    Detects: SQL injection, XSS, directory traversal, sensitive file probing,
             brute force on login endpoints.
    """
    alerts      = []
    login_fails = defaultdict(int)  # ip -> count of 401s
    not_founds  = defaultdict(int)  # ip -> count of 404s

    # Apache combined log format
    re_apache = re.compile(
        r'([\d.]+) .+ \[(.+?)\] "(\w+) (.+?) HTTP.+" (\d+) (\d+)'
    )

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        m = re_apache.search(line)
        if not m:
            continue

        ip, timestamp, method, path, status, size = (
            m.group(1), m.group(2), m.group(3),
            m.group(4), m.group(5), m.group(6)
        )
        status = int(status)

        # ── SQL Injection check ───────────────────────────────────────────────
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, path):
                alerts.append(Alert(
                    "CRITICAL", "SQL Injection Attempt",
                    f"Possible SQLi in request: {path[:80]}",
                    source_ip=ip, line_num=i
                ))
                break

        # ── XSS check ────────────────────────────────────────────────────────
        for pattern in XSS_PATTERNS:
            if re.search(pattern, path):
                alerts.append(Alert(
                    "HIGH", "XSS Attempt",
                    f"Possible XSS in request: {path[:80]}",
                    source_ip=ip, line_num=i
                ))
                break

        # ── Directory traversal ───────────────────────────────────────────────
        if "../" in path or "..%2F" in path.lower():
            alerts.append(Alert(
                "HIGH", "Directory Traversal",
                f"Path traversal attempt: {path[:80]}",
                source_ip=ip, line_num=i
            ))

        # ── Sensitive file probing ────────────────────────────────────────────
        for sensitive in SENSITIVE_PATHS:
            if sensitive.lower() in path.lower():
                alerts.append(Alert(
                    "MEDIUM", "Sensitive File Probe",
                    f"Request for sensitive path: {path[:80]}",
                    source_ip=ip, line_num=i
                ))
                break

        # ── Brute force on login (repeated 401s) ─────────────────────────────
        if status == 401:
            login_fails[ip] += 1

        # ── Excessive 404s from same IP (scanning) ────────────────────────────
        if status == 404:
            not_founds[ip] += 1

    # ── Evaluate brute force on login endpoint ────────────────────────────────
    for ip, count in login_fails.items():
        if count >= 3:
            alerts.append(Alert(
                "HIGH", "Web Login Brute Force",
                f"IP made {count} failed login attempts (HTTP 401).",
                source_ip=ip
            ))

    # ── Evaluate scanning behaviour (too many 404s) ───────────────────────────
    for ip, count in not_founds.items():
        if count >= 4:
            alerts.append(Alert(
                "MEDIUM", "Web Scanning / Enumeration",
                f"IP triggered {count} HTTP 404 errors — possible directory scanning.",
                source_ip=ip
            ))

    return alerts


# ── Windows Event Log Parser ──────────────────────────────────────────────────
def parse_windows_log(filepath: str) -> list:
    """
    Parses simplified Windows Event logs.
    Detects: failed logins, new user creation, suspicious processes,
             privilege abuse, log clearing, and scheduled task creation.
    """
    alerts      = []
    failed      = defaultdict(int)  # ip -> count

    re_event = re.compile(r"EventID=(\d+)")
    re_user  = re.compile(r"User=(\S+)")
    re_ip    = re.compile(r"IP=([\d.]+)")
    re_proc  = re.compile(r"ProcessName=(\S+)")
    re_task  = re.compile(r"TaskName=(\S+)")

    with open(filepath, "r", errors="ignore") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        event_m = re_event.search(line)
        if not event_m:
            continue

        event_id = event_m.group(1)
        user  = re_user.search(line)
        ip    = re_ip.search(line)
        user  = user.group(1) if user else "Unknown"
        ip    = ip.group(1)   if ip   else None

        # EventID 4625 = Failed login
        if event_id == "4625":
            if ip:
                failed[ip] += 1

        # EventID 4720 = New user account created
        elif event_id == "4720":
            alerts.append(Alert(
                "HIGH", "New User Account Created",
                f"A new user account was created by {user}. Verify this is authorised.",
                source_ip=ip, line_num=i
            ))

        # EventID 4672 = Special privileges assigned
        elif event_id == "4672":
            priv = re.search(r"Privileges=(\S+)", line)
            priv = priv.group(1) if priv else "Unknown"
            alerts.append(Alert(
                "MEDIUM", "Privileged Logon",
                f"User {user} logged on with elevated privileges: {priv}",
                source_ip=ip, line_num=i
            ))

        # EventID 4688 = New process created
        elif event_id == "4688":
            proc_m = re_proc.search(line)
            if proc_m:
                proc = proc_m.group(1).lower()
                for suspicious in SUSPICIOUS_PROCESSES:
                    if suspicious in proc:
                        alerts.append(Alert(
                            "CRITICAL", "Suspicious Process",
                            f"Known malicious/hacking tool executed: {proc_m.group(1)}",
                            line_num=i
                        ))
                        break

        # EventID 4698 = Scheduled task created (persistence technique)
        elif event_id == "4698":
            task_m = re_task.search(line)
            task = task_m.group(1) if task_m else "Unknown"
            alerts.append(Alert(
                "HIGH", "Scheduled Task Created",
                f"New scheduled task '{task}' created by {user}. Common persistence technique.",
                line_num=i
            ))

        # EventID 1102 = Audit log cleared (attacker covering tracks)
        elif event_id == "1102":
            alerts.append(Alert(
                "CRITICAL", "Audit Log Cleared",
                f"Security audit log was cleared by {user}! Possible cover-up of malicious activity.",
                source_ip=ip, line_num=i
            ))

        # EventID 4624 type 10 = Remote interactive logon
        elif event_id == "4624":
            logon_type = re.search(r"LogonType=(\d+)", line)
            if logon_type and logon_type.group(1) == "10":
                alerts.append(Alert(
                    "MEDIUM", "Remote Desktop Login",
                    f"RDP session opened for user {user}.",
                    source_ip=ip, line_num=i
                ))

    # ── Brute force via failed logins ─────────────────────────────────────────
    for ip, count in failed.items():
        if count >= 3:
            severity = "CRITICAL" if count >= 8 else "HIGH"
            alerts.append(Alert(
                severity, "Windows Brute Force",
                f"IP made {count} failed login attempts (EventID 4625).",
                source_ip=ip
            ))

    return alerts


# ── Auto-detect log type ──────────────────────────────────────────────────────
def detect_log_type(filepath: str) -> str:
    """
    Reads the first few lines and guesses which log format it is.
    Returns: 'auth', 'access', or 'windows'
    """
    with open(filepath, "r", errors="ignore") as f:
        sample = f.read(500)

    if "EventID=" in sample:
        return "windows"
    elif re.search(r'\d+\.\d+\.\d+\.\d+ - - \[', sample):
        return "access"
    elif re.search(r'sshd\[|sudo\[|Failed password|Accepted password', sample):
        return "auth"
    else:
        return "unknown"


# ── Print Dashboard ───────────────────────────────────────────────────────────
def print_dashboard(all_alerts: list, files_scanned: list):
    """
    Prints the summary dashboard — like a real SIEM overview panel.
    """
    c = Color

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    ip_hits = defaultdict(int)
    categories = defaultdict(int)

    for alert in all_alerts:
        counts[alert.severity] += 1
        if alert.source_ip:
            ip_hits[alert.source_ip] += 1
        categories[alert.category] += 1

    total = len(all_alerts)

    print(f"\n{c.BOLD}{'═'*55}{c.RESET}")
    print(f"{c.BOLD}   🔒 SIEM DASHBOARD — Security Event Summary{c.RESET}")
    print(f"{c.BOLD}{'═'*55}{c.RESET}")
    print(f"  Files scanned : {len(files_scanned)}")
    for f in files_scanned:
        print(f"    • {os.path.basename(f)}")
    print(f"  Total alerts  : {c.BOLD}{total}{c.RESET}")
    print(f"{'─'*55}")

    # Severity breakdown
    print(f"\n  {c.BOLD}Alerts by Severity:{c.RESET}")
    for sev, count in counts.items():
        if count == 0:
            continue
        bar_len = int((count / max(total, 1)) * 25)
        bar     = "█" * bar_len
        color   = SEVERITY[sev]["color"]
        label   = SEVERITY[sev]["label"].strip()
        print(f"  {color}{c.BOLD}{label:8}{c.RESET}  {color}{bar}{c.RESET} {count}")

    # Top offending IPs
    if ip_hits:
        print(f"\n  {c.BOLD}Top Offending IPs:{c.RESET}")
        sorted_ips = sorted(ip_hits.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f"  {c.RED}  {ip:18}{c.RESET}  {count} alert(s)")

    # Alert categories
    print(f"\n  {c.BOLD}Alert Categories:{c.RESET}")
    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)
    for cat, count in sorted_cats:
        print(f"    • {cat}: {count}")

    print(f"\n{'═'*55}\n")


# ── Print All Alerts ──────────────────────────────────────────────────────────
def print_alerts(alerts: list, log_name: str):
    c = Color
    print(f"\n{c.BOLD}{c.BLUE}── Alerts from: {log_name} ──{c.RESET}")
    if not alerts:
        print(f"  {c.GREEN}✔ No threats detected.{c.RESET}")
        return
    for alert in alerts:
        print(alert)
        print()


# ── Export Report ─────────────────────────────────────────────────────────────
def export_report(all_alerts: list, files_scanned: list, output_path: str):
    """
    Saves a plain-text report of all alerts to a file.
    """
    with open(output_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  LOG ANALYSIS SECURITY REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Files Scanned:\n")
        for fp in files_scanned:
            f.write(f"  - {fp}\n")

        f.write(f"\nTotal Alerts: {len(all_alerts)}\n\n")

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for a in all_alerts:
            counts[a.severity] += 1

        f.write("Severity Breakdown:\n")
        for sev, count in counts.items():
            f.write(f"  {sev}: {count}\n")

        f.write("\n" + "─" * 60 + "\n")
        f.write("DETAILED ALERTS\n")
        f.write("─" * 60 + "\n\n")

        for alert in all_alerts:
            ip_str = f" | IP: {alert.source_ip}" if alert.source_ip else ""
            ln_str = f" | Line {alert.line_num}" if alert.line_num else ""
            f.write(f"[{alert.severity}] {alert.category}{ip_str}{ln_str}\n")
            f.write(f"  {alert.description}\n\n")

    print(f"  Report saved → {Color.GREEN}{output_path}{Color.RESET}\n")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    c = Color

    print(f"\n{c.BOLD}{'='*55}")
    print("   Log Analyzer & Mini SIEM Tool")
    print(f"{'='*55}{c.RESET}")
    print("  Supported formats: SSH auth logs, Apache/Nginx, Windows Events\n")

    # ── Get log files from user ───────────────────────────────────────────────
    print(f"  {c.CYAN}Options:{c.RESET}")
    print("  [1] Scan sample logs (built-in demo)")
    print("  [2] Scan my own log file")
    print("  [3] Scan all files in a folder")
    print()

    choice = input("  Choose an option (1/2/3): ").strip()

    log_files = []

    if choice == "1":
        sample_dir = os.path.join(os.path.dirname(__file__), "sample_logs")
        if os.path.isdir(sample_dir):
            log_files = [
                os.path.join(sample_dir, f)
                for f in os.listdir(sample_dir)
                if f.endswith(".log")
            ]
        if not log_files:
            print(f"  {c.RED}Sample logs folder not found. Run from project directory.{c.RESET}")
            return

    elif choice == "2":
        path = input("  Enter full path to log file: ").strip().strip('"')
        if not os.path.isfile(path):
            print(f"  {c.RED}File not found: {path}{c.RESET}")
            return
        log_files = [path]

    elif choice == "3":
        folder = input("  Enter folder path: ").strip().strip('"')
        if not os.path.isdir(folder):
            print(f"  {c.RED}Folder not found: {folder}{c.RESET}")
            return
        log_files = [
            os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.endswith(".log") or f.endswith(".txt")
        ]
        if not log_files:
            print(f"  {c.RED}No .log or .txt files found in that folder.{c.RESET}")
            return
    else:
        print(f"  {c.RED}Invalid option.{c.RESET}")
        return

    # ── Parse each log file ───────────────────────────────────────────────────
    all_alerts = []
    print(f"\n  {c.CYAN}Scanning {len(log_files)} file(s)...{c.RESET}\n")

    for filepath in log_files:
        log_type = detect_log_type(filepath)
        name     = os.path.basename(filepath)

        print(f"  Scanning: {c.BOLD}{name}{c.RESET}  [{c.DIM}detected: {log_type}{c.RESET}]")

        if log_type == "auth":
            alerts = parse_auth_log(filepath)
        elif log_type == "access":
            alerts = parse_access_log(filepath)
        elif log_type == "windows":
            alerts = parse_windows_log(filepath)
        else:
            print(f"  {c.YELLOW}⚠ Could not detect format for {name}, skipping.{c.RESET}")
            continue

        print_alerts(alerts, name)
        all_alerts.extend(alerts)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    print_dashboard(all_alerts, log_files)

    # ── Export report? ────────────────────────────────────────────────────────
    if all_alerts:
        save = input("  Export report to file? (y/n): ").strip().lower()
        if save == "y":
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(os.path.dirname(__file__), f"report_{ts}.txt")
            export_report(all_alerts, log_files, report_path)

    print(f"  {c.GREEN}{c.BOLD}Scan complete. Stay secure!{c.RESET}\n")


if __name__ == "__main__":
    main()
