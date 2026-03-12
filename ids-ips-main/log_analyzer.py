#!/usr/bin/env python3

import re
import time
import threading
import subprocess
from pathlib import Path
from collections import defaultdict, deque
from urllib.parse import unquote
from datetime import datetime


# ───────── CONFIG ─────────

LOG_PATHS = [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log"
]

WHITELIST = {
    "127.0.0.1"
}

RATE_LIMIT = 100
RATE_WINDOW = 10

BLOCK_THRESHOLD = 120

ENABLE_FIREWALL_BLOCK = False


# ───────── ATTACK RULES ─────────

RULES = {

    "sql_injection": [
        r"union.*select",
        r"or\s+1=1",
        r"sleep\(",
        r"benchmark\("
    ],

    "xss": [
        r"<script",
        r"javascript:",
        r"onerror="
    ],

    "traversal": [
        r"\.\./",
        r"\.\.\\"
    ],

    "scanner": [
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"masscan"
    ]
}


# Threat score

SCORES = {
    "sql_injection": 50,
    "xss": 40,
    "traversal": 40,
    "scanner": 20,
    "rate": 30
}


# Compile regex

PATTERNS = {
    k: re.compile("|".join(v), re.IGNORECASE)
    for k, v in RULES.items()
}


# ───────── STATE ─────────

ip_scores = defaultdict(int)
ip_requests = defaultdict(lambda: deque())
blocked_ips = set()


# ───────── UTILITIES ─────────

def ts():
    return datetime.now().strftime("%H:%M:%S")


def extract_ip(line):

    m = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)

    if m:
        return m.group(1)

    return None


def extract_path(line):

    m = re.search(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)', line)

    if m:
        return unquote(m.group(1))

    return "unknown"


# ───────── RATE LIMIT ─────────

def check_rate(ip):

    now = time.time()

    dq = ip_requests[ip]

    dq.append(now)

    while dq and now - dq[0] > RATE_WINDOW:
        dq.popleft()

    return len(dq) > RATE_LIMIT


# ───────── FIREWALL ─────────

def block_ip(ip):

    if ip in blocked_ips:
        return

    blocked_ips.add(ip)

    print(f"[BLOCKED] {ip}")

    if ENABLE_FIREWALL_BLOCK:

        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL
            )

        except Exception as e:
            print("Firewall error:", e)


# ───────── REPORT ─────────

def report(ip, category, path):

    score = SCORES.get(category, 20)

    ip_scores[ip] += score

    print(
        f"[{ts()}] {ip} -> {category} -> {path} score={ip_scores[ip]}"
    )

    if ip_scores[ip] >= BLOCK_THRESHOLD:
        block_ip(ip)


# ───────── ANALYZE LINE ─────────

def analyze(line):

    ip = extract_ip(line)

    if not ip or ip in WHITELIST:
        return

    path = extract_path(line)

    data = unquote(line.lower())

    # Rate detection

    if check_rate(ip):

        report(ip, "rate", path)
        return

    # Pattern detection

    for category, pattern in PATTERNS.items():

        if pattern.search(data):

            report(ip, category, path)
            return


# ───────── FILE MONITOR ─────────

def tail_file(path):

    print("Monitoring:", path)

    try:

        with open(path, "r", errors="ignore") as f:

            f.seek(0, 2)

            while True:

                line = f.readline()

                if line:

                    analyze(line)

                else:

                    time.sleep(0.2)

    except FileNotFoundError:

        print("File not found:", path)


# ───────── START SYSTEM ─────────

def start():

    existing = [p for p in LOG_PATHS if Path(p).exists()]

    if not existing:

        print("No log files found")

        return

    threads = []

    for path in existing:

        t = threading.Thread(
            target=tail_file,
            args=(path,),
            daemon=True
        )

        t.start()

        threads.append(t)

    print("LogGuardian running...")

    while True:

        time.sleep(1)


# ───────── MAIN ─────────

if __name__ == "__main__":

    print("LogGuardian IDS started")

    try:

        start()

    except KeyboardInterrupt:

        print("Stopped")