"""
utils.py — Helper functions: OS detection, logging, timestamps, regex tools
"""

import os
import re
import sys
import json
import shutil
import platform
import subprocess
from datetime import datetime
from pathlib import Path

# ─── ANSI Colors ────────────────────────────────────────────────────────────
class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def cprint(msg: str, color: str = Color.RESET) -> None:
    print(f"{color}{msg}{Color.RESET}")

def banner() -> None:
    print(f"""
{Color.CYAN}{Color.BOLD}
 ██╗██████╗ ███████╗    ██╗██████╗ ███████╗
 ██║██╔══██╗██╔════╝    ██║██╔══██╗██╔════╝
 ██║██║  ██║███████╗    ██║██████╔╝███████╗
 ██║██║  ██║╚════██║    ██║██╔═══╝ ╚════██║
 ██║██████╔╝███████║    ██║██║     ███████║
 ╚═╝╚═════╝ ╚══════╝    ╚═╝╚═╝     ╚══════╝
{Color.RESET}
{Color.YELLOW}   Intrusion Detection & Prevention System v1.0{Color.RESET}
{Color.BLUE}   Linux-native | Python + Bash | Telegram Alerts{Color.RESET}
""")

# ─── OS & Tool Detection ─────────────────────────────────────────────────────
def detect_os() -> dict:
    """Detect OS type and available package manager."""
    info = {
        "distro": platform.system(),
        "version": platform.version(),
        "pkg_manager": None,
        "firewall": None,
    }
    if shutil.which("apt"):
        info["pkg_manager"] = "apt"
    elif shutil.which("apt-get"):
        info["pkg_manager"] = "apt-get"
    elif shutil.which("yum"):
        info["pkg_manager"] = "yum"
    elif shutil.which("dnf"):
        info["pkg_manager"] = "dnf"
    elif shutil.which("pacman"):
        info["pkg_manager"] = "pacman"

    if shutil.which("ufw"):
        info["firewall"] = "ufw"
    elif shutil.which("iptables"):
        info["firewall"] = "iptables"
    elif shutil.which("nft"):
        info["firewall"] = "nftables"

    return info

def require_root() -> None:
    """Exit if not running as root."""
    if os.geteuid() != 0:
        cprint("[!] This operation requires root privileges. Re-run with sudo.", Color.RED)
        sys.exit(1)

def run_command(cmd: str, silent: bool = False) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    )
    if not silent:
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            cprint(result.stderr.strip(), Color.YELLOW)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

# ─── Config ──────────────────────────────────────────────────────────────────
CONFIG_PATH = Path(__file__).parent / "config.json"

def load_config() -> dict:
    """Load config.json from project root."""
    if not CONFIG_PATH.exists():
        cprint(f"[!] config.json not found at {CONFIG_PATH}", Color.RED)
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)

# ─── Timestamps ──────────────────────────────────────────────────────────────
def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ts_short() -> str:
    return datetime.now().strftime("%H:%M:%S")

# ─── IP Validation ───────────────────────────────────────────────────────────
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_valid_ip(ip: str) -> bool:
    if not IPV4_REGEX.match(ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

def extract_ip_from_log_line(line: str) -> str | None:
    """Extract the first IPv4 address from a log line."""
    match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    return match.group(1) if match else None

# ─── Log helper ──────────────────────────────────────────────────────────────
LOG_FILE = Path(__file__).parent / "ids.log"

def log_event(level: str, message: str) -> None:
    """Append an event to ids.log and print to console."""
    line = f"[{timestamp()}] [{level.upper()}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    color_map = {
        "INFO":    Color.CYAN,
        "WARN":    Color.YELLOW,
        "ALERT":   Color.RED,
        "BLOCK":   Color.MAGENTA,
        "SUCCESS": Color.GREEN,
    }
    cprint(line, color_map.get(level.upper(), Color.RESET))
