"""
updater.py — Advanced system updater for Security Monitor Tool
Author: Project Team
"""

import shutil
import time
from utils import detect_os, run_command, require_root, log_event, cprint, Color


UPGRADE_COMMANDS = {
    "apt": "apt-get update -y && apt-get upgrade -y",
    "apt-get": "apt-get update -y && apt-get upgrade -y",
    "yum": "yum update -y",
    "dnf": "dnf update -y",
    "pacman": "pacman -Syu --noconfirm",
}


PYTHON_DEPS = [
    "watchdog",
    "requests",
    "python-telegram-bot",
    "colorama"
]


def banner():
    cprint("\n========== SYSTEM UPDATE MODULE ==========", Color.MAGENTA)
    cprint("Security Monitoring Tool Updater\n", Color.MAGENTA)


def show_system_info():
    os_info = detect_os()

    cprint("[*] System Information:", Color.CYAN)
    cprint(f"  OS: {os_info.get('name', 'Unknown')}", Color.GREEN)
    cprint(f"  Version: {os_info.get('version', 'Unknown')}", Color.GREEN)
    cprint(f"  Package Manager: {os_info.get('pkg_manager', 'Unknown')}\n", Color.GREEN)


def update_system():
    """Run full system update"""

    require_root()
    banner()

    os_info = detect_os()
    pkg = os_info.get("pkg_manager")

    if not pkg:
        cprint("[!] Supported package manager not found.", Color.RED)
        log_event("ERROR", "No package manager detected")
        return

    show_system_info()

    cmd = UPGRADE_COMMANDS.get(pkg)

    if not cmd:
        cprint("[!] Update command not available.", Color.RED)
        return

    cprint("[*] Starting system update...", Color.CYAN)

    start = time.time()

    code, out, err = run_command(cmd)

    duration = round(time.time() - start, 2)

    if code == 0:
        cprint("[✓] System update completed successfully", Color.GREEN)
        log_event("SUCCESS", f"System updated via {pkg} ({duration}s)")
    else:
        cprint("[!] System update finished with errors", Color.YELLOW)
        log_event("WARN", f"Update finished with code {code}")


def check_pip():
    """Check if pip3 exists"""
    if shutil.which("pip3") is None:
        cprint("[!] pip3 not found. Installing pip...", Color.YELLOW)

        os_info = detect_os()
        pkg = os_info.get("pkg_manager")

        install_cmds = {
            "apt": "apt install python3-pip -y",
            "apt-get": "apt install python3-pip -y",
            "yum": "yum install python3-pip -y",
            "dnf": "dnf install python3-pip -y",
            "pacman": "pacman -S python-pip --noconfirm"
        }

        cmd = install_cmds.get(pkg)

        if cmd:
            run_command(cmd)


def install_python_deps():
    """Install Python dependencies"""

    require_root()
    check_pip()

    banner()
    cprint("[*] Installing Python dependencies\n", Color.CYAN)

    success = 0
    failed = 0

    for pkg in PYTHON_DEPS:

        cprint(f"[*] Installing {pkg}...", Color.CYAN)

        code, _, _ = run_command(f"pip3 install {pkg} --quiet")

        if code == 0:
            cprint(f"[✓] {pkg} installed", Color.GREEN)
            success += 1
        else:
            cprint(f"[!] Failed to install {pkg}", Color.YELLOW)
            failed += 1

    cprint("\n========== INSTALL SUMMARY ==========", Color.MAGENTA)
    cprint(f"Success : {success}", Color.GREEN)
    cprint(f"Failed  : {failed}", Color.RED)

    log_event("INFO", f"Python deps installed success={success} fail={failed}")