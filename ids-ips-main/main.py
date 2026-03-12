#!/usr/bin/env python3
"""
main.py — IDS/IPS CLI entry point.

Usage:
  python main.py start                     Start real-time IDS/IPS monitoring
  python main.py update                    Update system packages
  python main.py ports --allow 22,80,443   Configure firewall allowed ports
  python main.py logs --analyze            Static scan of all configured log files
  python main.py logs --file /path/to.log  Static scan of a specific file
  python main.py alerts                    Send a Telegram test alert
  python main.py status                    Show firewall + IPS status
  python main.py block <ip>               Manually block an IP
  python main.py unblock <ip>             Unblock an IP
"""

import sys
import argparse
import time
import threading

from utils import banner, cprint, Color, detect_os, load_config, log_event
import updater
import firewall
import log_analyzer
import ips as IPS
import telegram_alert


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_start(args) -> None:
    """Start full IDS/IPS: port lockdown + real-time log monitoring."""
    config = load_config()
    cprint("\n[*] Starting IDS/IPS...", Color.CYAN)

    # System info
    os_info = detect_os()
    cprint(f"[*] OS: {os_info['distro']}  |  Firewall: {os_info['firewall']}  |  PKG: {os_info['pkg_manager']}", Color.CYAN)

    # Configure firewall
    allowed = config.get("allowed_ports", [22, 80, 443])
    cprint(f"[*] Configuring firewall — allowing ports: {allowed}", Color.CYAN)
    try:
        firewall.configure_ports(allowed)
    except SystemExit:
        cprint("[!] Root required for firewall management. Skipping port config.", Color.YELLOW)

    # Start log monitoring (blocking — loops until Ctrl+C)
    cprint("\n[*] Starting real-time log monitoring (Ctrl+C to stop)...\n", Color.GREEN)
    log_analyzer.start_monitoring()


def cmd_update(args) -> None:
    cprint("\n[*] Starting system update...", Color.CYAN)
    updater.update_system()


def cmd_ports(args) -> None:
    if args.allow:
        try:
            ports = [int(p.strip()) for p in args.allow.split(",")]
        except ValueError:
            cprint("[!] Invalid port list. Use: --allow 22,80,443", Color.RED)
            sys.exit(1)
    else:
        config = load_config()
        ports  = config.get("allowed_ports", [22, 80, 443])

    firewall.configure_ports(ports)
    firewall.show_status()


def cmd_logs(args) -> None:
    config = load_config()

    if args.file:
        # Scan a specific file
        log_analyzer.scan_file_once(args.file)
        IPS.show_stats()
    elif args.analyze:
        # Scan all configured log files
        paths = config.get("log_paths", [])
        if not paths:
            cprint("[!] No log_paths configured in config.json", Color.YELLOW)
            return
        total = 0
        for path in paths:
            total += log_analyzer.scan_file_once(path)
        cprint(f"\n[✓] Total threats across all files: {total}", Color.GREEN)
        IPS.show_stats()
    else:
        cprint("[!] Use --analyze or --file <path>", Color.YELLOW)


def cmd_alerts(args) -> None:
    cprint("\n[*] Sending test Telegram alert...", Color.CYAN)
    telegram_alert.send_test_alert()


def cmd_status(args) -> None:
    os_info = detect_os()
    cprint(f"\n[*] System: {os_info['distro']}  Firewall: {os_info['firewall']}  PKG: {os_info['pkg_manager']}", Color.CYAN)
    firewall.show_status()
    IPS.show_stats()


def cmd_block(args) -> None:
    if not args.ip:
        cprint("[!] Provide an IP: python main.py block <ip>", Color.RED)
        sys.exit(1)
    IPS.force_block(args.ip, reason="manual-cli")


def cmd_unblock(args) -> None:
    if not args.ip:
        cprint("[!] Provide an IP: python main.py unblock <ip>", Color.RED)
        sys.exit(1)
    IPS.unblock_ip(args.ip)


# ─── Argument parser ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids",
        description="IDS/IPS — Intrusion Detection & Prevention System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    sub = parser.add_subparsers(dest="command")

    # start
    sub.add_parser("start", help="Start real-time IDS/IPS monitoring")

    # update
    sub.add_parser("update", help="Update system packages")

    # ports
    p_ports = sub.add_parser("ports", help="Configure allowed firewall ports")
    p_ports.add_argument("--allow", metavar="PORTS",
                         help="Comma-separated ports to allow, e.g. 22,80,443")

    # logs
    p_logs = sub.add_parser("logs", help="Analyze web server logs")
    p_logs.add_argument("--analyze", action="store_true",
                        help="Scan all configured log files")
    p_logs.add_argument("--file", metavar="PATH",
                        help="Scan a specific log file")

    # alerts
    sub.add_parser("alerts", help="Send a Telegram test alert")

    # status
    sub.add_parser("status", help="Show firewall and IPS status")

    # block / unblock
    p_block = sub.add_parser("block", help="Manually block an IP")
    p_block.add_argument("ip", nargs="?", help="IP address to block")

    p_unblock = sub.add_parser("unblock", help="Unblock an IP")
    p_unblock.add_argument("ip", nargs="?", help="IP address to unblock")

    return parser


# ─── Entry point ─────────────────────────────────────────────────────────────

COMMANDS = {
    "start":   cmd_start,
    "update":  cmd_update,
    "ports":   cmd_ports,
    "logs":    cmd_logs,
    "alerts":  cmd_alerts,
    "status":  cmd_status,
    "block":   cmd_block,
    "unblock": cmd_unblock,
}

def main() -> None:
    banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handler = COMMANDS.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            cprint("\n[*] Interrupted. Shutting down.", Color.CYAN)
        except Exception as e:
            cprint(f"\n[!] Error: {e}", Color.RED)
            raise
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
