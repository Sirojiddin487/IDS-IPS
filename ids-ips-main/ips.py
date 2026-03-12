"""
ips.py — Intrusion Prevention System.
         Receives suspicious IPs from log_analyzer, applies blocks,
         tracks hit counts, triggers Telegram alerts.
"""

import threading
from collections import defaultdict
from utils import load_config, log_event, cprint, Color, timestamp
import firewall
import telegram_alert

# ─── State ───────────────────────────────────────────────────────────────────
_lock      = threading.Lock()
_hit_count: dict[str, int]              = defaultdict(int)
_blocked:   dict[str, str]              = {}   # ip → timestamp blocked
_events:    list[dict]                  = []   # audit log


# ─── Core logic ──────────────────────────────────────────────────────────────

def report_threat(ip: str, attack_type: str, endpoint: str, raw_line: str = "") -> None:
    """
    Called by log_analyzer when a suspicious request is detected.
    Increments hit counter; blocks IP once threshold is reached.
    """
    config    = load_config()
    threshold = config.get("block_threshold", 3)

    with _lock:
        _hit_count[ip] += 1
        hits = _hit_count[ip]

        event = {
            "ip":          ip,
            "attack_type": attack_type,
            "endpoint":    endpoint,
            "hits":        hits,
            "time":        timestamp(),
        }
        _events.append(event)

        cprint(
            f"  [THREAT] {ip}  type={attack_type}  endpoint={endpoint}  hits={hits}/{threshold}",
            Color.YELLOW
        )

        if hits >= threshold and ip not in _blocked:
            _block_and_alert(ip, attack_type, endpoint, raw_line)


def _block_and_alert(ip: str, attack_type: str, endpoint: str, raw_line: str) -> None:
    """Block IP and send Telegram alert. Called inside _lock."""
    success = firewall.block_ip(ip)
    if success:
        _blocked[ip] = timestamp()
        log_event("ALERT", f"IP {ip} BLOCKED — {attack_type} on {endpoint}")
        # Fire alert in background thread to avoid blocking the monitor
        t = threading.Thread(
            target=telegram_alert.send_alert,
            args=(ip, attack_type, endpoint, raw_line[:300]),
            daemon=True
        )
        t.start()
    else:
        log_event("WARN", f"Failed to block {ip}")


def force_block(ip: str, reason: str = "manual") -> None:
    """Manually block an IP immediately, regardless of threshold."""
    with _lock:
        if ip not in _blocked:
            firewall.block_ip(ip)
            _blocked[ip] = timestamp()
            log_event("BLOCK", f"Manual block: {ip} ({reason})")
        else:
            cprint(f"  {ip} is already blocked.", Color.YELLOW)


def unblock_ip(ip: str) -> None:
    """Unblock an IP and reset its hit counter."""
    with _lock:
        firewall.unblock_ip(ip)
        _blocked.pop(ip, None)
        _hit_count.pop(ip, None)
        log_event("INFO", f"Unblocked: {ip}")


def show_stats() -> None:
    """Print current IPS state to console."""
    cprint(f"\n{'─'*55}", Color.CYAN)
    cprint("  IPS Statistics", Color.BOLD)
    cprint(f"{'─'*55}", Color.CYAN)
    cprint(f"  Total threats detected : {len(_events)}", Color.RESET)
    cprint(f"  Unique IPs with hits   : {len(_hit_count)}", Color.RESET)
    cprint(f"  Currently blocked IPs  : {len(_blocked)}", Color.RED)

    if _blocked:
        cprint("\n  Blocked IPs:", Color.MAGENTA)
        for ip, ts in _blocked.items():
            cprint(f"    {ip:<20}  blocked at {ts}", Color.MAGENTA)

    if _hit_count:
        cprint("\n  Hit counts (not yet blocked):", Color.YELLOW)
        for ip, count in sorted(_hit_count.items(), key=lambda x: -x[1]):
            if ip not in _blocked:
                cprint(f"    {ip:<20}  {count} hits", Color.YELLOW)
    cprint(f"{'─'*55}\n", Color.CYAN)


def get_blocked_ips() -> dict[str, str]:
    return dict(_blocked)

def get_recent_events(n: int = 20) -> list[dict]:
    return _events[-n:]
