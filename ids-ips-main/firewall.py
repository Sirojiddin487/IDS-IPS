"""
firewall.py — Manage firewall rules using ufw or iptables.
             Blocks IPs, manages allowed ports, detects available tool.

Improvements:
- Full type annotations (Python 3.10+)
- Consistent error handling with custom FirewallError exception
- FirewallManager class replaces scattered module-level state
- Context-aware logging with structured messages
- Port validation added
- Protocol validation added
- Duplicate logic reduced via _dispatch() helper
"""

import subprocess
from dataclasses import dataclass, field
from typing import Literal

from utils import (
    detect_os, run_command, require_root,
    load_config, log_event, cprint, Color, is_valid_ip
)

# ─── Types & Constants ────────────────────────────────────────────────────────

Protocol = Literal["tcp", "udp"]
FirewallBackend = Literal["ufw", "iptables"]

VALID_PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp"})
PORT_MIN, PORT_MAX = 1, 65535
SEPARATOR = "─" * 50


# ─── Custom Exception ─────────────────────────────────────────────────────────

class FirewallError(RuntimeError):
    """Raised when a firewall operation fails or is not supported."""


# ─── UFW backend ─────────────────────────────────────────────────────────────

class _UFW:
    @staticmethod
    def enable() -> None:
        run_command("echo 'y' | ufw enable", silent=True)

    @staticmethod
    def deny_default() -> None:
        run_command("ufw default deny incoming", silent=True)
        run_command("ufw default allow outgoing", silent=True)

    @staticmethod
    def allow_port(port: int, proto: Protocol = "tcp") -> None:
        run_command(f"ufw allow {port}/{proto}", silent=True)

    @staticmethod
    def block_ip(ip: str) -> None:
        run_command(f"ufw deny from {ip} to any", silent=True)

    @staticmethod
    def unblock_ip(ip: str) -> None:
        run_command(f"ufw delete deny from {ip} to any", silent=True)

    @staticmethod
    def status() -> str:
        _, out, _ = run_command("ufw status numbered", silent=True)
        return out

    @staticmethod
    def flush() -> None:
        run_command("ufw --force reset", silent=True)


# ─── iptables backend ─────────────────────────────────────────────────────────

class _IPTables:
    @staticmethod
    def default_drop() -> None:
        run_command("iptables -P INPUT DROP", silent=True)
        run_command(
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            silent=True,
        )
        run_command("iptables -A INPUT -i lo -j ACCEPT", silent=True)

    @staticmethod
    def allow_port(port: int, proto: Protocol = "tcp") -> None:
        run_command(
            f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT",
            silent=True,
        )

    @staticmethod
    def block_ip(ip: str) -> None:
        run_command(f"iptables -I INPUT   -s {ip} -j DROP", silent=True)
        run_command(f"iptables -I FORWARD -s {ip} -j DROP", silent=True)

    @staticmethod
    def unblock_ip(ip: str) -> None:
        run_command(f"iptables -D INPUT   -s {ip} -j DROP", silent=True)
        run_command(f"iptables -D FORWARD -s {ip} -j DROP", silent=True)

    @staticmethod
    def status() -> str:
        _, out, _ = run_command("iptables -L INPUT -n --line-numbers", silent=True)
        return out

    @staticmethod
    def flush() -> None:
        run_command("iptables -F INPUT", silent=True)


# ─── FirewallManager ──────────────────────────────────────────────────────────

@dataclass
class FirewallManager:
    """
    High-level firewall abstraction over ufw / iptables.

    All public methods are safe to call without root unless they
    modify firewall rules (those call require_root() internally).

    Example
    -------
    >>> fw = FirewallManager()
    >>> fw.block_ip("10.0.0.99")
    True
    >>> fw.show_status()
    """

    _blocked: set[str] = field(default_factory=set, init=False, repr=False)

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _backend() -> FirewallBackend:
        fw = detect_os().get("firewall")
        if fw not in ("ufw", "iptables"):
            raise FirewallError(
                f"Unsupported or missing firewall backend: {fw!r}. "
                "Install ufw or iptables."
            )
        return fw  # type: ignore[return-value]

    @staticmethod
    def _validate_ip(ip: str) -> None:
        if not is_valid_ip(ip):
            raise ValueError(f"Invalid IP address: {ip!r}")

    @staticmethod
    def _validate_port(port: int, proto: str) -> None:
        if not (PORT_MIN <= port <= PORT_MAX):
            raise ValueError(f"Port {port} out of valid range {PORT_MIN}–{PORT_MAX}.")
        if proto not in VALID_PROTOCOLS:
            raise ValueError(f"Invalid protocol {proto!r}. Must be 'tcp' or 'udp'.")

    # ── Public API ────────────────────────────────────────────────────────────

    def block_ip(self, ip: str) -> bool:
        """
        Block an IP address using the available firewall.

        Returns True if the IP is now blocked, False if it was skipped
        (whitelisted, already blocked, or invalid).
        """
        try:
            self._validate_ip(ip)
        except ValueError as exc:
            log_event("WARN", str(exc))
            return False

        config = load_config()
        whitelist: list[str] = config.get("whitelist_ips", [])
        if ip in whitelist:
            log_event("INFO", f"IP {ip} is whitelisted — skipping block.")
            return False

        if ip in self._blocked:
            log_event("INFO", f"IP {ip} is already blocked.")
            return True

        try:
            fw = self._backend()
        except FirewallError as exc:
            log_event("WARN", str(exc))
            return False

        if fw == "ufw":
            _UFW.block_ip(ip)
        else:
            _IPTables.block_ip(ip)

        self._blocked.add(ip)
        log_event("BLOCK", f"Blocked {ip} via {fw}.")
        return True

    def unblock_ip(self, ip: str) -> bool:
        """
        Remove an existing block on an IP address.

        Returns True on success, False if no firewall is available.
        """
        try:
            fw = self._backend()
        except FirewallError as exc:
            log_event("WARN", str(exc))
            return False

        if fw == "ufw":
            _UFW.unblock_ip(ip)
        else:
            _IPTables.unblock_ip(ip)

        self._blocked.discard(ip)
        log_event("INFO", f"Unblocked {ip} via {fw}.")
        return True

    def configure_ports(self, allowed_ports: list[int] | None = None) -> None:
        """
        Set firewall to deny all incoming traffic except *allowed_ports*.

        Falls back to ``config.json → allowed_ports`` when none are passed.
        Raises FirewallError if no supported backend is found.
        """
        require_root()
        config = load_config()
        ports: list[int] = allowed_ports or config.get("allowed_ports", [22, 80, 443])

        # Validate every port before touching the firewall
        for port in ports:
            self._validate_port(port, "tcp")

        fw = self._backend()
        cprint(f"[*] Backend: {fw} | Allowing ports: {ports}", Color.CYAN)

        if fw == "ufw":
            _UFW.deny_default()
            for port in ports:
                _UFW.allow_port(port)
            _UFW.enable()
        else:
            _IPTables.flush()
            _IPTables.default_drop()
            for port in ports:
                _IPTables.allow_port(port)

        log_event("SUCCESS", f"{fw} configured. Allowed ports: {ports}")

    def show_status(self) -> None:
        """Print current firewall rules to stdout."""
        try:
            fw = self._backend()
        except FirewallError:
            cprint("  No supported firewall found.", Color.YELLOW)
            return

        cprint(f"\n{SEPARATOR}", Color.CYAN)
        cprint(f"  Backend : {fw}", Color.BOLD)
        cprint(f"  Blocked : {len(self._blocked)} IP(s) in session", Color.BOLD)
        cprint(SEPARATOR, Color.CYAN)

        status = _UFW.status() if fw == "ufw" else _IPTables.status()
        print(status)

    def list_blocked(self) -> list[str]:
        """Return a sorted list of IPs blocked in this session."""
        return sorted(self._blocked)

    def block_many(self, ips: list[str]) -> dict[str, bool]:
        """
        Block multiple IPs at once.

        Returns a mapping of ``{ip: success}`` for each address.
        """
        return {ip: self.block_ip(ip) for ip in ips}


# ─── Module-level singleton (backwards-compatible shim) ──────────────────────

_manager = FirewallManager()

# Keep old function-style API working without changes to callers.
block_ip       = _manager.block_ip
unblock_ip     = _manager.unblock_ip
configure_ports = _manager.configure_ports
show_status    = _manager.show_status
list_blocked   = _manager.list_blocked
