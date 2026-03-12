"""
telegram_alert.py — Send real-time Telegram alerts to the admin.
"""

import json
import urllib.request
import urllib.parse
from utils import load_config, log_event, timestamp

ATTACK_EMOJI = {
    "sql_injection":       "💉",
    "xss":                 "🕸️",
    "directory_traversal": "📂",
    "scanner":             "🔍",
    "rce_attempts":        "💀",
    "unknown":             "⚠️",
}


def send_alert(ip: str, attack_type: str, endpoint: str, details: str = "") -> bool:
    """
    Send a Telegram message to the admin.
    Returns True on success, False on failure.
    """
    config = load_config()
    token      = config.get("bot_token", "")
    chat_id    = config.get("admin_telegram_id", "")

    if not token or token == "YOUR_TELEGRAM_BOT_TOKEN":
        log_event("WARN", "Telegram bot_token not configured — skipping alert.")
        return False
    if not chat_id or chat_id == "YOUR_TELEGRAM_CHAT_ID":
        log_event("WARN", "Telegram admin_telegram_id not configured — skipping alert.")
        return False

    emoji = ATTACK_EMOJI.get(attack_type, "⚠️")
    text = (
        f"{emoji} *IDS/IPS ALERT*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🚨 *Attack Type:* `{attack_type.replace('_', ' ').upper()}`\n"
        f"🌐 *Source IP:*   `{ip}`\n"
        f"📍 *Endpoint:*    `{endpoint}`\n"
        f"🕐 *Time:*        `{timestamp()}`\n"
    )
    if details:
        text += f"📝 *Details:*     `{details[:200]}`\n"
    text += "━━━━━━━━━━━━━━━━━━━━\n🛡️ IP has been *BLOCKED*."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "Markdown",
    }

    try:
        data = urllib.parse.urlencode(payload).encode()
        req  = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                log_event("INFO", f"Telegram alert sent for {ip} ({attack_type})")
                return True
            else:
                log_event("WARN", f"Telegram API error: {result}")
                return False
    except Exception as e:
        log_event("WARN", f"Failed to send Telegram alert: {e}")
        return False


def send_test_alert() -> None:
    """Send a test message to verify Telegram configuration."""
    config = load_config()
    token   = config.get("bot_token", "")
    chat_id = config.get("admin_telegram_id", "")

    if not token or token == "YOUR_TELEGRAM_BOT_TOKEN":
        print("[!] Set bot_token in config.json first.")
        return
    if not chat_id or chat_id == "YOUR_TELEGRAM_CHAT_ID":
        print("[!] Set admin_telegram_id in config.json first.")
        return

    text = (
        "✅ *IDS/IPS — Test Alert*\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 Time: `{timestamp()}`\n"
        "Your Telegram alert system is working correctly!"
    )
    url     = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    data    = urllib.parse.urlencode(payload).encode()
    req     = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            if result.get("ok"):
                print("[✓] Test alert sent successfully!")
            else:
                print(f"[!] Telegram error: {result.get('description')}")
    except Exception as e:
        print(f"[!] Could not reach Telegram API: {e}")
