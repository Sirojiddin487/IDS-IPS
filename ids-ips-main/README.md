# IDS/IPS — Intrusion Detection & Prevention System

A lightweight, **Python-native** IDS/IPS CLI tool for Linux servers.  
No Docker required. Adapts automatically to your OS and firewall.

---

## Features

- 🔍 **Real-time log monitoring** — Apache & Nginx access logs
- 🛡️ **Attack detection** — SQL injection, XSS, directory traversal, scanner UAs, RCE
- 🚫 **Automatic IP blocking** — via `ufw` or `iptables` (auto-detected)
- 📱 **Telegram alerts** — instant notifications with attack details
- 📦 **System updater** — `apt`, `yum`, `dnf`, `pacman` support
- 🔌 **Port management** — open only what you need, block the rest
- 🪵 **Audit log** — all events written to `ids.log`

---

## Requirements

- Linux (Debian/Ubuntu, CentOS/RHEL, Arch)
- Python 3.10+
- Root/sudo for firewall and package operations
- `ufw` or `iptables` installed
- Web server with access logs (Apache or Nginx)

---

## Setup

```bash
git clone <your-repo>
cd ids
```

Edit `config.json`:

```json
{
  "admin_telegram_id": "YOUR_CHAT_ID",
  "bot_token":         "YOUR_BOT_TOKEN",
  "allowed_ports":     [22, 80, 443],
  "log_paths": [
    "/var/log/nginx/access.log",
    "/var/log/apache2/access.log"
  ],
  "whitelist_ips":   ["127.0.0.1"],
  "block_threshold": 3
}
```

> Get your Telegram Chat ID by messaging [@userinfobot](https://t.me/userinfobot).  
> Create a bot via [@BotFather](https://t.me/BotFather) to get your token.

---

## CLI Commands

| Command | Description |
|---|---|
| `sudo python main.py start` | Start full IDS/IPS (firewall + real-time monitoring) |
| `sudo python main.py update` | Update system packages |
| `sudo python main.py ports --allow 22,80,443` | Configure allowed ports |
| `python main.py logs --analyze` | Static scan of all log files |
| `python main.py logs --file /var/log/nginx/access.log` | Scan specific log file |
| `python main.py alerts` | Send a Telegram test message |
| `sudo python main.py status` | Show firewall + IPS stats |
| `sudo python main.py block 1.2.3.4` | Manually block an IP |
| `sudo python main.py unblock 1.2.3.4` | Unblock an IP |

---

## Alert Format (Telegram)

```
💉 IDS/IPS ALERT
━━━━━━━━━━━━━━━━━━━━
🚨 Attack Type: SQL INJECTION
🌐 Source IP:   192.168.1.100
📍 Endpoint:    /login.php?id=1
🕐 Time:        2026-03-04 12:34:56
📝 Details:     GET /login.php?id=UNION SELECT...
━━━━━━━━━━━━━━━━━━━━
🛡️ IP has been BLOCKED.
```

---

## Architecture

```
ids/
 ├── main.py          CLI entry point & argument routing
 ├── utils.py         OS detection, logging, IP helpers, config loader
 ├── updater.py       System package manager detection & updates
 ├── firewall.py      ufw/iptables port management & IP blocking
 ├── log_analyzer.py  Real-time log tailing & attack pattern detection
 ├── ips.py           Threat aggregation, block threshold, alert dispatch
 ├── telegram_alert.py Telegram Bot API integration
 └── config.json      All configuration
```

---

## Extending

- Add new attack patterns in `config.json → scan_rules`
- Add new log paths in `config.json → log_paths`
- Increase `block_threshold` to reduce false positives
- Add IPs to `whitelist_ips` to protect trusted sources
# ids-ips
