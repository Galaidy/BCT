# BCT — SNI Spoofing Config Modifier

### Overview

A lightweight desktop tool for editing and transforming V2Ray configuration links.
Supports **VLESS**, **VMess**, **Trojan**, and **Shadowsocks** protocols.

The main purpose is to make it easier to batch-edit configs, decode Base64 subscription links,
and quickly adjust connection parameters like host, port, and SNI.

It can also prepare configurations for use in SNI spoofing-related workflows:
👉 [github.com/patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

---

### Features

- 🔀 **SNI Spoof** — redirect address to `127.0.0.1:40443` and set TLS/SNI automatically
- 🌐 **Replace IP** — batch-replace the host/IP across all configs
- 🔌 **Replace Port** — batch-replace the port across all configs
- ✏️ **Replace Both** — update IP and port in one step
- 📦 **Base64 Support** — auto-detects and decodes subscription links
- 📋 **Auto Copy** — output is copied to clipboard automatically

---

### Download

| Version | Type | Link |
|---------|------|------|
| v1.0.0 | Windows EXE | [Download](../../releases/latest) |
| v1.0.0 | Python Script | [bct.py](bct.py) |

> The `.exe` requires no installation — just download and run.

---

### Run from Source

Requires Python 3.8+ and PyQt5:

```
pip install PyQt5
python bct.py
```

---

### Support Paterniha

If you find this project useful, consider supporting the original developer:

- **USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
- **USDT (TRC20):** `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`
