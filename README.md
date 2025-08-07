# 🔐 Python HTTPS/HTTP File Server with GUI Dashboard

A lightweight, local HTTPS/HTTP server with a built-in Tkinter-based GUI. Designed for easy file hosting, logging, and certificate management — all in one app.

## 🚀 Features

- 🌐 Serve files over **HTTPS or plain HTTP**
- 🖥️ Modern **Tkinter GUI dashboard**
- 📁 Browse and select **certificate, key, and serving directory**
- 📊 Real-time request log with:
  - Time, IP, Method, Path, Size
  - Filters for Method/IP
  - Live statistics: total requests, bandwidth, uptime
- 🔐 **Generate self-signed certificate** directly from the GUI (no OpenSSL needed)
- 🧠 Auto-detect certificate/key from the app directory
- 📜 All requests are **logged to `server.log`**
- 💡 Easy-to-use and self-contained (1 Python file)

---
## Note:
you need to name the certificate file to ```cert.cert``` and key file to ```key.key```
---

## 🧰 Requirements

- Python 3.7+
- `cryptography` (for self-signed certs)

Install dependencies:
```bash
pip install cryptography
