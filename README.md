# Network Security Traffic Analyzer (MITM Simulation — Lab Only)

> **Educational & research tool. Do not use outside a lab you own or without written authorization.**
>
> This project showcases network security engineering skills: packet capture & analysis with Scapy, a real‑time dashboard
> (with authentication), host discovery, session anomaly detection, credential monitoring, Wi‑Fi deauth detection, and
> SQLite persistence. It includes a JSON‑configurable injection engine for controlled **MITM simulation** in an
> isolated environment.

## ⚖️ Ethical Use

This software is provided **for educational, research, and authorized penetration testing labs only**.
Using it on networks **without explicit written permission** may be illegal. By using this software, you agree to the
terms in **ETHICAL_USE.md** and the license.

## ✨ Features (high level)
- Host discovery and device vendor identification (OUI lookup database)
- Live web dashboard (Basic Auth) with stats, requests, sessions, credentials, hosts
- Session anomaly/hijack detection (e.g., `PHPSESSID`, `JSESSIONID`)
- DNS logging & HTTP request parsing (with credential pattern detection for lab forms)
- Optional content‑injection rules for controlled response modification (lab simulation)
- Optional Wi‑Fi monitoring for deauth attacks and beacon frames (monitor mode interface)
- SQLite persistence for requests, credentials, packets, hosts, sessions
- JSON configuration for rules and runtime options
- Multi‑threaded architecture (sniffer, ARP spoof loop, dashboard server)

## 🧱 Project Structure
```
.
├── ETHICAL_USE.md
├── LICENSE
├── README.md
├── requirements.txt
├── .gitignore
└── src/
    └── arper.py
```

## 🚀 Quick Start (Lab Only)
> Tested on Linux with Python 3.10+. You need **root privileges** (or `CAP_NET_RAW`) for packet operations.

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run in a **controlled lab** you own or have written authorization for. Example:
   ```bash
   # Replace placeholders with your lab interface and IPs
   sudo python src/arper.py -i <iface> -g <gateway_ip> -t <target_ip> -c config.json
   ```

3. Open the local dashboard (printed on start), authenticate, and observe live stats.
   - Default: `http://localhost:8080` (unless changed in config)

> **Note:** Modern HTTPS protections (HSTS, certificate pinning) limit downgrade attacks. This tool focuses on **controlled simulation** and **defensive analytics** in lab settings.

## ⚙️ Configuration
Provide a JSON config (e.g., `config.json`) to control injection rules, credential patterns, dashboard auth, and wireless monitoring. See inline defaults inside `src/arper.py` for available keys.

## 🧪 Suggested Lab Demo
- Spin up two Linux VMs and a lightweight web app with a dummy login form.
- Use the tool to observe DNS/HTTP metadata, detect mock credentials, and see session anomalies.
- Enable Wi‑Fi monitoring only with a dedicated adapter in monitor mode on an isolated test AP.

## 📜 License & Attribution
- License: **GPL‑3.0** (see `LICENSE`)
- Ethical Policy: see `ETHICAL_USE.md`
- Built with: Python, Scapy, SQLite

---

**Author:** Ishaq — Network Security Traffic Analyzer (MITM Simulation — Lab Only)
