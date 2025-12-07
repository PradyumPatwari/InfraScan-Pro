
# InfraScan-Pro
Advanced Network Scanner (Nmap + Scapy + GUI + Reporting)
# NetReconX (scanner_v3.6)

**NetReconX — Multi-Feature Network Tool (Version 3.6)**  
A lab-only reconnaissance tool built with Python, Nmap and Scapy for educational and testing purposes.

> **Important:** Only use this tool on networks and hosts you own or have explicit written permission to test.

---

## Features
- Nmap-based scanning (SYN/UDP/OS/Aggressive/NSE)
- Banner grabbing for service identification
- Host discovery (ARP sweep)
- Packet sniffing using Scapy and saving PCAPs
- Interactive CLI menu workflow
- Simple offline CVE hints
- Report saving (text)

## Quickstart (local / VM)
1. Clone or download this repo (browser download or `git clone`).
2. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
