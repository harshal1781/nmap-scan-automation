# nmap-scan-automation
A simple Python wrapper for Nmap that automates basic SYN and optional UDP scans and outputs a human-readable text report. Intended for authorized testing and learning purposes. 🔍🛠️

Requirements:
Python 3 🐍
nmap binary installed (Nmap) 🧭
python3-nmap library (Debian/Ubuntu/Kali package name: python3-nmap) 📦
Recommended: sudo privileges for SYN (-sS) and UDP (-sU) scans ⚠️

Installation (Debian/Ubuntu/Kali)
Run:
sudo apt update
sudo apt install -y nmap python3-nmap ✅

If you prefer an isolated environment (virtualenv)
sudo apt install -y python3-venv python3-pip
python3 -m venv ~/venv_nmap
source ~/venv_nmap/bin/activate
pip install python-nmap 🛡️

Usage
Basic SYN scan with version detection (recommended if you have privileges):
sudo python3 nmap_automation.py <target> --out scan_report.txt ▶️

Include UDP scan (slower; may require sudo):
sudo python3 nmap_automation.py <target> --udp --out scan_report_udp.txt 🐢

Notes on arguments:
<target>: target IP or hostname (use only on systems you are authorized to test) ✅🔒
--udp: include UDP scanning (-sU) ⚠️ (slower)
--out: output filename (defaults to scan_report.txt) 💾

Safety and legal ⚖️
Only run this script against systems you own or have explicit written permission to test. Unauthorized scanning can be illegal and may trigger intrusion detection or legal action. Always sanitize any output or screenshots before sharing publicly. 🚫👮
