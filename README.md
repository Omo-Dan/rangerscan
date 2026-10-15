# RangerScan - Lightweight Python Port Scanner -> Full SOC Dashboard v1.0

Fast, multithreaded TCP port scanner built from scratch in Python. Evolved into a full security dashboard. A security tool for learning and authorized testing.

## Features
- **Sprint 1:** TCP Connect Scan, Service detection / Banner grabbing, Multithreaded (50x faster), Supports port ranges and lists, Save output to file
- **Sprint 2:** CVE detection (OpenSSH_6.6.1 etc)
- **Sprint 3:** Log watcher, Brute force detection, SQLite storage
- **Sprint 4 FINAL:** Unified dashboard ranger.py + Venv + Web header audit (X-Frame-Options, CSP)

## Installation
git clone https://github.com/Omo-Dan/rangerscan.git
cd rangerscan
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

## Usage
# Old scanner
python scanner.py scanme.nmap.org -p 1-100
python scanner.py 127.0.0.1 -p 1-1000 -t 100
python scanner.py example.com -p 22,80,443 -o results.txt

# NEW v1.0 Dashboard
python ranger.py --scan scanme.nmap.org 22
python ranger.py --scan google.com 80
python ranger.py --logs
python ranger.py --report

## Demo v1.0
[*] Scanning google.com:80
[WEB SERVER] gws
[VULN] Missing CSP
[ALERT] BRUTE FORCE 192.168.1.100 - 6x
[INFO] 10.0.0.5 - 3x

===== RANGER SCAN REPORT =====
IP: 192.168.1.100 | Attempts: 6 | Last: 2026-10-15T10:42:47.825112
IP: 10.0.0.5 | Attempts: 3 | Last: 2026-10-15T10:42:47.828379

## Tech Stack
Python 3, sockets, threading, argparse, requests, sqlite3, regex, venv

## Project Evolution
- Sprint 1: Port scanner
- Sprint 2: vuln.py
- Sprint 3: logwatcher.py + DB
- Sprint 4: ranger.py final dashboard (fixed duplicate IP bug with UNIQUE constraint)

## Legal Disclaimer
For educational purposes and authorized testing only. Do not scan targets you don't own without permission.

## Author
Built by Omo-Dan | Cybersecurity Analyst & Software Engineer