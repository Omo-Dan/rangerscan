# RangerScan - Lightweight Python Port Scanner

Fast, multithreaded TCP port scanner built from scratch in Python. A security tool for learning and authorized testing.

## Features
- TCP Connect Scan
- Service detection
- Multithreaded (50x faster)
- Supports port ranges (1-1000) and lists (22,80,443)
- Clean CLI

## Usage

# Scan top 100 ports
python scanner.py scanme.nmap.org -p 1-100

# Fast scan with 100 threads
python scanner.py 127.0.0.1 -p 1-1000 -t 100

# Scan specific ports
python scanner.py example.com -p 22,80,443

## Demo
[*] Scanning scanme.nmap.org with 50 threads...
[+] Port 22: OPEN - ssh
[+] Port 80: OPEN - http

## Legal Disclaimer
For educational purposes and authorized testing only. Do not scan targets you don't own without permission.

## Tech Stack
Python 3, sockets, threading, argparse

## Author
Built during cybersecurity learning journey