# RangerScan - Lightweight Python Port Scanner

Fast, multithreaded TCP port scanner built from scratch in Python. A security tool for learning and authorized testing.

## Features
- TCP Connect Scan
- Service detection / Banner grabbing
- Multithreaded (50x faster)
- Supports port ranges (1-1000) and lists (22,80,443)
- Save output to file

## Installation
git clone https://github.com/Omo-Dan/rangerscan.git
cd rangerscan

## Usage
python scanner.py scanme.nmap.org -p 1-100
python scanner.py 127.0.0.1 -p 1-1000 -t 100
python scanner.py example.com -p 22,80,443 -o results.txt

## Demo
[*] Scanning scanme.nmap.org with 50 threads...
[+] Port 22: OPEN - ssh
[+] Port 80: OPEN - http

## Tech Stack
Python 3, sockets, threading, argparse

## Legal Disclaimer
For educational purposes and authorized testing only. Do not scan targets you don't own without permission.

## Author
Built by Omo-Dan | Cybersecurity Analyst & Software Engineer