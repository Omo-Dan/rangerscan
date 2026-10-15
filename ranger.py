import argparse
import socket
import requests
import sqlite3
import re
from datetime import datetime

DB_FILE = "rangerscan.db"

# --- From vuln.py ---
CVE_DB = {
    "OpenSSH_6.6.1": "CVE-2015-5600 HIGH",
    "OpenSSH_7.2": "CVE-2016-10009 MEDIUM",
}

def scan_target(target, port):
    print(f"[*] Scanning {target}:{port}")
    try:
        if port in [80, 443]:
            url = f"{'https' if port==443 else 'http'}://{target}:{port}"
            r = requests.get(url, timeout=5)
            print(f"[WEB SERVER] {r.headers.get('Server','Unknown')}")
            issues = []
            if "X-Frame-Options" not in r.headers:
                issues.append("Missing X-Frame-Options")
            if "Content-Security-Policy" not in r.headers:
                issues.append("Missing CSP")
            if issues:
                print(f"[VULN] { ' | '.join(issues) }")
            else:
                print("[SAFE] Headers OK")
        else:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors='ignore')
            print(f"[BANNER] {banner.strip()}")
            found = False
            for k,v in CVE_DB.items():
                if k in banner:
                    print(f"[CVE] {v}")
                    found = True
            if not found:
                print("[SAFE] No known CVE")
            s.close()
    except Exception as e:
        print(f"[ERROR] {e}")

# --- From logwatcher.py ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS attacks
             (id INTEGER PRIMARY KEY, ip TEXT UNIQUE, attempts INTEGER, last_seen TEXT)''')

    conn.commit()
    conn.close()

def check_logs(log_file="auth.log"):
    init_db()
    pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    ips = {}
    try:
        with open(log_file) as f:
            for line in f:
                m = re.search(pattern, line)
                if m:
                    ip = m.group(1)
                    ips[ip] = ips.get(ip, 0) + 1
    except FileNotFoundError:
        print(f"[!] {log_file} not found")
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for ip, count in ips.items():
        c.execute("INSERT OR REPLACE INTO attacks (ip, attempts, last_seen) VALUES (?,?,?)",
                  (ip, count, datetime.now().isoformat()))
        if count >= 5:
            print(f"[ALERT] BRUTE FORCE {ip} - {count}x")
        else:
            print(f"[INFO] {ip} - {count}x")
    conn.commit()
    conn.close()

def show_report():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    print("\n===== RANGER SCAN REPORT =====")
    for row in c.execute("SELECT ip, attempts, last_seen FROM attacks ORDER BY attempts DESC"):
        print(f"IP: {row[0]} | Attempts: {row[1]} | Last: {row[2]}")
    conn.close()
    print("==============================")

# --- CLI ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RangerScan - Unified Security Tool")
    parser.add_argument("--scan", nargs=2, metavar=('TARGET','PORT'), help="Scan target")
    parser.add_argument("--logs", action="store_true", help="Check auth.log for attacks")
    parser.add_argument("--report", action="store_true", help="Show DB report")

    args = parser.parse_args()

    if args.scan:
        scan_target(args.scan[0], int(args.scan[1]))
    elif args.logs:
        check_logs()
    elif args.report:
        show_report()
    else:
        parser.print_help()
