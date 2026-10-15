import socket
import argparse
import sqlite3
import re
import requests
from datetime import datetime

DB = "rangerscan.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (ip TEXT PRIMARY KEY, attempts INTEGER, last_seen TEXT)''')
    conn.commit()
    conn.close()

def scan_target(target, port):
    print(f"[*] Scanning {target}:{port}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))

        if result!= 0:
            print(f"[-] {target}:{port} closed")
            sock.close()
            return

        # Banner grab
        try:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode(errors='ignore')
            if banner:
                print(f"[BANNER] {banner.splitlines()[0][:100]}")
        except:
            pass

        sock.close()

        # Web header audit for port 80,443,8080
        if port in [80, 443, 8080, 8000]:
            check_web_headers(target, port)

    except socket.timeout:
        print(f"[-] {target}:{port} filtered (timeout - firewall)")
    except ConnectionRefusedError:
        print(f"[-] {target}:{port} closed")
    except Exception as e:
        print(f"[ERROR] {e}")

def check_web_headers(target, port):
    try:
        proto = "https" if port == 443 else "http"
        url = f"{proto}://{target}:{port}"
        r = requests.get(url, timeout=3)
        server = r.headers.get('Server', 'Unknown')
        print(f"[WEB SERVER] {server}")

        vulns = []
        if 'X-Frame-Options' not in r.headers:
            vulns.append("Missing X-Frame-Options")
        if 'Content-Security-Policy' not in r.headers:
            vulns.append("Missing CSP")

        for v in vulns:
            print(f"[VULN] {v}")

    except Exception as e:
        pass

def parse_logs(logfile="auth.log"):
    print("[*] Parsing logs...")
    pattern = r"Failed password for.* from (\d+\.\d+\.\d+\.\d+)"
    ips = {}
    try:
        with open(logfile, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    ips[ip] = ips.get(ip, 0) + 1
    except FileNotFoundError:
        print(f"[-] {logfile} not found")
        return

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    for ip, count in ips.items():
        now = datetime.now().isoformat()
        # Fix duplicate IP bug with UNIQUE
        c.execute("INSERT OR REPLACE INTO logs (ip, attempts, last_seen) VALUES (?,?,?)",
                  (ip, count, now))
        if count >= 5:
            print(f"[ALERT] BRUTE FORCE {ip} - {count}x")
        else:
            print(f"[INFO] {ip} - {count}x")
    conn.commit()
    conn.close()

def report():
    print("\n===== RANGER SCAN REPORT =====")
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        for row in c.execute("SELECT * FROM logs"):
            print(f"IP: {row[0]} | Attempts: {row[1]} | Last: {row[2]}")
    except:
        print("No logs yet")
    conn.close()

if __name__ == "__main__":
    init_db()
    parser = argparse.ArgumentParser(description="RangerScan v1.0 SOC Dashboard")
    parser.add_argument('--scan', nargs=2, metavar=('TARGET', 'PORT'), help='Scan target')
    parser.add_argument('--logs', action='store_true', help='Parse auth logs')
    parser.add_argument('--report', action='store_true', help='Show report')
    args = parser.parse_args()

    if args.scan:
        target = args.scan[0]
        port = int(args.scan[1])
        scan_target(target, port)
    if args.logs:
        parse_logs()
    if args.report:
        report()
    if not any(vars(args).values()):
        parser.print_help()