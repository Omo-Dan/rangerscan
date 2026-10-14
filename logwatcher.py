import re
import sqlite3
from datetime import datetime

DB_FILE = "rangerscan.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks
                 (id INTEGER PRIMARY KEY, ip TEXT, attempts INTEGER, last_seen TEXT, blocked INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()
    print("[*] DB initialized: rangerscan.db")

def parse_log(log_file="auth.log"):
    # Regex for Failed password
    pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
    ips = {}

    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    ips[ip] = ips.get(ip, 0) + 1
    except FileNotFoundError:
        print(f"[!] {log_file} not found, creating fake log for demo")
        # Create demo log
        with open(log_file, 'w') as f:
            f.write("Failed password for root from 192.168.1.100\n" * 6)
            f.write("Failed password for admin from 10.0.0.5\n" * 3)
        return parse_log(log_file)

    return ips

def save_to_db(ips):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    for ip, count in ips.items():
        c.execute("SELECT attempts FROM attacks WHERE ip=?", (ip,))
        row = c.fetchone()

        if row:
            c.execute("UPDATE attacks SET attempts=?, last_seen=? WHERE ip=?",
                      (count, datetime.now().isoformat(), ip))
        else:
            c.execute("INSERT INTO attacks (ip, attempts, last_seen) VALUES (?,?,?)",
                      (ip, count, datetime.now().isoformat()))

        # Alert logic
        if count >= 5:
            print(f"[ALERT] BRUTE FORCE DETECTED! IP {ip} - {count} attempts - SHOULD BLOCK")
        else:
            print(f"[INFO] IP {ip} - {count} attempts")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    results = parse_log()
    save_to_db(results)
    print("\n[DB] Check: sqlite3 rangerscan.db 'SELECT * FROM attacks;'")
