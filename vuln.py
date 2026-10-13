import socket
from cve_db import VULN_DB
import sys

def grab_banner(ip, port):
    try:
        print(f"[*] Connecting to {ip}:{port}...")
        s = socket.socket()
        s.settimeout(5) # increased to 5 sec for Kenya internet
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return f"Error: {e}"

def check_cve(banner):
    for version, cve in VULN_DB.items():
        if version.lower() in banner.lower():
            return cve
    return "No known CVE - Likely Safe"

if __name__ == "__main__":
    # You can change these 2 lines directly
    TARGET = "scanme.nmap.org"
    PORT = 22

    # If you pass args: python vuln.py 127.0.0.1 135 it will use them
    if len(sys.argv) == 3:
        TARGET = sys.argv[1]
        PORT = int(sys.argv[2])

    banner = grab_banner(TARGET, PORT)
    print(f"\n[BANNER] {banner}")
    print(f"[CVE CHECK] {check_cve(banner)}")