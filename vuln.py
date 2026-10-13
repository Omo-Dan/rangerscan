import socket
import sys
from cve_db import VULN_DB

# Try import requests, fallback if not installed
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def grab_banner(ip, port):
    try:
        print(f"[*] Connecting to {ip}:{port}...")
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return f"Error: {e}"

def check_web_headers(ip, port):
    if not HAS_REQUESTS:
        return "Install requests: pip install requests"

    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"

    try:
        print(f"[*] Checking web headers for {url}...")
        r = requests.get(url, timeout=5, verify=False)
        headers = r.headers

        print(f"\n[WEB SERVER] {headers.get('Server', 'Unknown')}")

        # Security header checks
        missing = []
        if "X-Frame-Options" not in headers:
            missing.append("Missing X-Frame-Options (Clickjacking risk)")
        if "Content-Security-Policy" not in headers:
            missing.append("Missing CSP (XSS risk)")
        if "Strict-Transport-Security" not in headers and port == 443:
            missing.append("Missing HSTS (HTTPS downgrade risk)")

        if missing:
            print("[HEADER CHECK] VULNERABLE:")
            for m in missing:
                print(f" - {m}")
            return " | ".join(missing)
        else:
            print("[HEADER CHECK] Secure headers present")
            return "Secure"

    except Exception as e:
        return f"Web Error: {e}"

def check_cve(banner):
    for version, cve in VULN_DB.items():
        if version.lower() in banner.lower():
            return cve
    return "No known CVE - Likely Safe"

if __name__ == "__main__":
    TARGET = "scanme.nmap.org"
    PORT = 22

    if len(sys.argv) == 3:
        TARGET = sys.argv[1]
        PORT = int(sys.argv[2])

    # If web port, do web check + banner
    if PORT in [80, 443, 8080, 8000]:
        result = check_web_headers(TARGET, PORT)
        print(f"\n[RESULT] {result}")
    else:
        banner = grab_banner(TARGET, PORT)
        print(f"\n[BANNER] {banner}")
        print(f"[CVE CHECK] {check_cve(banner)}")