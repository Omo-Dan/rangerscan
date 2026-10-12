import argparse
from urllib.parse import urlparse

RISKY_PORTS = [22, 3389, 3306, 27017, 5432]

def scan_ports(host):
    print(f"\n[+] Scanning {host} for risky ports")
    for port in RISKY_PORTS:
        print(f" [-] Checking port {port}...")

def check_headers(url):
    print(f"\n[+] Checking security headers for {url}")

def main():
    parser = argparse.ArgumentParser(description="RangerScan - Mini Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL or IP")
    args = parser.parse_args()

    host = urlparse(args.target).hostname or args.target
    print(f"RangerScan started for: {args.target}")
    scan_ports(host)
    check_headers(args.target)
    print("\n[Ok] Day 1 scaffold complete")

if __name__ == "__main__":
    main()
