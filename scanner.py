import socket
import argparse
from datetime import datetime

def scan_ports(target, ports):
    print(f"\n[*] Scanning {target}...")
    print(f"[*] Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                print(f"[+] Port {port}: OPEN - {service}")
                open_ports.append(port)
            else:
                print(f"[-] Port {port}: closed")
            
            sock.close()
        except Exception as e:
            print(f"[!] Error scanning port {port}: {e}")
    
    print(f"\n[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="RangerScan - Lightweight Python Security Scanner")
    parser.add_argument("target", help="Target IP or domain (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="21,22,80,443,3306,8080", help="Comma separated ports")
    
    args = parser.parse_args()
    
    ports = [int(p.strip()) for p in args.ports.split(",")]
    scan_ports(args.target, ports)

if __name__ == "__main__":
    main()