import socket
import argparse
from datetime import datetime
import threading
from queue import Queue

open_ports = []
print_lock = threading.Lock()

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            with print_lock:
                print(f"[+] Port {port}: OPEN - {service}")
            open_ports.append(port)
        sock.close()
    except:
        pass

def scan_ports(target, ports, threads=50):
    print(f"\n[*] Scanning {target} with {threads} threads...")
    print(f"[*] Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    q = Queue()
    for port in ports:
        q.put(port)
    
    def worker():
        while not q.empty():
            port = q.get()
            scan_port(target, port)
            q.task_done()
    
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    q.join()
    
    print(f"\n[*] Scan complete. Found {len(open_ports)} open ports: {sorted(open_ports)}")
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="RangerScan - Lightweight Python Security Scanner")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("-p", "--ports", default="1-100", help="Ports: 21,22,80 or range 1-1000")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    
    args = parser.parse_args()
    
    # Parse ports - support both 21,22 and 1-1000
    ports = []
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end+1)
    else:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    
    scan_ports(args.target, ports, args.threads)

if __name__ == "__main__":
    main()