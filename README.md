# RangerScan - Mini Vulnerability Scanner

> Lightweight scanner that checks for the 3 most common misconfigurations in small web apps

### Why this exists
Most small apps get breached the same way: open DB port, missing security headers, or basic SQLi. Existing tools are heavy. This is fast and readable.

### How to run
```bash
pip install -r requirements.txt
python scanner.py --target https://example.com
