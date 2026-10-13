# cve_db.py - small CVE database
VULN_DB = {
    "Apache/2.4.29": "CVE-2021-41773 - Path Traversal RCE",
    "Apache/2.4.49": "CVE-2021-41773 - Path Traversal RCE",
    "Apache/2.4.50": "CVE-2021-42013 - Path Traversal RCE",
    "nginx/1.18.0": "CVE-2021-23017 - DNS Resolver Off-by-One",
    "OpenSSH_7.2": "CVE-2016-0777 - Information Disclosure",
    "vsftpd 2.3.4": "Backdoor - Malicious backdoor, HIGH RISK",
    "OpenSSH_6.6.1": "CVE-2015-5600 - Brute Force / Privilege Escalation - HIGH"
}

RISKY_HEADERS = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]
