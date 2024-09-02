TOOLS = {
    "nmap": {"cmd": "nmap", "args": ["-T4", "-F"], "output": "nmap.txt"},
    "Nuclei": {
        "cmd": "nuclei",
        "args": ["-t", "cves", "-o", "nuclei.txt", "-u"],
        "output": "nuclei.txt",
    },
    "ZAP": {
        "cmd": "zap.sh",
        "args": ["-cmd", "-quickout", "zap.txt"],
        "output": "zap.txt",
    },
    "sslscan": {"cmd": "sslscan", "args": ["--no-failed"], "output": "sslscan.txt"},
    "dnsrecon": {"cmd": "dnsrecon", "args": ["-d"], "output": "dnsrecon.txt"},
}

NUCLEI_TEMPLATES = {
    "cve": ["-t", "cves"],
    "common_web_vulnerabilities": ["-t", "common-web-vulnerabilities"],
    "default-credentials": ["-t", "default-credentials"],
    "exposed-panels": ["-t", "exposed-panels"],
    "exposures": ["-t", "exposures"],
    "file-upload": ["-t", "file-upload"],
    "misconfiguration": ["-t", "misconfiguration"],
    "path-traversal": ["-t", "path-traversal"],
    "subdomain-takeover": ["-t", "subdomain-takeover"],
    "vulnerability": ["-t", "vulnerabilities"],
}

SEVERITY_LEVELS = {
    "critical": ["remote code execution", "sql injection"],
    "high": ["xss", "broken auth"],
    "medium": ["info disclosure", "csrf"],
    "low": ["clickjacking", "ssl issues"],
}