#!/usr/bin/env python3
import re
import time
import requests
from datetime import datetime

API_KEY = '6fd0110aa6a269afd71f2db2a074e5ca7d99e23a3b2a1d70362e34dc8c4889fb02c3df6463f0aa2f'
LOG_FILE = '/var/log/auth.log'
CHECK_INTERVAL = 1  # Проверка каждую секунду

CATEGORIES = {
    'ssh': (18, 'SSH brute-force attack'),
    'port_scan': (15, 'Port scanning activity'),
    'brute_force': (12, 'Generic brute-force attempt'),
    'hacking': (5, 'General hacking attempt or invalid user'),
    'ddos': (14, 'Frequent connection closures — possible DDoS'),
    'proxy': (21, 'Proxy or relay abuse'),
    'fraud': (10, 'Fraudulent or automated abuse'),
    'spoofing': (20, 'Possible spoofed connection / fake client'),
    'phishing': (6, 'Suspicious phishing behavior'),
    'web_attack': (22, 'Web app attack pattern detected'),
    'fake_search': (19, 'Fake search engine crawler detected')
}

def report_to_abuseipdb(ip, categories, reason):
    cat_string = ','.join(str(c) for c in categories)
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {
        'ip': ip,
        'categories': cat_string,
        'comment': reason
    }

    try:
        response = requests.post(url, headers=headers, data=params)
        if response.status_code == 200:
            print(f"[!] Reported {ip} ({cat_string}): {reason}")
        else:
            print(f"[ERROR] Failed to report {ip}: {response.text}")
    except Exception as e:
        print(f"[ERROR] API Error: {str(e)}")

def parse_log_line(line):
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if not ip_match:
        return
    ip = ip_match.group()
    line_lower = line.lower()

    categories = []
    reason = ''

    if 'failed password' in line_lower:
        categories = [18, 12]
        reason = 'SSH brute-force attack'
    elif 'invalid user' in line_lower:
        categories = [5, 12]
        reason = 'Invalid user — brute-force or recon'
    elif 'did not receive identification string' in line_lower:
        categories = [15, 20]
        reason = 'Port scan or spoofed connection'
    elif 'connection closed' in line_lower or 'connection reset' in line_lower:
        categories = [14]
        reason = 'Frequent disconnects — possible DDoS'
    elif 'proxy' in line_lower and ('unauthorized' in line_lower or 'relay' in line_lower):
        categories = [21]
        reason = 'Proxy or relay abuse'
    elif 'bot' in line_lower and not ('google' in line_lower or 'bing' in line_lower):
        categories = [19]
        reason = 'Fake crawler (bot pretending to be search engine)'
    elif 'sql' in line_lower or 'union select' in line_lower or 'xss' in line_lower:
        categories = [22, 5]
        reason = 'Web application attack detected (SQLi/XSS)'
    elif 'login' in line_lower and ('empty' in line_lower or '""' in line_lower):
        categories = [10, 12]
        reason = 'Suspicious automated login (fraud)'
    elif 'spoof' in line_lower or 'faked' in line_lower:
        categories = [20]
        reason = 'Spoofed agent or origin'

    if categories:
        report_to_abuseipdb(ip, categories, reason)

def tail_log():
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(CHECK_INTERVAL)
                continue
            parse_log_line(line)

if __name__ == '__main__':
    print("[*] Starting ULTIMATE abuse monitor")
    print(f"[*] Monitoring log: {LOG_FILE}")
    try:
        tail_log()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped.")
