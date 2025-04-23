#!/usr/bin/env python3
import re
import time
import requests
from datetime import datetime

# Конфигурация
API_KEY = '6fd0110aa6a269afd71f2db2a074e5ca7d99e23a3b2a1d70362e34dc8c4889fb02c3df6463f0aa2f'
LOG_FILE = '/var/log/auth.log'
REPORT_THRESHOLD = 1
CHECK_INTERVAL = 1  # Проверка каждую секунду
SSH_CATEGORY = 18
PORTSCAN_CATEGORY = 15

def report_to_abuseipdb(ip, category, reason):
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {
        'ip': ip,
        'categories': category,
        'comment': reason
    }

    try:
        response = requests.post(url, headers=headers, data=params)
        if response.status_code == 200:
            print(f"[!] Reported {ip} to AbuseIPDB (reason: {reason})")
        else:
            print(f"[ERROR] Failed to report {ip}: {response.text}")
    except Exception as e:
        print(f"[ERROR] API Error: {str(e)}")

def parse_log_line(line):
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if not ip_match:
        return
    ip = ip_match.group()

    # SSH brute-force
    if 'Failed password' in line or 'Invalid user' in line:
        print(f"[!] SSH brute-force attempt from {ip}")
        report_to_abuseipdb(ip, SSH_CATEGORY, 'SSH brute-force detected')

    # Port scan indicators
    elif ('Did not receive identification string' in line or
          'Connection closed by authenticating user' in line or
          'Connection reset by peer' in line):
        print(f"[!] Possible port scan from {ip}")
        report_to_abuseipdb(ip, PORTSCAN_CATEGORY, 'Port scanning activity detected')

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
    print(f"[*] Starting aggressive SSH and port-scan monitor for {LOG_FILE}")
    print(f"[*] Config: check_interval={CHECK_INTERVAL}s (no repeat delay)")
    try:
        tail_log()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped")
