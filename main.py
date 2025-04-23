#!/usr/bin/env python3
import re
import time
import requests
from datetime import datetime, timedelta

# Конфигурация
API_KEY = '6fd0110aa6a269afd71f2db2a074e5ca7d99e23a3b2a1d70362e34dc8c4889fb02c3df6463f0aa2f'
LOG_FILE = '/var/log/auth.log'
REPORT_THRESHOLD = 1  # 1 попытка = сразу репорт
CHECK_INTERVAL = 5    # 5 секунд между проверками
ABUSE_CATEGORY = 18   # SSH атаки
REPEAT_REPORT_DELAY = timedelta(minutes=15)  # Интервал между репортами одного IP

ip_last_reported = {}

def report_to_abuseipdb(ip, attempts):
    now = datetime.now()
    last_report = ip_last_reported.get(ip)

    if last_report and now - last_report < REPEAT_REPORT_DELAY:
        print(f"[-] Skipping report for {ip}, last reported {now - last_report} ago")
        return

    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {
        'ip': ip,
        'categories': ABUSE_CATEGORY,
        'comment': f'SSH brute-force detected: {attempts} failed attempts'
    }

    try:
        response = requests.post(url, headers=headers, data=params)
        if response.status_code == 200:
            ip_last_reported[ip] = now
            print(f"[!] Reported {ip} to AbuseIPDB (attempts: {attempts})")
        else:
            print(f"[ERROR] Failed to report {ip}: {response.text}")
    except Exception as e:
        print(f"[ERROR] API Error: {str(e)}")

def parse_log_line(line):
    if 'Failed password' in line or 'Invalid user' in line:
        ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
        if ip_match:
            ip = ip_match.group()
            print(f"[!] Failed login attempt from {ip}")
            report_to_abuseipdb(ip, 1)

def tail_log():
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)  # Переходим в конец файла
        while True:
            line = f.readline()
            if not line:
                time.sleep(CHECK_INTERVAL)  # Ждем 5 секунд
                continue
            parse_log_line(line)

if __name__ == '__main__':
    print(f"[*] Starting aggressive SSH brute-force monitor for {LOG_FILE}")
    print(f"[*] Config: threshold={REPORT_THRESHOLD}, check_interval={CHECK_INTERVAL}s, repeat_delay={REPEAT_REPORT_DELAY}")
    try:
        tail_log()
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped")
