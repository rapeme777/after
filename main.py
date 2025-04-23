#!/usr/bin/env python3
import re
import time
import requests
from datetime import datetime

# API-ключи
ABUSEIPDB_API_KEY = '6fd0110aa6a269afd71f2db2a074e5ca7d99e23a3b2a1d70362e34dc8c4889fb02c3df6463f0aa2f'
THREATFOX_API_KEY = 'a1e11e5c9fbfaf9308efb783edb8147c397917d198c708da'

# Путь к лог-файлу
LOG_FILE = '/var/log/auth.log'
CHECK_INTERVAL = 1  # Проверка каждую секунду

# Категории для AbuseIPDB
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
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {
        'ip': ip,
        'categories': cat_string,
        'comment': reason
    }

    try:
        response = requests.post(url, headers=headers, data=params)
        if response.status_code == 200:
            print(f"[!] Reported to AbuseIPDB {ip} ({cat_string}): {reason}")
        else:
            print(f"[ERROR] AbuseIPDB failed: {response.text}")
    except Exception as e:
        print(f"[ERROR] AbuseIPDB API Error: {str(e)}")

def report_to_threatfox(ip, threat_type='malicious-ip', confidence=80, description='Detected malicious activity'):
    url = 'https://threatfox-api.abuse.ch/api/v1/'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'query': 'submit_ioc',
        'api_key': THREATFOX_API_KEY,
        'ioc': ip,
        'ioc_type': 'ip',
        'threat_type': threat_type,
        'malware': 'unknown',
        'confidence_level': confidence,
        'reference': 'auth.log abuse monitor',
        'comment': description
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200 and 'status' in response.json() and response.json()['status'] == 'success':
            print(f"[+] Reported to ThreatFox: {ip} ({threat_type})")
        else:
            print(f"[ERROR] ThreatFox report failed: {response.text}")
    except Exception as e:
        print(f"[ERROR] ThreatFox API Error: {str(e)}")

def parse_log_line(line):
    ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
    if not ip_match:
        return
    ip = ip_match.group()
    line_lower = line.lower()

    categories = []
    reason = ''
    threat_type = 'malicious-ip'

    if 'failed password' in line_lower:
        categories = [18, 12]
        reason = 'SSH brute-force attack'
        threat_type = 'brute-force'
    elif 'invalid user' in line_lower:
        categories = [5, 12]
        reason = 'Invalid user — brute-force or recon'
        threat_type = 'brute-force'
    elif 'did not receive identification string' in line_lower:
        categories = [15, 20]
        reason = 'Port scan or spoofed connection'
        threat_type = 'port-scan'
    elif 'connection closed' in line_lower or 'connection reset' in line_lower:
        categories = [14]
        reason = 'Frequent disconnects — possible DDoS'
        threat_type = 'dos'
    elif 'proxy' in line_lower and ('unauthorized' in line_lower or 'relay' in line_lower):
        categories = [21]
        reason = 'Proxy or relay abuse'
        threat_type = 'abuse'
    elif 'bot' in line_lower and not ('google' in line_lower or 'bing' in line_lower):
        categories = [19]
        reason = 'Fake crawler (bot pretending to be search engine)'
        threat_type = 'bot'
    elif 'sql' in line_lower or 'union select' in line_lower or 'xss' in line_lower:
        categories = [22, 5]
        reason = 'Web application attack detected (SQLi/XSS)'
        threat_type = 'web-attack'
    elif 'login' in line_lower and ('empty' in line_lower or '""' in line_lower):
        categories = [10, 12]
        reason = 'Suspicious automated login (fraud)'
        threat_type = 'fraud'
    elif 'spoof' in line_lower or 'faked' in line_lower:
        categories = [20]
        reason = 'Spoofed agent or origin'
        threat_type = 'spoofing'

    if categories:
        report_to_abuseipdb(ip, categories, reason)
        report_to_threatfox(ip, threat_type=threat_type, description=reason)

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
