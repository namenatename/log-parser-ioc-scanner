# VirusTotal API IP lookup and parsing data for malicious factoring

import os
from dotenv import load_dotenv
import requests
from parser import get_logs, network_events
from extractor import extract_ioc
import time

load_dotenv()
api_key = os.getenv('VT_API_KEY')

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    # Make request to VT for IP check and parse data for use
    vt_check = requests.get(url, headers=headers)
    data = vt_check.json()
    malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
    sus = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious')
    harmless = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless')
    return {"malicious": malicious, 
            "suspicious": sus, 
            "harmless": harmless
    }

if __name__ == "__main__":
    events = get_logs('sample_logs/sample_alerts.json')
    net_evts = network_events(events)
    ip_list = extract_ioc(net_evts)
    for i in ip_list:
        result = check_ip(i)
        print(f"IP: {i} ")
        print(f"\tMalicious: {result['malicious']}")
        print(f"\tSuspicious: {result['suspicious']}")
        print(f"\tHarmless: {result['harmless']}")
        # Account for free API key cooldown, removable for paid versionsw
        time.sleep(15)
    


