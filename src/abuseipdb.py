# AbuseIPDB functionality

import os
from dotenv import load_dotenv
import requests

load_dotenv()
api_key = os.getenv('ABUSEIPDB_API_KEY')

def abuse_check(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        ipdb_check = requests.request(method='GET', url=url, headers=headers, params=params)
        ipdb_check.raise_for_status()
        data = ipdb_check.json()
        confidence_score = data.get('data', {}).get('abuseConfidenceScore')
        totalReports = data.get('data', {}).get('totalReports')
        isTor = data.get('data', {}).get('isTor')
        usageType = data.get('data', {}).get('usageType')
        return {
            'confidence': confidence_score,
            'total_reports': totalReports,
            'isTor' : isTor,
            'usageType' : usageType
        }
    except Exception as e:
        print(f'Error checking {ip}: {e}')
        return {
            'confidence': 0,
            'total_reports': 0,
            'isTor' : None,
            'usageType' : None
        }

