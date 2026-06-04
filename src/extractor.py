# Extractor for IOC data from parser

# Import all functions from parser
from parser import get_logs, network_events

# Function to remove redundant API calls by checking for most common private IP addresses
def is_private(ip):
    if ip.startswith('10.') or ip.startswith('172.16') or ip.startswith('192.168.') or ip.startswith('fe80'):
        return True
    else:
        return False

def extract_ioc(events):
    # Set for storing unique IPs
    ip_list = set()
    for line in events:
        if line.get('SourceIp') is not None:
            source_ip = line.get('SourceIp')
            priv_check = is_private(source_ip)
            if priv_check == False:
                ip_list.add(source_ip)
        if line.get('DestinationIp') is not None:
            dest_ip = line.get('DestinationIp')
            priv_check = is_private(dest_ip)
            if priv_check == False:
                ip_list.add(dest_ip)
    return ip_list


if __name__ == "__main__":
    events = get_logs('sample_logs/sample_alerts.json')
    net_evts = network_events(events)
    ip_list = extract_ioc(net_evts)
    print('IP LIST:', ip_list)
