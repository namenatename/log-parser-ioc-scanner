# Extractor for IOC data from parser

# Import all functions from parser
from parser import get_logs, network_events

def extract_ioc(events):
    # Set for storing unique IPs
    ip_list = set()
    for line in events:
        if line.get('SourceIp') is not None:
            source_ip = line.get('SourceIp')
            ip_list.add(source_ip)
        if line.get('DestinationIp') is not None:
            dest_ip = line.get('DestinationIp')
            ip_list.add(dest_ip)
    return ip_list


if __name__ == "__main__":
    events = get_logs('sample_logs/sample_alerts.json')
    net_evts = network_events(events)
    ip_list = extract_ioc(net_evts)
    print('IP LIST:', ip_list)
