# Parser used to find total events in .json and parse key network event log (ID 3) total

import json

def get_logs(path):
    events = []
    f = open(path, 'r')
    for line in f:
        line = line.strip() 
        if line: # check for empty lines
            events.append(json.loads(line))
    return events

def network_events(events):
    return [e for e in events if e.get('EventID') == 3] # returns None by default

if __name__ == "__main__":
    events = get_logs('/Users/nate/log-parser/sample_logs/mimikatz_alerts.json')
    net_evts = network_events(events)
    print("Total events: " + str(len(events)))
    print("Total Network events (ID 3): " + str(len(net_evts)))
