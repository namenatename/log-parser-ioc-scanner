# Report generator to confirm findings of VT API 

import csv

def generate_report(result, choice):
    with open('output/report.csv', 'w') as file:
        writer = csv.writer(file)
        # Loop through each iteration of a new IP and subsequent results and add new CSV line
        if choice == "A":
            writer.writerow(['Type', 'IOC', 'Malicious', 'Suspicious', 'Harmless', 'AbuseIPDB Score','Threat'])
            for ip in result:
                stats = result[ip]
                # Fix flagging condition
                if (stats['malicious'] >= 1 or stats['suspicious'] >= 2) and stats['confidence'] >= 50:
                    verdict = "FLAGGED/HIGH"
                elif (stats['malicious'] >= 1 or stats['suspicious'] >= 1) and stats['confidence'] >= 20:
                    verdict = "SUSPICIOUS"
                elif stats['isTor'] is True:
                    verdict = "SUSPICIOUS (Tor)"
                else:
                    verdict = "CLEAN"
                writer.writerow(['IP', ip, stats['malicious'], stats['suspicious'], stats['harmless'], stats['confidence'], verdict])
        elif choice == "B":
            writer.writerow(['Type', 'IOC', 'Malicious', 'Suspicious', 'Harmless','Result'])
            for file_hash in result:
                stats = result[file_hash]
                if stats['malicious'] >= 1 or stats['suspicious'] >= 2:
                    verdict = "FLAGGED"
                else:
                    verdict = "CLEAN"
                writer.writerow(['HASH', file_hash, stats['malicious'], stats['suspicious'], stats['harmless'], "CLEAN"])

def main_menu():
    print("Log Parser & IOC Scanner Menu")
    print("Select from choices: ")
    print("A) IP Check")
    print("B) Hash Check")
    print("Q) Quit")
    

            






