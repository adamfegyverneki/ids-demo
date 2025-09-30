import time
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP
from collections import defaultdict

# configuration
INTERFACE = "enp4s0"  # network interface (e.g., wlan0, eth0)
LOG_FILE = "network_logs.csv"
REPORT_IMAGE = "traffic_report.png"
PORT_THRESHOLD = 10  # unique ports for scan alert
TIME_WINDOW = 60  # seconds to sniff packets
PACKET_THRESHOLD = 50  # packets for high traffic alert

# data storage
logs = []
port_counts = defaultdict(set)  # ports per source ip
packet_counts = defaultdict(int)  # packet counts per source ip

def packet_callback(packet):
    # process packets and check for threats
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        port = packet[TCP].dport
        timestamp = time.time()

        # log packet info
        logs.append({
            'timestamp': timestamp,
            'src_ip': src,
            'dst_ip': dst,
            'dst_port': port,
            'flags': packet[TCP].flags
        })

        # track ports and packets
        port_counts[src].add(port)
        packet_counts[src] += 1

        # check for port scanning
        if len(port_counts[src]) > PORT_THRESHOLD:
            print(f"ALERT: possible port scan from {src} ({len(port_counts[src])} ports)")
        
        # check for high packet volume
        if packet_counts[src] > PACKET_THRESHOLD:
            print(f"ALERT: high packet volume from {src} ({packet_counts[src]} packets)")

def save_logs():
    # save logs to csv
    if logs:
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
        df.to_csv(LOG_FILE, index=False)
        print(f"logs saved to {LOG_FILE}")
        return df
    else:
        print("no logs to save.")
        return None

def generate_report(df):
    """create packet source chart."""
    if df is not None:
        plt.figure(figsize=(10, 6))
        df.groupby('src_ip').size().plot(kind='bar')
        plt.title('packets by source ip')
        plt.xlabel('source ip')
        plt.ylabel('packet count')
        plt.tight_layout()
        plt.savefig(REPORT_IMAGE)
        plt.close()
        print(f"report saved as {REPORT_IMAGE}")

def main():
    # run the ids
    print(f"starting ids on interface {INTERFACE} for {TIME_WINDOW} seconds...")
    try:
        # sniff packets
        sniff(iface=INTERFACE, prn=packet_callback, timeout=TIME_WINDOW)
    except PermissionError:
        print("error: need sudo for packet sniffing.")
        return
    except Exception as e:
        print(f"error during sniffing: {e}")
        return

    # save logs and make report
    df = save_logs()
    generate_report(df)
    print("ids stopped.")

if __name__ == "__main__":
    main()
