#!/usr/bin/env python3

################
### Includes ###
################
import os, sys, argparse, time
from collections import defaultdict
from multiprocessing import Manager, Process, Queue, cpu_count
from scapy.all import RawPcapReader, Ether, IP, TCP, UDP, ICMP
import OSFingerprinter, NetFingerprinter
from tqdm import tqdm

########################
### Global Variables ###
########################

config = {}

#################
###  Methods  ###
#################

#
# Count number of packets in the pcap file.
#
def count_packets(pcap_file):
    count = 0
    for _, _ in RawPcapReader(pcap_file):
        count += 1
    return count

#
# Using tqdm library for progres bar stuff, read the pcap file and add packets
# to the queue.
#
def packet_producer(pcap_file, packet_queue, num_workers, total_packets):
    reader = RawPcapReader(pcap_file)
    for pkt_data, pkt_metadata in tqdm(reader, total=total_packets, desc="Reading PCAP"):

        # Check what attributes are actually available
        #print(f"Available attributes: {dir(pkt_metadata)}")


        # Try different timestamp access methods
        if hasattr(pkt_metadata, 'timestamp'):
            ts = pkt_metadata.timestamp
        elif hasattr(pkt_metadata, 'sec'):
            ts = pkt_metadata.sec + (pkt_metadata.usec if hasattr(pkt_metadata, 'usec') else 0) / 1_000_000
        elif hasattr(pkt_metadata, 'ts_sec'):
            ts = pkt_metadata.ts_sec + (pkt_metadata.ts_usec if hasattr(pkt_metadata, 'ts_usec') else 0) / 1_000_000
        elif hasattr(pkt_metadata, 'tshigh') and hasattr(pkt_metadata, 'tslow'):
            ts_raw = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow

            if ts_raw > 1e18:  # Nanoseconds
                ts = ts_raw / 1_000_000_000

            elif ts_raw > 1e15:  # Microseconds (after year 2001)
                ts =  ts_raw / 1_000_000

            elif ts_raw > 1e12:  # Milliseconds (after year 2001)
                ts =  ts_raw / 1000
            else:
                ts = ts_raw  # Already in seconds
        else:
            ts = 0
        packet_queue.put((pkt_data, ts))
    reader.close()

    # Shutdown worker threads
    for _ in range(num_workers):
        packet_queue.put(None)


#
# Create default dictionary for network node.
#

def make_profile():
    return {
        'mac_vendor': '',
        'ip_addresses': [],
        'ttl_values': [],
        'window_sizes': [],
        'user_agents': [],
        'packet_count': 0,
        'protocols': set(),
        'port_patterns': set(),
        'services': [],
        'timestamps':[],
    }

#
# Takes a packet from the packet queue, then processes it and extracts relevant
# information.
#
def packet_consumer(packet_queue, result_queue):
    os_fp = OSFingerprinter.OSFingerprinter()
    nf = NetFingerprinter.NetFingerprinter()
    profiles = defaultdict(make_profile)

    while True:
        pkt_data = packet_queue.get()
        if pkt_data is None:
            break
        try:
            pkt_data, ts = pkt_data
            pkt = Ether(pkt_data)
            pkt.time = ts
            nf.analyze_packet(pkt, os_fp, profiles)

        except Exception:
            pass

    result_queue.put(profiles)

#
# Reads all of the individual profiles created and merges them into a single dictionary
#
def merge_profiles(profile_list):
    merged = defaultdict(make_profile)

    for profiles in profile_list:
        for mac, data in profiles.items():
            m = merged[mac]
            m['packet_count'] += data['packet_count']
            m['mac_vendor'] = m['mac_vendor'] or data['mac_vendor']
            m['ip_addresses'].extend(ip for ip in data['ip_addresses'] if ip not in m['ip_addresses'])
            m['ttl_values'].extend(data['ttl_values'])
            m['window_sizes'].extend(data['window_sizes'])
            m['user_agents'].extend([ua for ua in data['user_agents'] if ua not in m['user_agents']])
            m['protocols'].update(data['protocols'])
            m['port_patterns'].update(data['port_patterns'])
            m['services'].extend([s for s in data['services'] if s not in m['services']])
            m['timestamps'].extend(time for time in data['timestamps'])
    return merged

#
# Reads in the config file and assigns values to global conf dictionary
#
def import_config(config_file):

    with open("config.txt") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
    # Convert number keys to actual integers
    for key in ['TTL_Weight', 'Window_Size', 'User_Agent']:
        config[key] = int(config[key])
    # Check that the OUI Database file exists
    if not os.path.exists(config["OUI_Database"]):
        print(f"Config File Error: OUI Database for mac vendors file not found.")
        sys.exit(1)
    # Check that the TCP_Ports file exists
    if not os.path.exists(config["TCP_Ports"]):
        print(f"Config File Error: TCP Ports file not found.")
        sys.exit(1)
    # Check that the UDP_Ports file exists
    if not os.path.exists(config["UDP_Ports"]):
        print(f"Config File Error: UDP Ports file not found.")
        sys.exit(1)

#
# Main method
#
def main():
    parser = argparse.ArgumentParser(description="NetFingerprinter with multiprocessing PCAP analysis.")
    parser.add_argument("--config_file", default="config.txt", help="Path to the config file (default: config.txt)")
    parser.add_argument("pcap_file", help="Path to the pcap file to analyze")
    args = parser.parse_args()

    # Error handling for pcap file
    if not os.path.exists(args.pcap_file):
        print(f"Error: File '{args.pcap_file}' not found.")
        sys.exit(1)

    # Make sure capture is in .pcap or .pcapng for Scapy
    if not args.pcap_file.endswith(('.pcap', '.pcapng')):
        print(f"Error: Non supported capture file. Please use a .pcap.")
        sys.exit(1)

    # Error handling for config file
    if not os.path.exists(args.config_file):
        print(f"Error: Config file '{args.config_file}' not found.")
        sys.exit(1)

    # Import config file and assign variables to config dict
    import_config(args.config_file)

    # Counting packets for progress bar
    total_packets = count_packets(args.pcap_file)

    # Calculate number of workers based on cpu count, leaving one core available
    num_workers = max(2, cpu_count() - 1)

    # Create mltiprocessing queue with large maxsize so producers don't have to wait
    packet_queue = Queue(maxsize=10000)

    # Create multiprocessing manager
    manager = Manager()

    # Create shared queue for collecting results from subprocesses
    result_queue = manager.Queue()


    print(f"\nLaunching {num_workers} worker processes...")

    # Create workers list for easy iteration
    workers = []

    # Loop through num of workers calculated and create subprocess consumers
    for _ in range(num_workers):
        p = Process(target=packet_consumer, args=(packet_queue, result_queue))
        p.start()
        workers.append(p)

    print("\nStarting producer with progress bar...")

    # Parallelize the producer so that cosumers don't have to wait
    producer = Process(target=packet_producer, args=(args.pcap_file, packet_queue, num_workers, total_packets))
    producer.start()

    # Loop through workers and block all items in queue until they have been processed
    for p in workers:
        p.join()

    # Create a list to store all of the node profiles from packet_consumers
    all_profiles = []

    # Loop through all the workers and get their profiles, waiting 10s before throwing an error
    for _ in range(num_workers):
        try:
            profiles = result_queue.get(timeout=10)
            all_profiles.append(profiles)
        except Exception as e:
            print(f"Error getting result from queue: {e}")

    # Merge the profile dictionaries into one
    merged = merge_profiles(all_profiles)

    # Initiate OSFingerprinter
    os_fp = OSFingerprinter.OSFingerprinter()

    # Initiate NetFingerprinter
    nf = NetFingerprinter.NetFingerprinter()

    # Assign merged profiles back to NetFingerprinter
    nf.ip_profiles = merged

    # Print analysis for user
    nf.print_os_analysis(nf, os_fp)

if __name__ == "__main__":
    main()
