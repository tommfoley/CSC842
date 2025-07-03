#!/usr/bin/env python3
"""
PCAP OS Detection and Profiling
Analyzes network traffic to detect and profile operating systems of source IPs.
"""
################
### Includes ###
################

import sys, argparse
from collections import defaultdict, Counter


try:
    from scapy.all import rdpcap, PcapReader, Ether, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("Error: scapy library not found. Install it with: pip install scapy")
    sys.exit(1)

try:
    import OSFingerprinter
except ImportError:
    print("Error: OSFingerprinter class not found.")
    sys.exit(1)

#
# Analyze pcap file for OS fingerprinting of source IPs.
#

def analyze_pcap_for_os(pcap_file):

    # Initiate OSFingerprinter
    fingerprinter = OSFingerprinter.OSFingerprinter()

    # Data structure for analysis
    ip_profiles = defaultdict(lambda: {
        'mac_vendor': '',
        'ip_addresses': [],
        'ttl_values': [],
        'window_sizes': [],
        'user_agents': [],
        'packet_count': 0,
        'protocols': set(),
        'port_patterns': set(),
        'services': [],
        'first_seen': None,
        'last_seen': None
    })

    # Use PcapReader to read the pcap
    with PcapReader(pcap_file) as pcap:
        for packet in pcap:

            if Ether in packet:
                src_mac = packet[Ether].src
                profile = ip_profiles[src_mac]

                # If mac_vendor for the source node has already been looked up, skip looking up again
                if profile['mac_vendor'] == '':

                    # Perform MAC vendor lookup using local database in OSFingerprinter library
                    mac_vendor = fingerprinter.get_vendor_local(src_mac)

                    # Uncomment line below to perform MAC vendor lookup through macvendors.com
                    #mac_vendor = fingerprinter.get_vendor_MACVendors(src_mac)

                    profile['mac_vendor'] = mac_vendor

            # Analyze the IP info keeping count of how many packets are seen.
            if IP in packet:
                if packet[IP].src not in profile['ip_addresses']:
                    src_ip = packet[IP].src
                    profile['ip_addresses'].append(src_ip)

                profile['packet_count'] += 1


                # TCP analysis
                if TCP in packet:
                    profile['protocols'].add('TCP')
                    src_port = packet[TCP].sport
                    profile['port_patterns'].add(f"TCP:{src_port}")

                    # Query fingerprinter to get the service name associated with the port.
                    service = fingerprinter.get_service_name(src_port,'TCP')
                    if service != "" and service not in profile['services']:
                        profile['services'].append(service)

                    # Collect TTL and window size
                    profile['ttl_values'].append(packet[IP].ttl)
                    profile['window_sizes'].append(packet[TCP].window)

                    # HTTP User-Agent analysis
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        ua_info = fingerprinter.analyze_http_user_agent(packet)
                        if ua_info and ua_info not in profile['user_agents']:
                            profile['user_agents'].append(ua_info)

                # UDP Analysis
                elif UDP in packet:
                    profile['protocols'].add('UDP')
                    src_port = packet[UDP].sport
                    profile['port_patterns'].add(f"UDP:{src_port}")
                    service = fingerprinter.get_service_name(src_port,'UDP')
                    if service != "" and service not in profile['services']:
                        profile['services'].append(service)

                    profile['ttl_values'].append(packet[IP].ttl)

                # ICMP Analysis
                elif ICMP in packet:
                    profile['protocols'].add('ICMP')
                    profile['ttl_values'].append(packet[IP].ttl)

    return ip_profiles, fingerprinter

#
# Generates OS profile based on collected information.
#

def generate_os_profile(ip_data, fingerprinter):
    profile = {
        'confidence': 0,
        'primary_os': 'Unknown',
        'possible_os': [],
        'evidence': []
    }

    os_votes = Counter()

    # Analyze TTL patterns
    if ip_data['ttl_values']:

        # Look through the TTL data to find the most common value.
        most_common_ttl = Counter(ip_data['ttl_values']).most_common(1)[0][0]

        # Using fingerprinter, try and extrapolate the actual TTL value
        ttl_range = fingerprinter.get_ttl_range(most_common_ttl)
        if ttl_range in fingerprinter.ttl_signatures:
            possible_os = fingerprinter.ttl_signatures[ttl_range]
            for os in possible_os:
                os_votes[os] += 2
            profile['evidence'].append(f"TTL: {most_common_ttl} (range: {ttl_range})")

    # Analyze window sizes
    if ip_data['window_sizes']:

        # Look through the window size data to find the most common value.
        most_common_window = Counter(ip_data['window_sizes']).most_common(1)[0][0]

        # Using fingerprinter, try and associate the window size with an OS.
        if most_common_window in fingerprinter.tcp_window_signatures:
            possible_os = fingerprinter.tcp_window_signatures[most_common_window]
            for os in possible_os:
                os_votes[os] += 3
            profile['evidence'].append(f"TCP Window: {most_common_window}")

    # Analyze User-Agent strings
    if ip_data['user_agents']:
        for ua_info in ip_data['user_agents']:
            if ua_info['detected_os'] != 'Unknown':
                os_votes[ua_info['detected_os']] += 5
                if not (ua_info['detected_os']) in profile['evidence']:
                    profile['evidence'].append(f"User-Agent: {ua_info['detected_os']}")

    # Determine most likely OS, calculating a confidence level out of 100
    if os_votes:
        # Find the most likely OS
        most_likely = os_votes.most_common()
        # Set Primary OS to the most voted for
        profile['primary_os'] = most_likely[0][0]
        # Calculate confidence level out of 100
        profile['confidence'] = min(most_likely[0][1] * 10, 100)
        # Add the top 3 possible os results to a list
        profile['possible_os'] = [os for os, votes in most_likely[:3]]

    return profile

#
# Print our analysis for the user
#
def print_os_analysis(ip_profiles, fingerprinter):
    print("\n" + "="*80)
    print("OS Detection and Profiling Results")
    print("="*80)

    # Sort IPs by packet count, highest to lowest
    sorted_ips = sorted(ip_profiles.items(), key=lambda x: x[1]['packet_count'], reverse=True)

    for src_mac, data in sorted_ips:

        #Print the node information
        print(f"\n{'='*60}")
        print(f"\nNode Information:")
        print("-" * 21)
        print(f"   Source MAC: {src_mac}")
        print(f"   MAC Vendor: {data['mac_vendor']}")
        print(f"   Source IP(s): {data['ip_addresses']}")


        # Generate OS profile
        os_profile = generate_os_profile(data, fingerprinter)

        #Print protocol summary information
        print(f"\n   Packet Count: {data['packet_count']}")
        print(f"   Protocols: {', '.join(data['protocols'])}")
        print(f"   Active Ports: {', '.join(list(data['port_patterns'])[:10])}")
        print(f"   Identified Services: {', '.join(list(data['services'])[:10])}")

        # Print OS Detection Results
        print(f"\nOS Detection Results:")
        print("-" * 21)
        print(f"   Primary OS: {os_profile['primary_os']}")
        print(f"   Confidence: {os_profile['confidence']}%")

        if os_profile['possible_os']:
            print(f"   Possible OS: {', '.join(os_profile['possible_os'])}")

        if os_profile['evidence']:
            print(f"\nEvidence:")
            print("-" * 21)
            for evidence in os_profile['evidence']:
                print(f"  - {evidence}")

        # Additional technical details
        if data['ttl_values']:
            ttl_stats = Counter(data['ttl_values'])
            print(f"\n  TTL Analysis:")
            for ttl, count in ttl_stats.most_common(3):
                print(f"    TTL {ttl}: {count} packets")

        if data['window_sizes']:
            window_stats = Counter(data['window_sizes'])
            print(f"  TCP Window Sizes:")
            for window, count in window_stats.most_common(3):
                print(f"    {window}: {count} packets")

        if data['user_agents']:
            print(f"User Agents Found: {len(data['user_agents'])}")
            for ua_info in data['user_agents'][:2]:  # Show first 2
                print(f"  {ua_info['detected_os']}: {ua_info['user_agent'][:60]}...")
        print(f"{'='*60}")


#
# Main
#
def main():

    # argparse stuff; more for future use
    parser = argparse.ArgumentParser(
        description="Detect and profile operating systems from network traffic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python NetFingerprinter.py capture.pcap
        """
    )

    parser.add_argument("pcap_file", help="Path to the pcap file to analyze")

    args = parser.parse_args()

    # Check if file exists
    import os
    if not os.path.exists(args.pcap_file):
        print(f"Error: File '{args.pcap_file}' not found.")
        sys.exit(1)

    print(f"\nAnalyzing pcap file for OS detection: {args.pcap_file}")

    # Analyze pcap
    result = analyze_pcap_for_os(args.pcap_file)
    if result is None:
        sys.exit(1)

    ip_profiles, fingerprinter = result

    # Print results
    print_os_analysis(ip_profiles, fingerprinter)

if __name__ == "__main__":
    main()
