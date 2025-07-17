#!/usr/bin/env python3
"""
Class that provides various packet analysis methods and support methods for main.
"""
################
### Includes ###
################

from datetime import datetime, timezone

try:
    from scapy.all import *
except ImportError:
    print("Error: scapy library not found. Install it with: pip install scapy")
    sys.exit(1)

#################
###   Class   ###
#################
class NetFingerprinter:
    pass

    #################
    ###  Methods  ###
    #################

    #
    # Analyze packet and extract Ether, IP, or IPv6 data.
    #

    def analyze_packet(self, pkt, os_fp, profiles):
        src_mac = pkt[Ether].src
        profile = profiles[src_mac]
        if not profile['mac_vendor']:
            profile['mac_vendor'] = os_fp.get_vendor_local(src_mac)

        profile['timestamps'].append(pkt.time)
        if IPv6 in pkt:
            src_ip = pkt[IPv6].src
            if src_ip not in profile['ip_addresses']:
                profile['ip_addresses'].append(src_ip)
            profile['packet_count'] += 1

            if TCP in pkt:
                profile['protocols'].add('TCP')
                profile['port_patterns'].add(f"TCP:{pkt[TCP].sport}")

                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    ua_info = os_fp.analyze_http_user_agent(pkt)
                    if ua_info and ua_info not in profile['user_agents']:
                        profile['user_agents'].append(ua_info)

                service = os_fp.get_service_name(pkt[TCP].sport, 'TCP')
                if service and service not in profile['services']:
                    profile['services'].append(service)

            elif UDP in pkt:
                profile['protocols'].add('UDP')
                profile['port_patterns'].add(f"UDP:{pkt[UDP].sport}")

                service = os_fp.get_service_name(pkt[UDP].sport, 'UDP')
                if service and service not in profile['services']:
                    profile['services'].append(service)

            elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
                profile['protocols'].add('ICMPv6')

        if IP in pkt:
            src_ip = pkt[IP].src
            if src_ip not in profile['ip_addresses']:
                profile['ip_addresses'].append(src_ip)
            profile['packet_count'] += 1

            if TCP in pkt:
                profile['protocols'].add('TCP')
                profile['ttl_values'].append(pkt[IP].ttl)
                profile['window_sizes'].append(pkt[TCP].window)
                profile['port_patterns'].add(f"TCP:{pkt[TCP].sport}")

                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    ua_info = os_fp.analyze_http_user_agent(pkt)
                    if ua_info and ua_info not in profile['user_agents']:
                        profile['user_agents'].append(ua_info)

                service = os_fp.get_service_name(pkt[TCP].sport, 'TCP')
                if service and service not in profile['services']:
                    profile['services'].append(service)

            elif UDP in pkt:
                profile['protocols'].add('UDP')
                profile['ttl_values'].append(pkt[IP].ttl)
                profile['port_patterns'].add(f"UDP:{pkt[UDP].sport}")

                service = os_fp.get_service_name(pkt[UDP].sport, 'UDP')
                if service and service not in profile['services']:
                    profile['services'].append(service)

            elif ICMP in pkt:
                profile['protocols'].add('ICMP')
                profile['ttl_values'].append(pkt[IP].ttl)


    #
    # Generates OS profile based on collected information.
    #

    def generate_os_profile(self, ip_data, fingerprinter):
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
    def print_os_analysis(self, ip_profiles, fingerprinter):
        print("\n" + "="*80)
        print("OS Detection and Profiling Results")
        print("="*80)

        # Sort IPs by packet count, highest to lowest
        sorted_ips = sorted(ip_profiles.ip_profiles.items(), key=lambda x: x[1]['packet_count'], reverse=True)

        for src_mac, data in sorted_ips:

            #Print the node information
            print(f"\n{'='*60}")
            print(f"\nNode Information:")
            print("-" * 21)
            print(f"   Source MAC: {src_mac}")
            print(f"   MAC Vendor: {data['mac_vendor']}")
            print(f"   Source IP(s): {data['ip_addresses']}")
            #data['timestamps'].sort
            first_seen = datetime.fromtimestamp(data['timestamps'][0], tz=timezone.utc)
            last_seen = datetime.fromtimestamp(data['timestamps'][-1], tz=timezone.utc)
            print(f"   Node first seen: " + first_seen.isoformat())
            print(f"   Node last seen: " + last_seen.isoformat())


            # Generate OS profile
            os_profile = self.generate_os_profile(data, fingerprinter)

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
