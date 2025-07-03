#!/usr/bin/env python3
"""
Class that provides various passive fingerprinting techniques to detect node details
and operating system.
"""

################
### Includes ###
################
import ast, re, requests, urllib.parse

try:
    from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, Raw
except ImportError:
    print("Error: scapy library not found. Install it with: pip install scapy")
    sys.exit(1)


#################
###   Class   ###
#################
class OSFingerprinter:
    def __init__(self):

        ####################
        ### Dictionaries ###
        ####################

        # TCP Initial Window Size signatures
        self.tcp_window_signatures = {
            65535: ["Windows (older versions)", "Some Linux"],
            8192: ["Windows Vista/7/8/10", "Windows Server 2008+"],
            5840: ["Linux 2.4/2.6", "Android"],
            5792: ["FreeBSD", "OpenBSD"],
            4128: ["Cisco IOS"],
            512: ["Some embedded systems"],
            1024: ["Some embedded systems"],
            2048: ["Some Unix variants"],
            4096: ["MacOS X (older)", "Some Unix"],
            16384: ["Windows XP", "Some Linux distributions"],
            32768: ["Some Linux distributions"],
            29200: ["Linux (recent kernels)"],
            14600: ["Linux (recent kernels)"]
        }

        # TTL signatures
        self.ttl_signatures = {
            64: ["Linux", "Unix", "MacOS X", "FreeBSD", "OpenBSD"],
            128: ["Windows"],
            255: ["Cisco", "Solaris", "AIX"],
            60: ["MacOS (older versions)"],
            32: ["Windows (older versions)"],
            30: ["Some Unix variants"]
        }

        # User-Agent patterns (if HTTP traffic is present)
        self.user_agent_patterns = {
            r'Windows NT 10\.0': 'Windows 10',
            r'Windows NT 6\.3': 'Windows 8.1',
            r'Windows NT 6\.2': 'Windows 8',
            r'Windows NT 6\.1': 'Windows 7',
            r'Windows NT 6\.0': 'Windows Vista',
            r'Windows NT 5\.1': 'Windows XP',
            r'Mac OS X': 'MacOS X',
            r'Linux.*Android': 'Android',
            r'Linux': 'Linux',
            r'iPhone': 'iOS (iPhone)',
            r'iPad': 'iOS (iPad)',
            r'FreeBSD': 'FreeBSD',
            r'OpenBSD': 'OpenBSD'
        }

        # OUI Database Patterns; loaded from text file
        with open('mac-vendors.txt') as f:
            vendor_data = f.read()
        self.oui_database = ast.literal_eval(vendor_data)

        # Common well-known ports
        with open('tcp_ports.txt') as f:
            tcp_port_data = f.read()
        self.tcp_ports = ast.literal_eval(tcp_port_data)

        with open('udp_ports.txt') as f:
            udp_port_data = f.read()
        self.udp_ports = ast.literal_eval(udp_port_data)


    #################
    ###  Methods  ###
    #################

    #
    # Analyzes Window size, & TTL to generate signature
    #
    def analyze_tcp_signature(self, packet):
        """Analyze TCP packet for OS fingerprinting."""
        if not TCP in packet:
            return {}

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        signature = {}

        # Window size
        window_size = tcp_layer.window
        if window_size in self.tcp_window_signatures:
            signature['window_size'] = {
                'value': window_size,
                'possible_os': self.tcp_window_signatures[window_size]
            }

        # TTL analysis
        ttl = ip_layer.ttl
        # Group TTL values by common ranges
        ttl_range = self.get_ttl_range(ttl)
        if ttl_range in self.ttl_signatures:
            signature['ttl'] = {
                'value': ttl,
                'range': ttl_range,
                'possible_os': self.ttl_signatures[ttl_range]
            }

        return signature

    #
    # Given a specific ttl value, will try and guess the default TTL value.
    #
    def get_ttl_range(self, ttl):
        """Map TTL to common ranges."""
        if ttl <= 32:
            return 32
        elif ttl <= 64:
            return 64
        elif ttl <= 128:
            return 128
        else:
            return 255


    #
    # Extract and analyze HTTP User-Agent strings.
    #
    def analyze_http_user_agent(self, packet):
        if not Raw in packet:
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Look for User-Agent header
            ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
            if ua_match:
                user_agent = ua_match.group(1)

                # Match against known patterns
                for pattern, os_name in self.user_agent_patterns.items():
                    if re.search(pattern, user_agent, re.IGNORECASE):
                        return {
                            'user_agent': user_agent,
                            'detected_os': os_name
                        }

                return {'user_agent': user_agent, 'detected_os': 'Unknown'}
        except:
            pass

        return None

    #
    # Get vendor information from MAC address OUI (first 3 octets).
    #
    def get_vendor_local(self, mac_address):
        try:
            temp_oui = mac_address[:8].upper()
            if temp_oui in self.oui_database:
                return self.oui_database[temp_oui]
            else:
                return "Not Found"

        except:
            pass
        return None

    #
    # Get vendor information from MACVendors.com.
    #
    def get_vendor_MACVendors(self, mac_address):

        url = "https://api.macvendors.com/" + urllib.parse.quote(mac_address)

        try:
            response = requests.get(url)
            if response.status_code == 200 and response.text:
                print("Vendor:", response.text)
            else:
                print("Not Found")
        except requests.RequestException as e:
            # Print verbose error due to internet lookup
            print("Error:", e)

    #
    # Get service name based on port info.
    #
    def get_service_name(self, port, protocol):
        try:
            # Match against known TCP ports
            if protocol.upper() == "TCP":
                if port in self.tcp_ports:
                    return self.tcp_ports[port]
                else:
                    return ""

            # Match against known UDP ports
            elif protocol.upper() == "UDP":
                if port in self.udp_ports:
                    return self.udp_ports[port]
                else:
                    return ""

        except:
            pass

        return ""
