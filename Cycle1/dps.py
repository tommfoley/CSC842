################
### Includes ###
################

from scapy.all import sniff, Ether
from scapy.contrib.lldp import *
from scapy.contrib.cdp import *
import sys
import ipaddress

#################
### Functions ###
#################

#Accepts lldp packet from scapy and processes it for the user.
def process_lldp_packet(packet):

    print("\n=== LLDP Packet Received ===")

    # Extract Ethernet details
    eth = packet[Ether]
    print(f"Source MAC: {eth.src}")
    print(f"Destination MAC: {eth.dst}")

    # Extract LLDP details
    lldp = packet[LLDPDU]
    systemName = str(lldp.system_name)
    print(f"System Name: ", systemName[2:-1])
    systemDescription = str(lldp.description)
    print(f"System Description: ", systemDescription[2:-1])
    try:
        mgmtIP = lldp.management_address.hex()
        ip_int = int(mgmtIP, 16)
        ip_address = ipaddress.IPv4Address(ip_int)
        print(f"Management Address: ", ip_address)
    except Exception as e:
        print(f"No management address found")
    print(f"----Capabilities----")
    tel = int(lldp.telephone_available)
    print(f"    Telephone: Yes" if tel == 1 else "    Telephone: No")
    router = int(lldp.router_available)
    print(f"    Router: Yes" if router == 1 else "    Router: No")
    wap = int(lldp.wlan_access_point_available)
    print(f"    WLAN AP: Yes" if wap == 1 else "    WLAN AP: No")
    macBridge = int(lldp.mac_bridge_available)
    print(f"    MAC Bridge: Yes" if macBridge == 1 else "    MAC Bridge: No")
    repeater = int(lldp.repeater_available)
    print(f"    Repeater: Yes" if repeater == 1 else "    Repeater: No")
    docsis = int(lldp.docsis_cable_device_available)
    print(f"    DOCSIS Cable Device: Yes" if tel == 1 else "    DOCSIS Cable Device: No")

    print("=== End of LLDP Packet ===")

#Accepts CDP packet from scapy and processes it for the user.
def process_cdp_packet(packet):
    print("\n=== CDP Packet Received ===")

    # Extract Ethernet details
    print(f"Source: {packet.src}")
    print(f"Destination MAC: {packet.dst}")

    # Extract CDP details
    print (f"IP Address: {packet['CDPAddrRecordIPv4'].addr}")
    print (f"Device ID: {packet['CDPMsgDeviceID'].val.decode('utf-8')}")
    print (f"Capabilities: {packet['CDPMsgCapabilities'].cap}")
    print (f"Native VLAN: {packet['CDPMsgNativeVLAN'].vlan}")
    print (f"Platform: {packet['CDPMsgPlatform'].val.decode('utf-8')}")
    print (f"Platform: {packet['CDPMsgVTPMgmtDomain'].val.decode('utf-8')}")
    print (f"IP Address: {packet['CDPMsgPortID'].iface.decode('utf-8')}")
    duplex = int(packet['CDPMsgDuplex'].duplex)
    print(f"Duplex: Full" if duplex == 1 else "Duplex: No")
    try:
        mgmtIP6 = packet['CDPAddrRecordIPv6'].addr
        print(f"IPv6 Address: ", mgmtIP6)
    except Exception as e:
        print(f"IPv6 Address: None")

    print("=== End of CDP Packet ===")

#Displays menu options from options list
def display_menu(options):
    print("\nMenu:")
    for i, option in enumerate(options):
        print(f"{i + 1}. {option}")
    print("0. Exit")

#Gets user choice
def get_choice(options):
    while True:
        try:
            choice = int(input("Enter your choice: "))
            if 0 <= choice <= len(options):
                return choice
            else:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

####################
### Main Program ###
####################
def main():
    # Options list
    options = ["LLDP Capture", "CDP Capture"]

    while True:
        display_menu(options)
        choice = get_choice(options)

        # If user wants to exit
        if choice == 0:
            print("Exiting...")
            break

        # If user wants to process lldp packet(s)
        elif choice == 1:
            print("Executing Option 1...")
            """Capture LLDP packets on the specified interface."""
            interface = input("Enter the network interface (e.g., eth0, en0): ") or "eth0"
            numPackets = int(input("Enter the number of packets you would like to capture: ") or "1")
            print(f"Starting LLDP packet capture on {interface}... (Press Ctrl+C to stop)")
            try:
                # Sniff LLDP packets (Ether type 0x88cc)
                sniff(iface=interface, filter="ether proto 0x88cc", prn=process_lldp_packet, count=numPackets)
            except PermissionError:
                print("Error: Packet capturing requires root/admin privileges. Run with sudo.")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nStopped capturing packets.")
            except Exception as e:
                print(f"An error occurred: {e}")
                sys.exit(1)
        # If user wants to process cdp packet(s)
        elif choice == 2:
            print("Executing Option 2...")
            # Add code for option 2 here
            """Capture CDP packets on the specified interface."""
            interface = input("Enter the network interface (e.g., eth0, en0): ") or "eth0"
            numPackets = int(input("Enter the number of packets you would like to capture: ") or "1")
            print(f"Starting CDP packet capture on {interface}... (Press Ctrl+C to stop)")
            try:
                # Sniff CDP packets (Ether type 0x2000)
                sniff(iface=interface, filter="ether dst 01:00:0c:cc:cc:cc", prn=process_cdp_packet, count=numPackets)
            except PermissionError:
                print("Error: Packet capturing requires root/admin privileges. Run with sudo.")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nStopped capturing packets.")
            except Exception as e:
                print(f"An error occurred: {e}")
                sys.exit(1)


if __name__ == "__main__":
    main()
