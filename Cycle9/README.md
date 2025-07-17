# NetFingerprinter

## Overview

NetFingerprinter is a program that will analyze packet capture files and try to extract and summarize source node information, including the operating system of the source node. The program tries to meet the needs of network analysts who would normally have to sort through packet data manually to find relevant information, including window size, TTL, or user agent strings.

This tool was written in Python 3.10.12 and has been tested on Linux.

### V2 Improvements
* Multiprocessing
* Global config file to easily modify the behavior of the application
* Added partial IPv6 support
* Recorded packet timestamps (first seen and last seen)

## Dependencies
* Python 3
* Scapy
* tqdm


## Folder Structure

```
project_root/
├── OSFingerprinter.py
├── NetFingerprinter.py
├── tcp_ports.txt
├── udp_ports.txt
├── mac_vendors.txt
├── config.txt
└── main.py

```
## Logic Flow
```
[RawPcapReader]
     |
     v
[packet_producer] --> [Queue] --> [packet_consumer] x N-1 processors (cores)
                                            |
                                            v
                                  [result_queue -> merged]
```
## To Execute

Run the Python file.

```bash
python3 main.py exampleCapture.pcap
```
Or

Specify a custom config file.
```bash
python3 main.py --config_file sample_config.txt exampleCapture.pcap
```
## Sample Output

```bash
============================================================

Node Information:
---------------------
   Source MAC: b4:fb:e4:xx:xx:xx
   MAC Vendor: Ubiquiti Inc
   Source IP(s): ['192.168.1.1']
   Node first seen: 2005-07-16T15:29:29.800000+00:00
   Node last seen: 2005-07-16T15:29:55.115430+00:00
   Packet Count: 1
   Protocols: UDP
   Active Ports: UDP:53
   Identified Services: DNS

OS Detection Results:
---------------------
   Primary OS: Linux
   Confidence: 20%
   Possible OS: Linux, Unix, MacOS X

Evidence:
---------------------
  - TTL: 64 (range: 64)

  TTL Analysis:
    TTL 64: 1 packets
============================================================

```
## Run Statistics
* Time to analyze 189MB pcap :: 18.23s
* Time to analyze 1.8GB pcap :: 7m3s

## Future Work
* Adding additional fingerprinting techniques and more robust signatures/dictionaries.    
* Ability to export/import report data.
* Logging
