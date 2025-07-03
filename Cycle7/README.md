# NetFingerprinter

## Overview

Fingerprinter is a program that will analyze packet capture files and try to extract and summarize source node information, including the operating system of the source node. The program tries to meet the needs of network analysts who would normally have to sort through packet data manually to find relevant information, including window size, TTL, or user agent strings.

This tool was written in Python 3.10.12 and has been tested on Linux.

## Dependencies
* Python 3
* Scapy

## Folder Structure

```
project_root/
├── OSFingerprinter.py
├── fingerprint.py
├── tcp_ports.txt
├── udp_ports.txt
└── mac-vendors.txt

```

## To Execute

Simply run the Python file.

```bash
python3 fingerprint.py exampleCapture.pcap
```
## Sample Output

```bash
============================================================

Node Information:
---------------------
   Source MAC: b4:fb:e4:xx:xx:xx
   MAC Vendor: Ubiquiti Inc
   Source IP(s): ['192.168.1.1']

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
* Time to analyze 16MB pcap :: 7.75s
* Time to analyze 1.8GB pcap :: 22m

## Future Work
* Possible multithreading implementation to increase run performance.    
* Adding additional fingerprinting techniques and more robust signatures/dictionaries.    
* Ability to export/import report data.
