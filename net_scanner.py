#!/usr/bin/env python

import scapy.all as scapy #


# function to take in an ip address and use it with broadcast MAC address to send out an ARP request to determine MAC of
# requested IP.
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_bcast = broadcast/arp_request
    answered, unanswered = scapy.srp(arp_req_bcast, timeout=2)
    print(answered.summary())
    print("\n")
    print(unanswered.summary())


# function calls
scan("10.0.2.1/24")
