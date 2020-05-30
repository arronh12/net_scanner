#!/usr/bin/env python

import scapy.all as scapy


# function to take in an ip address and use it with broadcast MAC address to send out an ARP request to determine MAC of
# requested IP.
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_bcast = broadcast/arp_request
    answered = scapy.srp(arp_req_bcast, timeout=2, verbose=False)[0]

    clients_list = []

    for e in answered:
        client_dict = {"ip": e[1].psrc, "mac": e[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


# function to take scan result to format and print for user.
def print_result(results_list):
    print("\n---------------------------------------------------------")
    print("IP Address\t\t\tMAC Address\n---------------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t\t" + client["mac"])


# function calls
scan_result = scan("10.0.2.1/24")
print_result(scan_result)

