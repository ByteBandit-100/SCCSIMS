import scapy.all as scapy

INTERFACE = "\\Device\\NPF_{D248DB56-09B4-4DF1-A3B6-CE7CBDA36CE9}"

def scan_network_arp(network="10.124.206.6/24"):

    arp = scapy.ARP(pdst=network)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = scapy.srp(
        packet,
        timeout=2,
        retry=1,
        verbose=0,
        iface=INTERFACE
    )[0]

    devices = []

    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices