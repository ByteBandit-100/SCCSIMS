import scapy.all as scapy

INTERFACE = None
def scan_network_arp(network="192.168.1.0/24"):

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