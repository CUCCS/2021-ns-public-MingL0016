#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.109"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=10)
if ret is None:
    print("Filtered")
elif ret.haslayer(TCP):
    if ret[1].flags == 0x12:
    	send_rst=sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="R"),timeout=10)
        print("Open")
    elif ret[1].flags == 0x14:
        print("Closed")
elif ret.haslayer(ICMP):
	if int(ret.getlayer(ICMP).type)==3 and int(ret.getlayer(ICMP).code) in [1,2,3,9,10,13]:
		print("Filtered")
