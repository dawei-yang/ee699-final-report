
#!/usr/bin/python

'''@author: Ramon Fontes
   @email: ramon.fontes@imd.ufrn.br'''

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
import subprocess

def topology():
    "Create a network."
    net = Mininet_wifi()

    info("*** Creating nodes\n")
    
    ap1 = net.addAccessPoint('ap1', ssid="simplewifi", channel="1",
                             passwd='123456789a',
                             failMode="standalone", datapath='user',
 			     encrypt='wpa3',
 			     ieee80211w='0',
 			     transition_disable=0x02,
 			     mac='02:00:00:00:00:00'
                             )
                             
    sta1 = net.addStation('sta1', passwd='123456789a',mac='02:00:00:00:01:00')
    sta2 = net.addStation('sta2', passwd='123456789a', mac='02:00:00:00:02:00')
    sta3 = net.addStation('sta3', encrypt='wpa3',mac="02:00:00:00:03:00", config='ssid="simplewifi",psk="123456789a",proto=WPA2,pairwise=CCMP,ieee80211w=0,key_mgmt=SAE')
    victim = net.addStation('victim', passwd='123456789a', mac='02:00:00:00:04:00')
    attacker = net.addStation('attacker', mac='02:00:00:00:05:00')

    
    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Associating Stations\n")
    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(sta3, ap1)
    net.addLink(victim, ap1)
    net.addLink(attacker, ap1)

    info("*** Starting network\n")
    net.build()
    ap1.start([])
    ap1.cmd('ifconfig hwsim0 up')
    attacker.cmd('iw dev attacker-wlan0 interface add mon0 type monitor')
    attacker.cmd('ip link set mon0 up')
    info("*** Running CLI\n")
    CLI(net)
 
    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
