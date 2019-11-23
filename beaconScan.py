# References : https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html

import threading, os, time, random
from scapy.all import *

F_bssids = []    # Found BSSIDs

# Starting monitor mode on wlan0
def startMonMode():
  os.system('airmon-ng start wlan0')

def channelHopper(iface):
    ch = 1
    while True:
        # Switching channel every 250ms because beacon frames are usually sent at 100ms
        # There is a total of fourteen channels defined for use by Wi-Fi 802.11 for the 2.4 GHz ISM band.
        time.sleep(0.25)
        os.system('iwconfig %s channel %d' % (iface, ch))
        if ch == 14: 
          ch = 1
        else:
          ch += 1

def packetHandler(pkt):
    if pkt.haslayer(Dot11Beacon):
       if pkt.getlayer(Dot11).addr2 not in F_bssids:
           F_bssids.append(pkt.getlayer(Dot11).addr2)
           ssid = pkt.getlayer(Dot11Elt).info
           if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
               print "Hidden Network Detected"
           print "Network Detected: %s" % (ssid)

if __name__ == "__main__":

    interface = "wlan0mon"
    thread = threading.Thread(target=channelHopper, args=(interface, ), name="channelHopper")
    thread.daemon = True
    thread.start()

    startMonMode()
    sniff(iface=interface, prn=packetHandler)