#!/usr/bin/env python

import threading, os, time
from scapy.all import *

isDebug = True
macAddrList = [["aa:bb:cc:00:11:22","SSID","RSSI","Count","RSSI Deviation","Probability"]]
filteredMacList = []
knownVendorList = ["61:60:1f","e0:b6:f5","00:12:1c","00:26:7e","90:03:b7","90:3a:e6","a0:14:3d"]
whiteList = ["b0:be:76"]
 
# Will need to run when debugging on non-raspberrypi
def startMonMode(iface):
    print '[+] Setting ' + iface + ' into monitor mode'
    os.system('sudo airmon-ng start ' + iface)
    time.sleep(2)
    os.system('toor')
    time.sleep(2)

# Channel hopping is needed to be done every 210ms because beacon frames usually is sent every 100ms
# Total of 14 channels defined for use by WiFi 802.11 2.4Ghz ISM Band
def channelHopping(iface):
    ch = 1
    while True:
	time.sleep(0.210)
	os.system('iwconfig %s channel %d' % (iface, ch))
#	print "Changed to channel " + str(ch)
	if ch == 14:
	  ch = 1
	else:
	  ch += 1

def turnOnCamera():

    print "[+] Camera Turning On"

def OUICheck(mac):
    if mac[0:8] in knownVendorList:
	return True
    else:
	return False

def beaconFilter(kp,kd):
    for i, beacons in enumerate(macAddrList):
        if beacons[-1] >= kp:
    	    turnOnCamera()
	    macAddrList.pop(i)
	    break
	if beacons[4]/beacons[3] > kd:
	    beacons[-1] += 0.2
	if beacons[3] > 1000 or beacons[0][0:8] in whiteList or "unifi" in beacons[1]:
            filteredMacList.append(beacons[0])
	    macAddrList.pop(i)
    print "Filtered MAC List: "
    print filteredMacList
    print '\n'

# This function only handles incoming new packets
def PacketHandler(packet):
    # If packet has a beacon frame
    if packet.haslayer(Dot11Beacon):
	prob = 0
        if packet.addr2 not in filteredMacList:
            # Primary Filter, use vendor OUI Mac Address 
            if OUICheck(packet.addr2): prob = 1
	    # Secondary Filter, common drone has underscore and the 'drone' word in SSID
	    ssid = packet.getlayer(Dot11Elt).info
	    if 'drone' in ssid.lower():
		prob += 0.2
	    for foundBeacons in macAddrList:
		if packet.addr2 in foundBeacons:
		    # Increament counter
		    foundBeacons[3] += 1
		    # Get RSSI deviation and update RSSI
		    foundBeacons[4] += abs(foundBeacons[2]-packet.dBm_AntSignal)
		    foundBeacons[2] = packet.dBm_AntSignal
		    break
		if foundBeacons == macAddrList[-1]:
		    # format[macAddr,SSID,RSSI,Count,RSSIDeviation,Probability]
                    macAddrList.append([packet.addr2, ssid, packet.dBm_AntSignal,0,0,prob])

	beaconFilter(0.7,6)
	print "macAddrList: "
	print macAddrList
           # print("Access Point MAC: %s, SSID: %s , RSSI: %s" %(packet.addr2, ssid, packet.dBm_AntSignal))


if __name__ == "__main__":
    interface = "wlan0mon"
    chHopthread = threading.Thread(target=channelHopping, args=(interface, ), name="channelHopping")
    chHopthread.daemon = True
    chHopthread.start()

    if not isDebug:
        startMonMode(interface[:-3])

    sniff(iface=interface, store=False, prn = PacketHandler)
