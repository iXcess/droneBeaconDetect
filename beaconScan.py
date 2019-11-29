#!/usr/bin/env python

import threading, os, time
from scapy.all import *

# Set is debug = False when monitor mode is needed to be setup
isDebug = False
# Format for macAddrList ["aa:bb:cc:00:11:22","SSID","RSSI","Count","RSSI Deviation","Probability","Channel","Channel Encounter"]
macAddrList = [["aa:bb:cc:00:11:22","SSID","RSSI","Count","RSSI Deviation","Probability","Channel","Channel Encounter"]]
filteredMacList = []
knownVendorList = ["61:60:1f","e0:b6:f5","00:12:1c","00:26:7e","90:03:b7","90:3a:e6","a0:14:3d"]
whiteList = ["b0:be:76"]
foundDroneList = []
channels = []

# To start monitor mode
def startMonMode(iface):
    print '[+] Setting ' + iface + ' into monitor mode'
    try:
        os.system('sudo airmon-ng start ' + iface)
        time.sleep(4)
    except:
	print '[ERROR] Aircrack Suite is not installed, please install by typing sudo apt-get install aircrack-ng'
	exit()

# Channel hopping is needed to be done every 220ms because beacon frames usually is sent every 100ms
# Total of 14 channels defined for use by WiFi 802.11 2.4Ghz ISM Band
# If there are no found beacons, the channel will hop from channel 1 to channel 14
# If a particular beacon is found, it will only focus on that channel until it has made sure they are filtered
def channelHopping(iface):
    while True:
	if len(channels) == 0:
	    for ch in range(1,15):
		os.system('iwconfig %s channel %d' % (iface, ch))
		print "Changed to channel " + str(ch)
		time.sleep(0.220)
	else:
	    for ch in channels:
		os.system('iwconfig %s channel %d' % (iface, ch))
		# Increment the Channel Encounter
		for beacons in macAddrList:
		    if int(beacons[6]) == ch:
			beacons[7] += 1 
		print "Changed to channel " + str(ch)
		time.sleep(0.300)

# Function to execute when a drone has been found
def turnOnCamera():
    print "[+] Camera Turning On"

# Cross check with the vendor specific mac address
def OUICheck(mac):
    if mac[0:8] in knownVendorList:
	return True
    else:
	return False

# Filter beacons based on the probability
def beaconFilter(kp,kd):
    # Clear the channels list
    del channels[:]
    for i, beacons in enumerate(macAddrList):
	# Update the channels list for focused channel hopping
	if beacons[6] not in channels:
	    channels.append(beacons[6])
	# If probability more than the preset probability constant, this means we have found a drone
        if beacons[5] >= kp:
    	    turnOnCamera()
	    foundDroneList.append(beacons[0])
	    macAddrList.pop(i)
	    break
	# Increment probability 0.2 if the average RSSI deviation is higher than detection constant
	if beacons[4]/beacons[3] > kd:
	    beacons[5] += 0.2
	# Filter them out as non-drones if the AP stayed static for a long time/ in white list / has 'unifi' word in it
	if beacons[3] > 100 or beacons[0][0:8] in whiteList or "unifi" in beacons[1]:
            filteredMacList.append(beacons[0])
	    macAddrList.pop(i)
	# If beacon frame is sent too infrequent, suspect might be a mobile phone
	if beacons[7]/beacons[3] > 10:
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
	    # Get channel information based on https://learntomato.flashrouters.com/wp-content/uploads/wifi-frequency-channels.jpg
            channel = int(((packet.ChannelFrequency - 2412) / 5) + 1)
	    if 'drone' in ssid.lower():
		prob += 0.2
	    if len(macAddrList) == 0:
		macAddrList.append([packet.addr2, ssid, packet.dBm_AntSignal,0,0,prob,channel,1])
	    for foundBeacons in macAddrList:
		if packet.addr2 in foundBeacons:
		    # Increament counter
		    foundBeacons[3] += 1
		    # Get RSSI deviation and update RSSI
		    foundBeacons[4] += abs(foundBeacons[2]-packet.dBm_AntSignal)
		    foundBeacons[2] = packet.dBm_AntSignal
		    break
		# If end of for loop and the mac address is not found in macAddrList
		if foundBeacons == macAddrList[-1]:
		    # format[macAddr,SSID,RSSI,Count,RSSIDeviation,Probability]
                    macAddrList.append([packet.addr2, ssid, packet.dBm_AntSignal,0,0,prob,channel,1])

	beaconFilter(0.7,5)
	print "macAddrList: "
	print macAddrList
	print "foundDroneList: "
	print foundDroneList
      # print("Access Point MAC: %s, SSID: %s , RSSI: %s" %(packet.addr2, ssid, packet.dBm_AntSignal))


if __name__ == "__main__":
    interface = "wlan1mon"

    if not isDebug:
	startMonMode(interface[:-3])

    chHopthread = threading.Thread(target=channelHopping, args=(interface, ), name="channelHopping")
    chHopthread.daemon = True
    chHopthread.start()

    sniff(iface=interface, store=False, prn = PacketHandler)
