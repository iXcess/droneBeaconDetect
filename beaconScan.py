#!/usr/bin/env python

import threading, os, time
from scapy.all import *

##########      USER INPUT VARIABLES    #############
pcapFilename = 'droneAlert.pcap'
isDebug = True                  # Set isDebug = False when monitor mode is needed to be setup
interface = 'wlan1mon'
kp = 0.7                         # Probability Threshold Constant
kd = 3.5                         # Detection Threshold Constant
MB_ch = 2			 # MeshBulb Operating Channel

# Format for macAddrList ["aa:bb:cc:00:11:22","SSID","RSSI","Count","RSSI Deviation","Probability","Channel","Channel Encounter"]
macAddrList = []
filteredMacList = []
knownVendorList = ["60:60:1f","e0:b6:f5","00:12:1c","00:26:7e","90:03:b7","90:3a:e6","a0:14:3d"]
whiteList = ["b0:be:76"]
foundDroneList = []
channels = []
isPacketAvail = False
isChannelHopping = True
availLocalizer = []

# To start monitor mode
def startMonMode(iface):
    print '[+] Setting ' + iface + ' into monitor mode'
    try:
        os.system('sudo airmon-ng start ' + iface)
        time.sleep(4)
    except:
	print '[ERROR] Aircrack Suite is not installed, please install by typing sudo apt-get install aircrack-ng'
	exit()

def detectDrone(iface):
    global isPacketAvail

    sendp(pkt[0], iface=iface)
    while isPacketAvail:
 	time.sleep(1)

# Channel hopping is needed to be done every 220ms because beacon frames usually is sent every 100ms
# Total of 14 channels defined for use by WiFi 802.11 2.4Ghz ISM Band
# If there are no found beacons, the channel will hop from channel 1 to channel 14
# If a particular beacon is found, it will only focus on that channel until it has made sure they are filtered
def channelHopping(iface):
    global isPacketAvail
    global isChannelHopping
    while isChannelHopping:
	if len(channels) == 0:
	    for ch in range(1,15):
		os.system('iwconfig %s channel %d' % (iface, ch))
		print "Changed to channel " + str(ch)
		time.sleep(0.220)
	else:
	    for ch in channels:
		os.system('iwconfig %s channel %d' % (iface, ch))
		if ch == MB_ch and isPacketAvail:
		    detectDrone(iface)
		# Increment the Channel Encounter
		for beacons in macAddrList:
		    if int(beacons[6]) == ch:
			beacons[7] += 1 
		print "Changed to channel " + str(ch)
		time.sleep(0.300)

# Function to execute when a drone has been found
# Because ESP sometimes can only either detect SSID or MAC Addr, so we have to send both information
def announceDroneDetected(ssid, mac, detected_ch):
    print "[+] Drone Detected"
    global isPacketAvail
    pkt[0].load = "\x7f\x18\xfe4\x9a\xab\x9f\x15\xdd\x11\x18\xfe4\x04\x01" + str(mac) + ":" + str(detected_ch) + ":" + ssid + ":" +"\x00\x00\x00\x00\x00\x00\x85"
    isPacketAvail = True
    print "SSID: "+ ssid + "\nMAC: " + mac + "\nChannel: " + str(detected_ch) + "\n"

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

    # Adding this to speed up the channel change to MB_ch to broadcast the existence of a drone
    if isPacketAvail:
	channels.append(MB_ch)

    for i, beacons in enumerate(macAddrList):
	# Update the channels list for focused channel hopping
	if beacons[6] not in channels:
	    channels.append(beacons[6])
	# If probability more than the preset probability constant, this means we have found a drone, then send mac addr and channel info to ESPNOW
        if beacons[5] >= kp:
    	    announceDroneDetected(beacons[1],beacons[0],beacons[6])
	    if beacons[0] not in foundDroneList:
	    	foundDroneList.append(beacons[0])
	    macAddrList.pop(i)
	    break
	# Increment probability 0.2 if the average RSSI deviation is higher than detection constant
	if float(beacons[4]/beacons[3]) > kd:
	    beacons[5] += 0.2
	    beacons[3] = 1
	    beacons[4] = 0
	# Filter them out as non-drones if the AP stayed static for a long time/ in white list / has 'unifi' word in it
	if beacons[3] > 50 or beacons[0][0:8] in whiteList or "unifi" in beacons[1]:
            filteredMacList.append(beacons[0])
	    macAddrList.pop(i)
	# If beacon frame is sent too infrequent, suspect might be a mobile phone
	if beacons[7]/beacons[3] > 10:
	    macAddrList.pop(i)

#    print "Filtered MAC List: "
#    print filteredMacList
#    print '\n'

# This function only handles incoming new packets
def PacketHandler(packet):
    global isPacketAvail
    # If it is data from ESP NOW
    if packet.subtype == 13 and packet.addr2 and isPacketAvail:
	payload = str(packet.load).split(':')
	if len(payload) == 5 or len(payload) == 6:
	    global isPacketAvail
	    # payload[-3] is the x_coord and payload[-4] is the y_coord
	    currentCoords = [payload[-3],payload[-4]]
	    currentRSSI = payload[-2]
	    if currentCoords not in availLocalizer:
	        availLocalizer.append(currentCoords)
	    if currentRSSI == "0":
	        availLocalizer.remove(currentCoords)
	    if len(availLocalizer) == 0:
		isPacketAvail = False

	    print "x_coord: " + payload[-3] + " y_coord: " + payload[-4] + " RSSI: " + currentRSSI

    # If packet has a beacon frame
    elif packet.haslayer(Dot11Beacon):
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

	beaconFilter(kp,kd)
#	print "macAddrList: "
#	print macAddrList
#	print "foundDroneList: "
#	print foundDroneList


if __name__ == "__main__":

    pkt = rdpcap(pcapFilename)

    if not isDebug:
	startMonMode(interface[:-3])

    chHopthread = threading.Thread(target=channelHopping, args=(interface, ), name="channelHopping")
    chHopthread.daemon = True
    chHopthread.start()

    sniff(iface=interface, store=False, prn = PacketHandler)
