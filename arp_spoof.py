#! /usr/bin/python
# coding: utf-8
import sys
import fcntl, socket, struct
import getpass
import os
import threading
import signal

from scapy.all import *
from scpay.base_classes import Gen, Set Gen
import scapy.plist as plist
from scapy.utils import *	# PcapReader
from scapy.data import *	# MTU, ETH_P_ARP

"""
made by ch4n3
to connect to me, send email to chaneyoon[at]gmail[dot]com
blog : http://chaneyoon.tistory.com/
wargame : http://ch4n3.dothome.co.kr/

"""

"""
### assignment
arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]

"""

def get_mac_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
	return ':'.join(['%02x' % ord(char) for char in info[18:24]])


# function to check user name
def isRoot():
	username = getpass.getuser()
	
	if username == "root":
		return 0
	else:
		return 1


if __name__ == "__main__":
	
	# check argc
	if len(sys.argv) < 4:
		print "[*] arp_spoof <interface> <sender ip> <target ip>"
		sys.exit(1);
		
	# set network interface 
	interface = sys.argv[1]

	# get mac address from network interface
	try:
		my_mac_address = get_mac_address(interface)

		print "[*] Mac Address : {0}".format(my_mac_address)
	except IOError as e:
		# if this code execute,
		# user input invalid value

		print "[-] Your network interface is invalid"

	if isRoot() == 1:
		# username is not 'root'
		print "[-] You must be system root"
		sys.exit(1)


	




