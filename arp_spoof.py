#! /usr/bin/python
# coding: utf-8
import sys
import fcntl, socket, struct
import getpass
import os
import threading
import signal
from time import sleep

from scapy.all import *

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


# ARP Hardware Type
ETHERNET = 0x01

# ARP Operation Code
ARP_REQUEST		= 0x1
ARP_REPLY		= 0x2
RARP_REQUEST 	= 0x3
RARP_REPLY		= 0x4


ERROR = 1



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


# sniffing ARP Packet
def sniffARP():
	result = sniff(filter="arp", count=5)
	print result[0]

	return result


# get remote mac address by making thread
def get_remote_mac_address( sender_ip ):
	
	# create ARP Packet
	packet = ARP(op=ARP_REQUEST, psrc="192.168.52.2", pdst=sender_ip)

	# send 6 packets to get mac address
	for _ in range(10):
		send(packet)


	

if __name__ == "__main__":
	
	# Print options
	for argv in sys.argv:
		if argv == "-h":
			print "[*] Help page\n"
			print "=" * 10 + " OPTION " + "=" * 10
			print "\n\t-h : view help"
			print "\t-a : get all mac address in LAN"
			print "\n" + "=" * (11 * 2 + len("OPTION"))
			print "\nUsage : arp_spoof.py <interface> <sender ip> <target ip>\n"
		
			sys.exit(0)


	# Check argc
	if len(sys.argv) < 4:
		print "[*] arp_spoof.py <interface> <sender ip> <target ip>"
	
		sys.exit(ERROR);


	# check whether username is 'root' or not.
	if isRoot() == 1:
		# username is not 'root'
		print "[-] You must be system root"
		
		sys.exit(ERROR)


	# set network interface 
	interface = sys.argv[1]

	# set sender, target ip
	sender_ip = sys.argv[2]
	target_ip = sys.argv[3]


	# get mac address from network interface
	try:
		my_mac_address = get_mac_address(interface)
		print "[*] Network Interfae : {0}".format(interface)
		print "[*] Mac Address : {0}".format(my_mac_address)

	except IOError as e:
		# if this code execute,
		# user input invalid value

		print "[-] Your network interface is invalid"

	
	# create threads to get remote mac address
	t1 = threading.Thread(target=get_remote_mac_address, args=(sender_ip,))
	t2 = threading.Thread(target=sniffARP)

	print "\n\n"
	print "#"*5 + " get mac address of SENDER " + "#"*5
	print "\n"
	t1.start()
	t2.start()



	# print result.summary()
	print "done"




