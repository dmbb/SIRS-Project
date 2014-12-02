#!/usr/bin/env python
import argparse
import sys
import dpkt
import socket
import pyshark


def main():
	#Argument Parsing & Program Info
	parser = argparse.ArgumentParser(prog='correlator')
	parser.add_argument('--version', action='version', version='%(prog)s 1.0')
	parser.add_argument('-f', '--file', nargs=1, required=True, help='Pcap file to analyse')
	args = parser.parse_args()


	#Processing
	storage = processPackets(args)


	while 1:
	    try:
			printPreamble()  
		        c = raw_input()
		        if c == "t":
		            users = set([])
		            for i in storage:
		            	users.add(i[0])
		            for i in users:
		                print "---------------------------------------"
		            	print "Messages sent by " + i
		            	print "---------------------------------------"
		            	print "sourceIP \ttimeStamp"
		            	for j in storage:
		            		if i == j[0]:
		            			print i+"\t", j[2]
		        elif c == "c":
		        	print "c de cenas"
		        elif c == "e":
		        	break
	    except IOError: pass

	#printData(storage)    


def printPreamble():
	print "\nSelect an option:"
	print "t - Check when a user sent a message"
	print "c - Check to whom a user sent messages"
	print "e - Exit program"

#Parses pcap file in order to obtain a list which element contains the tuple srcIP/dstIP/timeStamp
#	Only includes packets with a src/dst in a XMPP port. 
def processPackets(args):
	pcap = open(args.file[0])
	storage = []

	capture = dpkt.pcap.Reader(pcap)
	first = 0
	for timeStamp, packet in capture:
	    if first ==0:
		    first = timeStamp
	    eth = dpkt.ethernet.Ethernet(packet)
	    ip = eth.data
	    tcp = ip.data
	    if tcp.dport == 5222 or tcp.sport ==5222: #Connection filter (disregard non-XMPP data)
		    sourceIP = socket.inet_ntoa(ip.src)
		    dstIP = socket.inet_ntoa(ip.dst)
		    element = [sourceIP, dstIP, timeStamp - first]
		    storage.append(element)
	pcap.close()
	return storage



#Dump of the capture regarding source/destination/timestamp. Only parsing applied (RAW)
def printData(storage):
	print "sourceIP \tdestinationIP \ttimeStamp"
	for i in storage:
		print i[0] + "\t" + i[1] + "\t", i[2]



if __name__ == "__main__":
	main()




#TODO
# Test latency. Check time relation between a message into and out of the server

#ATTACKS
#Implement records of when someone sent a message. 
#	Example: Messages sent by 10:10:10:10 should display a timeStamp
#Implement records of the receiver of the message sent by 10:10:10:10
#	Example: Correlate the time when a user sent a message with the time of when it got to the recipient.
#Implement records of the receivers of a message sent by a user when in a chat room
#	Example: Correlate the time of when a user sent a message with the time of receiving the message by all users in the room

#DONE
#Filter connections to build storage upon connections where XMPP port appears (disregard other traffic data)
#     Check server IP (common) will show up as both sender and receiver from a same IP
# [X] Can be identified by src/dst port = 5222
#Extract timeStamp and SRC/DST from XMPP packets