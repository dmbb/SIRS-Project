#!/usr/bin/env python
import argparse
import sys
import socket
import csv

def main():
	#Argument Parsing & Program Info
	parser = argparse.ArgumentParser(prog='correlator')
	parser.add_argument('--version', action='version', version='%(prog)s 1.1')
	parser.add_argument('-f', '--file', nargs=1, required=True, help='PCSV file to analyse')
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
		        	printData(storage)
		        elif c == "e":
		        	break
	    except IOError: pass

	#printData(storage)    


def printPreamble():
	print "\nSelect an option:"
	print "t - Check traded messages"
	print "c - Check to whom a user sent messages"
	print "e - Exit program"

#Parses csv file in order to obtain a list which element contains the tuple srcIP/dstIP/timeStamp
#	Only includes packets with a src/dst in a XMPP port. 
# wireshark filter: not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and ip.src==192.168.1.3
def processPackets(args):
	pcap = open(args.file[0])
	pcap_csv = csv.reader(pcap)
	next(pcap_csv)
	storage = []

	
	for i in pcap_csv:
			srcIP = i[2]
			dstIP = i[3]
			timeStamp = i[1]
			info = i[6]
			element = [srcIP, dstIP, timeStamp, info]
			storage.append(element)
	pcap.close()
	return storage

#ip.data.flags & dpkt.tcp.TH_FIN
#Dump of the capture regarding source/destination/timestamp. Only parsing applied (RAW)
def printData(storage):
	print "sourceIP \tdestinationIP \ttimeStamp \tInfo"
	for i in storage:
		print i[0] + "\t" + i[1] + "\t", i[2], "\t" + i[3]



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