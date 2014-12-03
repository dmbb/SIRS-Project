#!/usr/bin/env python
import argparse
import sys
import socket
import csv

def main():
	#Argument Parsing & Program Info
	parser = argparse.ArgumentParser(prog='correlator')
	parser.add_argument('--version', action='version', version='%(prog)s 1.1')
	parser.add_argument('-f', '--file', nargs=1, required=True, help='CSV file containing the packet capture.')
	args = parser.parse_args()


	#Parse input file
	storage = processPackets(args)


	while 1:
	    try:
			printPreamble()  
		        c = raw_input()
		        if c == "u":
		        	messages = correlate(storage)
		        	users = set([])
		        	for i in messages:
		        		users.add(i[1])
		        	for i in users:
		        		print "---------------------------------------"
		        		print "Messages sent by " + i
		        		print "---------------------------------------"
		        		print "dstIP \ttimeStamp"
		        		for j in messages:
		        			if i == j[1]:
		        				print j[2]+"\t", j[0]
		        elif c == "t":
		        	messages = correlate(storage)
		        	printCorrelation(messages)
		        elif c == "e":
		        	break
	    except IOError: pass
 



#Parses CSV file in order to obtain a list which element contains the tuple srcIP/dstIP/timeStamp/Info
#	The CSV file comes from wireshark, already filtered.
#	In this stage, we analyse packets with the server as source only. Moreover, retransmission and DUP ACK 
#     packets are discarded. At least one of the ports in the connection is 5222 (XMPP-client port).
# Wireshark filter used: tcp.port eq 5222 and not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and ip.src=="SERVER_IP"
def processPackets(args):
	pcap = open(args.file[0])
	pcap_csv = csv.reader(pcap)
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

#Correlate messages. ACK-PDU Server -> c1,c2 .   Disregards ACK-PDU Server -> c1,c1 as it happens in KeepAlive
def correlate(storage):
	messages = []
	for i, index in enumerate(storage):
		if "[ACK]" in index[3]:
			client1 = index[1]
			if(i+1 < len(storage)):
				prox = storage[i+1]
				if "[TCP segment of a reassembled PDU]" in prox[3]:
					client2 = prox[1]
					timeStamp = prox[2]
					if(client1 != client2):
						clients = [timeStamp, client1, client2]
						messages.append(clients)
	return messages


#Prints the program preamble messages, along with allowed functions.
def printPreamble():
	print "\nSelect an option:"
	print "u - Check messages sent between users - by user"
	print "t - Check messages sent between users - by timeStamp"
	print "e - Exit program"


#Dump of the correlation results, regarding timestamp/source/destination.
def printCorrelation(messages):
	print "-------------------------------------------"
	print "timeStamp \tclient_1 \tclient_2"
	print "-------------------------------------------"
	for i in messages:
		print i[0] + "\t" + i[1] + "\t", i[2]


#Dump of the capture regarding source/destination/timestamp/info. Shows raw parsing results.
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