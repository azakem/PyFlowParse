#!/usr/bin/env python2.7

import sys
import pyshark
import traceback
from collections import deque

## read in packets from specified .pcap file
##
## write flow statistics (start time, bytes sent) to specified output
##
## flows are defined by 4-tuple of (src_ip, dst_ip, src_port, dst_port)
##
## flows end when time since last packet in flow was observed exceeds
## specified threshold

def main(argv): 
	## validate command line  arguments
	validate(argv)
	try:
		cap = pyshark.FileCapture(argv[0])
	except:
		print('Error opening input .pcap file')
		sys.exit()

	## map of flow 4-tuple to list of flow statistics
	## we need a list of flow statistics because multiple flows can 
	## be associated with the same 4-tuple, and we are writing
	## flows to the output file in chronological order from their inception
	flows = dict() 

	## queue of flows 4-tuples, so we know the oldest flow that we haven't
	## yet written to the output file
	flow_queue = deque()
	threshold = argv[2]

	i = 0 
	try: 
		with open(argv[1], 'w+') as output:
			for packet in cap:
				i += 1
				if (i % 50000 == 0):
					print("Processing packet {}".format(i))
				parseFlow(packet, flows, flow_queue, threshold, output)
			
			## after having read all packets from .pcap file, print 
			## any flows remaining in hashmap to output file	
			printRemaining(flows, flow_queue, output)
	except:
		print('Error opening output file')
		traceback.print_exc() 
		cap.close()
		sys.exit()
			
## process packet from .pcap file
def parseFlow(packet, flows, flow_queue, threshold, output): 
	try:
		source_ip = packet.ip.src
		dest_ip = packet.ip.dst
		source_port = packet.tcp.srcport
		dest_port = packet.tcp.dstport
		time = packet.sniff_time
		size = packet.length
		key = source_ip + ":" + dest_ip + ":" + source_port + ":" + dest_port

		if (key in flows): 
			## if key is already in flows map, check if it has expired
			flow_stats = flows[key].pop()
			prev_time = flow_stats[1]
			delta = time - prev_time
			if (delta.total_seconds() >= threshold):
				## if threshold exceeded, old flow ended, begin new flow
				flows[key].append(flow_stats)
				flows[key].append((time, time, int(size)))
				flow_queue.append(key)
			else:
				## otherwise part of of same flow, add size to existing flow
				s_time = flow_stats[0]
				f_size = flow_stats[2] + int(size)
				flows[key].append((s_time, time, f_size))
		else:
			## add a new flow to map
			flows[key] = deque()
			flows[key].append((time, time, int(size)))
			flow_queue.append(key)

		## check if flows can be written to output
		while(True):
			oldest_flow = flow_queue.popleft()
			oldest_flow_stats = flows[oldest_flow].popleft()
			prev_time = oldest_flow_stats[1]
			delta = time - prev_time
			if (delta.total_seconds() >= threshold):
				# oldest flow is finished
				writeFlowToOutput(oldest_flow, oldest_flow_stats, output)
				if (len(flows[oldest_flow]) == 0):
					del flows[oldest_flow]
			else:
				flow_queue.appendleft(oldest_flow)
				flows[oldest_flow].appendleft(oldest_flow_stats)
				break
	except AttributeError:
		pass

## write stats for remaining flows in queue to file
def printRemaining(flows, flow_queue, output):
	while (len(flow_queue) > 0):
		oldest_flow = flow_queue.popleft()
		oldest_flow_stats = flows[oldest_flow].popleft()
		writeFlowToOutput(oldest_flow, oldest_flow_stats, output)
		if (len(flows[oldest_flow]) == 0):
			del flows[oldest_flow]

## write a flow and its stats to output file
def writeFlowToOutput(flow, flow_stats, output):
	flow_tokens = flow.split(':')
	line = '{}, {}, {}, {}, {}, {}\n'.format(flow_tokens[0], 
		flow_tokens[1], flow_tokens[2], flow_tokens[3], 
		str(flow_stats[0]), flow_stats[2])
	try: 
		output.write(line)
	except:
		print "Error writing to output"
		pass

## validate command line arguments
def validate(argv): 
	if (len(argv) != 3):
		print('Error: incorrect number of arguments')
		usage() 
		sys.exit()
	try:
		float(argv[2])
	except ValueError:
		print('Error: third argument (time threshold) must be a number')
		usage()
		sys.exit()

## print usage
def usage():
	print('Usage: python pyflowcap <pcap_path> <output_path> <time_threshold>')

if __name__ == '__main__':
	main(sys.argv[1:])