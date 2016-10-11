#!/usr/bin/env python2.7

import sys
import pyshark
import traceback
from collections import deque

## read in packets from specified .pcap file
##
## write flow statistics (flow,  start time, bytes sent) to specified output
##
## flows are defined by 4-tuple of (src_ip, dst_ip, src_port, dst_port)
##
## flows end when time since last packet in flow was observed exceeds
## specified threshold

class flow_info: 
	"""class for storing flow time and size information """
	
	def __init__(self, s_time, size): 
		self.start_time = s_time
		self.last_packet_time = s_time
		self.size = int(size)

class extraction_parameters: 
	"""class for storing extraction parameters (threshold and files)"""
	def __init__(self, threshold, output_file, input_files):
		self.threshold = threshold
		self.output_file = output_file
		self.input_files = input_files

def main(argv): 
	## validate command line arguments
	if (len(argv) ==1 ):
		params = parseParameterFile(argv[0])
	else: 
		params = parseCommandLineArguments(argv)
	
	threshold = params.threshold
	output_file = params.output_file
	input_files = params.input_files

	## map of flow 4-tuple to list of flow statistics
	## we need a list of flow statistics because multiple flows can 
	## be associated with the same 4-tuple, and we are writing
	## flows to the output file in chronological order from their inception
	flows = dict() 

	## queue of flows 4-tuples, so we know the oldest flow that we haven't
	## yet written to the output file
	flow_queue = deque()
	i = 0 
	
	try: 
		with open(output_file, 'w+') as output:
			output.write('source_ip, destination_ip, source_port, destination_port, start_time, duration, flow_size\n')
			for input_file in input_files: 
				try: 
					cap = pyshark.FileCapture(input_file)
					for packet in cap:
						i += 1
						if (i % 50000 == 0):
							print("Processing packet {}".format(i))
						parseFlow(packet, flows, flow_queue, threshold, output)
					cap.close()
				except: 
					print('Error opening input .pcap file ' + input_file)
					pass
			
			## after having read all packets from .pcap file, print 
			## any flows remaining in hashmap to output file	
			printRemaining(flows, flow_queue, output)
	except:
		print('Error opening output file')
		traceback.print_exc() 
		sys.exit()
			

def parseParameterFile(parameter_filepath):
	"""get extraction parameters from parameter file"""
	try:
		with open(parameter_filepath, 'r') as params_file:
			lines = params_file.readlines()
			lines = [entry.rstrip("\n") for entry in lines]
			try: 
				threshold = float(lines[0])
			except:
				print('Error: first line in parameters file (threshold) must be a number')
				sys.exit()
			output_file = lines[1]
			input_files = lines[2:]
			params = extraction_parameters(threshold, output_file, input_files)
			return params
	except:
		print('Error opening parameters file')
		traceback.print_exc() 
		sys.exit()

def parseCommandLineArguments(argv): 
	"""get extraction parameters from command line arguments"""
	validate(argv)
	argv_length = len(argv)
	threshold = float(argv[0])
	output_file = argv[1]
	## input_files is a list of the .pcap files comprising a datacenter trace
	## the files must be listed in command line in chronological order
	input_files = argv[2:]
	params = extraction_parameters(threshold, output_file, input_files)
	return params

def parseFlow(packet, flows, flow_queue, threshold, output): 
	"""process packet from .pcap file"""
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
			prev_time = flow_stats.last_packet_time
			delta = time - prev_time
			if (delta.total_seconds() >= threshold):
				## if threshold exceeded, old flow ended, begin new flow
				flows[key].append(flow_stats)
				flows[key].append(flow_info(time, int(size)))
				flow_queue.append(key)
			else:
				## otherwise part of same flow, add size to existing flow
				flow_stats.last_packet_time = time
				flow_stats.size = flow_stats.size + int(size)
				flows[key].append(flow_stats)
		else:
			## add a new flow to map
			flows[key] = deque()
			flows[key].append(flow_info(time, int(size)))
			flow_queue.append(key)

		## check if flows can be written to output
		while(True):
			oldest_flow = flow_queue.popleft()
			oldest_flow_stats = flows[oldest_flow].popleft()
			prev_time = oldest_flow_stats.last_packet_time
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

def printRemaining(flows, flow_queue, output):
	"""write stats for remaining flows in queue to file"""
	while (len(flow_queue) > 0):
		oldest_flow = flow_queue.popleft()
		oldest_flow_stats = flows[oldest_flow].popleft()
		writeFlowToOutput(oldest_flow, oldest_flow_stats, output)
		if (len(flows[oldest_flow]) == 0):
			del flows[oldest_flow]

def writeFlowToOutput(flow, flow_stats, output):
	"""write a flow and its stats to output file"""
	flow_tokens = flow.split(':')
	duration = (flow_stats.last_packet_time - flow_stats.start_time).total_seconds()
	line = '{}, {}, {}, {}, {}, {}, {}\n'.format(flow_tokens[0], 
		flow_tokens[1], flow_tokens[2], flow_tokens[3], 
		str(flow_stats.start_time), str(duration), flow_stats.size)
	try: 
		output.write(line)
	except:
		print "Error writing to output"
		pass

def validate(argv): 
	"""validate command line arguments"""
	if (len(argv) < 3):
		print('Error: incorrect number of arguments')
		usage() 
		sys.exit()
	try:
		float(argv[0])
	except ValueError:
		print('Error: first argument (time threshold) must be a number')
		usage()
		sys.exit()

def usage():
	"""print usage"""
	print('Usage 1: python pyflowcap <time_threshold> <output_path> <pcap_path_1> ... <pcap_path_n>')
	print('Usage 2: python pyflowcap <parameter_file>')

if __name__ == '__main__':
	main(sys.argv[1:])