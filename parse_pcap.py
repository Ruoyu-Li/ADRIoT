from scapy.all import *
import pandas as pd
import sys
import csv
import os


device_ips = {}
flows = {}
packets_list = []
PACKET_LEN = 500


def rawbyte_callback(packet):
	if IP not in packet:
		return
	if TCP not in packet and UDP not in packet and ICMP not in packet:
		return

	global device_ips
	if packet[IP].src in device_ips: # TODO
		if TCP in packet or UDP in packet:
			trans = 'TCP' if TCP in packet else 'UDP'
			sport, dport = packet.sport, packet.dport
		elif ICMP in packet:
			trans = 'ICMP'
			sport, dport = 0, 0
		else:
			trans = 'NULL'
			sport, dport = 0, 0
		# flow = (packet[IP].src, packet[IP].dst, dport, packet.proto)
		# reverse_flow = (packet[IP].dst, packet[IP].src, sport, packet.proto)

		# protocol filtering
		if trans == 'TCP' or trans == 'UDP':
			# NTP, NetBIOS
			# if packet.sport == 123 or packet.dport == 123 \
			# or packet.sport == 1900 or packet.dport == 1900 \
			# or packet.sport == 137 or packet.dport == 137 \
			# or packet.sport == 138 or packet.dport == 138 \
			# or packet.sport == 139 or packet.dport == 139:
			# 	return
			# payload filter
			if Raw not in packet:
				return

		# only inspect connections initialized by malicious
		# if flow not in flows:
		# 	if reverse_flow in flows:
		# 		flow = reverse_flow
		# 	elif packet[IP].src in device_ips:
		# 			print(f'create new flow: {flow}')
		# 			flows[flow] = []
		# 	else:
		# 		return

		# IP address masking
		packet[IP].src = '0.0.0.0'
		packet[IP].dst = '0.0.0.0'

		# link layer removal
		packet_bytes = packet[IP].build()

		# UDP/ICMP header padding
		if trans == 'UDP' or trans == 'ICMP':
			idx1 = len(packet[IP]) - len(packet[trans])
			if Raw in packet:
				idx2 = len(packet[trans]) - len(packet.load)
			else:
				idx2 = len(packet[trans])	
			packet_bytes = packet_bytes[:idx1 + idx2] + b'\x00' * (20 - idx2) + packet_bytes[idx1 + idx2:]

		# PACKET_LEN bytes truncation and padding PACKET_LEN bytes, and normalization
		packet_bytes = packet_bytes + b'\x00' * (PACKET_LEN - len(packet_bytes)) if len(packet_bytes) < PACKET_LEN else packet_bytes[:PACKET_LEN]
		byte_list = [x / 255.0 for x in list(packet_bytes)]

		# add into flow record
		# flows[flow].append([packet.time] + byte_list)
		packets_list.append(byte_list)


def feature_callback(packet):
	pass


if __name__ == '__main__':
	df = pd.read_csv('device_ips.csv')
	# device_ips = {row['IP']: row['type'] for idx, row in df.iterrows()}
	device_ip = sys.argv[2]
	device_ips[device_ip] = 1
	sniff(offline=sys.argv[1], prn=rawbyte_callback, store=0)
	with open(f"data/{device_ip}.csv", "w") as fout:
		writer = csv.writer(fout)
		for packet in packets_list:
			writer.writerow(packet)

