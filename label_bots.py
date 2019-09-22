from scapy.all import *
import pandas as pd
import os
import sys


malicious_ips = {}
packets_buff = {}
mode = None


def callback_func(packet):
	if IP not in packet:
		return
	global malicious_ips
	global packets_buff
	global mode
	if packet[IP].src in malicious_ips:
		ip = packet[IP].src
	elif packet[IP].dst in malicious_ips:
		ip = packet[IP].dst
	else:
		return
	if ip not in packets_buff:
		packets_buff[ip] = []
	packets_buff[ip].append(packet)
	if len(packets_buff[ip]) == 1000:
		if not os.path.exists(f"{mode}/{malicious_ips[ip]}"):
			os.mkdir(f"{mode}/{malicious_ips[ip]}")
		if not os.path.exists(f"{mode}/{malicious_ips[ip]}/{ip}.pcap"):
			f = open(f"{mode}/{malicious_ips[ip]}/{ip}.pcap", 'w')
			f.close()
		wrpcap(f"{mode}/{malicious_ips[ip]}/{ip}.pcap", packets_buff[ip], append=True)
		del packets_buff[ip][:]


if __name__ == '__main__':
	df = pd.read_csv('device_ips.csv')
	malicious_ips = {row['IP']: row['type'] for idx, row in df.iterrows()}
	if sys.argv[2] == 'train':
		mode = 'ISCX_train'
	elif sys.argv[2] == 'test':
		mode = 'ISCX_test'
	sniff(offline=sys.argv[1], prn=callback_func, store=0)
	for ip in packets_buff:
		if len(packets_buff[ip]) > 0:
			wrpcap(f"{mode}/{malicious_ips[ip]}/{ip}.pcap", packets_buff[ip], append=True)
