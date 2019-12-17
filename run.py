"""
This file is the main function to run the system.
"""
__author__ = 'Ruoyu Li'


from capturer import PacketCapturer
from handler import FlowHandler
import sys
import os


# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
stream = sys.argv[1]
source = sys.argv[2]

cap = PacketCapturer(stream)
flow_handler = FlowHandler(config='config.csv')
for f in os.listdir(source):
	if f.endswith('.pcap'):
		print('Deal with {}'.format(f))
		cap.capture(os.path.join(source, f), flow_handler.parse)
