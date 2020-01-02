"""
This file is the main function to run the system.
"""
__author__ = 'Ruoyu Li'


from capturer import PacketCapturer
from handler import FlowHandler
import sys
import os


# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
stream_type = sys.argv[1]
source = sys.argv[2]
mode = sys.argv[3]

cap = PacketCapturer(stream_type)
flow_handler = FlowHandler(config='config/config.csv', mode=mode)
if stream_type == 'pcap':
    for device in os.listdir(source):
        if device == '.DS_Store':
            continue
        print('Dealing with device {}'.format(device))
        for action in os.listdir(os.path.join(source, device)):
            if action == '.DS_Store':
                continue
            for f in os.listdir(os.path.join(source, device, action)):
                if f == '.DS_Store':
                    continue
                if f.endswith('.pcap'):
                    cap.capture(os.path.join(source, device,
                                             action, f), flow_handler.parse)
else:
    cap.capture(source, flow_handler.parse)
