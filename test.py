"""
This file is the main function to run the system.
"""
__author__ = 'Ruoyu Li'


from capturer import PacketCapturer
from handler import FlowHandler
import sys
import os
import csv


# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
stream_type = sys.argv[1]
source = sys.argv[2]
mode = sys.argv[3]

cap = PacketCapturer(stream_type)
for d in os.listdir('../iot-data-processed/us_eval_7/'):
    with open('config/config_2.csv', 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['192.168.2.110', d])
    flow_handler = FlowHandler(config='config_2.csv', mode=mode)
    print('Dealing with attack {}'.format(source))
    for f in os.listdir(source):
        if f.endswith('.pcap'):
            cap.capture(os.path.join(source, f), flow_handler.parse)
