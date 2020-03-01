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
packet_length = 500
cap = PacketCapturer('pcap')
for d in os.listdir('../iot-data-processed/us_eval_7/'):
    with open('config/config_2.csv', 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['192.168.2.110', d])
    flow_handler = FlowHandler(packet_length=packet_length, config='config/config_2.csv', mode='E')
    # print('Dealing with attack {}'.format(source))
    cap.capture('../malicious/mirai/Mirai_pcap.pcap', flow_handler.parse)
