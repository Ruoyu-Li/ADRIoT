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
device = sys.argv[1]
attack = sys.argv[2]

cap = PacketCapturer('pcap')
for d in os.listdir('../iot-data-processed/us_eval/'):
    if device != 'all' and device != d:
        continue
    with open('config/config_2.csv', 'w') as csv_file:
        writer = csv.writer(csv_file)
        if attack == 'infection':
            writer.writerow(['3c:33:00:98:ee:fd', d])

        else:
            writer.writerow(['00:50:56:be:02:54', d])
    flow_handler = FlowHandler(packet_length=1500, seq_length=10, batch_size=128, epochs=50,
                                       config='config/config_2.csv', mode='E')
    if attack == 'infection':
        cap.capture('../iot-data-processed/attack/infection/001.pcap', flow_handler)
    elif attack == 'http_ddos':
        cap.capture('../iot-data-processed/attack/http_ddos/001.pcap', flow_handler)
    elif attack == 'tcp_ddos':
        cap.capture('../iot-data-processed/attack/tcp_ddos/001.pcap', flow_handler)
    elif attack == 'udp_ddos':
        cap.capture('../iot-data-processed/attack/udp_ddos/001.pcap', flow_handler)
