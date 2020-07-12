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
dev_name = [
    'appletv',
    'google-home-mini',
    'nest-tstat',
    't-wemo-plug',
    'tplink-bulb',
    'tplink-plug',
    'zmodo-doorbell',
    'echoplus'
]
attacks = [
    'infection',
    'tcp',
    'udp',
    'http',
    'scan',
    'os',
    'data',
    'keylogging'
]
seq_length = 10
config = 'config/config_{}.csv'.format(seq_length)

cap = PacketCapturer('pcap')
for d in dev_name:
    eval_path = os.path.join('evaluation_{}'.format(seq_length), d + '_test.csv')
    # eval_path = os.path.join('evaluation', d + '.csv')
    with open(config, 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['3c:33:00:98:ee:fd', d])
        writer.writerow(['00:50:56:be:02:54', d])
    for att in attacks:
        flow_handler = FlowHandler(packet_length=1500, seq_length=seq_length, batch_size=128, epochs=50, config=config,
                                   mode='E')
        cap.capture('../iot-data-processed/attack/{}/001.pcap'.format(att), flow_handler)
        os.rename(eval_path, os.path.join('evaluation_{}'.format(seq_length), d + '_{}.csv'.format(att)))
        # os.rename(eval_path, os.path.join('evaluation', d + '_{}.csv'.format(att)))
