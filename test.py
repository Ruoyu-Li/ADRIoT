"""
This file is to simulate detection on attack traffic.
"""
__author__ = 'Ruoyu Li'

from capturer import PacketCapturer
from handler import FlowHandler
import os
import csv

# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
dev_name = [
    'appletv',
    'nest-tstat',
    't-wemo-plug',
    'tplink-bulb',
    'tplink-plug',
    'zmodo-doorbell',
    'echoplus',
    'roku-tv',
    'sengled-hub',
    'echospot',
]
attacks = [
    'infection',
    'tcp',
    'udp',
    'http',
    'scan',
    'os',
    'data',
    'keylogging',
    'xbash'
]
seq_length = 10
config = 'config/config_{}.csv'.format(seq_length)
dir_path = 'evaluation_{}'.format(seq_length)

cap = PacketCapturer('pcap')
for d in dev_name:
    eval_path = os.path.join(dir_path, d + '_test.csv')
    with open(config, 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['3c:33:00:98:ee:fd', d])
        writer.writerow(['00:50:56:be:02:54', d])
        writer.writerow(['b8:27:eb:8b:b1:2c', d])
    for att in attacks:
        flow_handler = FlowHandler(seq_length=seq_length, config=config, mode='E')
        cap.capture('../iot-data-processed/attack/{}/001.pcap'.format(att), flow_handler)
        flow_handler.wrap_up()
        os.rename(eval_path, eval_path.replace('test', att+'_0'))
