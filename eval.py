"""
This file is to train, evaluate and test the detector using IoT data.
"""
__author__ = 'Ruoyu Li'


from capturer import PacketCapturer
from handler import FlowHandler
import os


source_train = '../iot-data-processed/us_train'
source_eval = '../iot-data-processed/us_eval'
source_test = '../iot-data-processed/uk_eval'
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
batch_size = [128]
epoches = [50]
packet_len = [1500]
seq_len = [10]


def handle(capturer, handler, source, target_device, act=None):
    for device in os.listdir(source):
        if device not in target_device:
            continue
        print('Dealing with device {}'.format(device))
        actions = os.listdir(os.path.join(source, device))
        actions.sort(reverse=True)
        for action in actions:
            if act is None:
                pass
            elif not action.startswith(act):
                continue
            for f in os.listdir(os.path.join(source, device, action)):
                if f.endswith('.pcap'):
                    capturer.capture(os.path.join(source, device, action, f), handler)
        handler.wrap_up()


mode = ['T', 'S', 'E']
data = [source_train, source_eval, source_test]
for b in batch_size:
    for e in epoches:
        for p in packet_len:
            for s in seq_len:
                cap = PacketCapturer('pcap')
                for i in range(len(mode)):
                    flow_handler = FlowHandler(seq_length=s, config='config/config_mac.csv', mode=mode[i])
                    handle(cap, flow_handler, data[i], dev_name, None)
