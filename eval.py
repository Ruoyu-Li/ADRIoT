"""
This file is the main function to run the system.
"""
__author__ = 'Ruoyu Li'


from capturer import PacketCapturer
from handler import FlowHandler
import sys
import os


# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
device = sys.argv[1]
source_train = sys.argv[2]
source_eval = sys.argv[3]
source_test = sys.argv[4]

batch_size = [128]
epoches = [50]
packet_len = [1500]
seq_len = [10]


def handle(capturer, handler, source, target_device):
    for device in os.listdir(source):
        if device != 'all' and device != target_device:
            continue
        print('Dealing with device {}'.format(device))
        actions = os.listdir(os.path.join(source, device))
        actions.sort(reverse=True)
        for action in actions:
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
                model_list = os.listdir('model')
                # if len(model_list):
                #     for m in model_list:
                #         os.remove(os.path.join('model', m))
                # thres_list = os.listdir('stats')
                # if len(thres_list):
                #     for t in thres_list:
                #         os.remove(os.path.join('stats', t))
                cap = PacketCapturer('pcap')
                for i in range(len(mode)):
                    flow_handler = FlowHandler(packet_length=p, seq_length=s, batch_size=b, epochs=e,
                                               config='config/config_mac.csv', mode=mode[i])
                    handle(cap, flow_handler, data[i], device)
