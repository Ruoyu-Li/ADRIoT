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
source_train = sys.argv[2]
source_eval = sys.argv[3]
source_test = sys.argv[4]

batch_size = [128]
epoches = [10]
packet_len = [1500]
seq_len = [6]

for b in batch_size:
    for e in epoches:
        for p in packet_len:
            for s in seq_len:
                model_list = os.listdir('model')
                if len(model_list):
                    for m in model_list:
                        os.remove(os.path.join('model', m))
                thres_list = os.listdir('threshold')
                if len(thres_list):
                    for t in thres_list:
                        os.remove(os.path.join('threshold', t))
                cap = PacketCapturer(stream_type)
                flow_handler = FlowHandler(packet_length=p, seq_length=s, batch_size=b, epoches=e, config='config/config.csv', mode='T')
                for device in os.listdir(source_train):
                    if device == '.DS_Store':
                        continue
                    print('Dealing with device {}'.format(device))
                    for action in os.listdir(os.path.join(source_train, device)):
                        if action == '.DS_Store':
                            continue
                        for f in os.listdir(os.path.join(source_train, device, action)):
                            if f == '.DS_Store':
                                continue
                            if f.endswith('.pcap'):
                                cap.capture(os.path.join(
                                    source_train, device, action, f), flow_handler.parse)
                cap = PacketCapturer(stream_type)
                flow_handler = FlowHandler(packet_length=p, seq_length=s, batch_size=b, epoches=e, config='config/config.csv', mode='S')
                for device in os.listdir(source_eval):
                    if device == '.DS_Store':
                        continue
                    print('Dealing with device {}'.format(device))
                    for action in os.listdir(os.path.join(source_eval, device)):
                        if action == '.DS_Store':
                            continue
                        for f in os.listdir(os.path.join(source_eval, device, action)):
                            if f == '.DS_Store':
                                continue
                            if f.endswith('.pcap'):
                                cap.capture(os.path.join(
                                    source_eval, device, action, f), flow_handler.parse)
                cap = PacketCapturer(stream_type)
                flow_handler = FlowHandler(packet_length=p, seq_length=s, batch_size=b, epoches=e, config='config/config.csv', mode='E')
                for device in os.listdir(source_test):
                    if device == '.DS_Store':
                        continue
                    print('Dealing with device {}'.format(device))
                    for action in os.listdir(os.path.join(source_test, device)):
                        if action == '.DS_Store':
                            continue
                        for f in os.listdir(os.path.join(source_test, device, action)):
                            if f == '.DS_Store':
                                continue
                            if f.endswith('.pcap'):
                                cap.capture(os.path.join(
                                    source_test, device, action, f), flow_handler.parse)
