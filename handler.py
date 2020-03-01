"""
This file provides a class that receives incoming packets from a stream or 
a pcap file, parses flows into sequences based on a sequence length, and 
returns a sequence for detection when a flow fills up the length.
"""
__author__ = 'Ruoyu Li'


from scapy.all import *
import numpy as np
import sys
import os
import csv
import random
from collections import deque
from detector import Detector
random.seed(7)


class FlowHandler(object):
    def __init__(self, packet_length=1500, seq_length=6, batch_size=128, epochs=10, config=None, mode='T'):
        super(FlowHandler, self).__init__()
        self.packet_length = packet_length
        self.seq_length = seq_length
        self.batch_size = batch_size
        self.epochs = epochs
        self.flow_dict = {}
        # maximum cached flows use more than 50% of memory size
        self.max_flows = int((os.sysconf('SC_PAGE_SIZE') * os.sysconf(
            'SC_PHYS_PAGES')) * 0.5 / (self.packet_length * self.seq_length))
        self.proto_lookup = {
            'ICMP': 1,
            'TCP': 6,
            'UDP': 17
        }
        self.mode = mode

        self.dev2det = {}
        self.detectors = {}
        # self.device_list = {}
        if config:
            with open(config, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    self.dev2det[row[0]] = row[1]

    def parse(self, packet):
        """ 
        Parse a packet and add it into its flow list. Return a sequence and 
        its mac address if a sequence is collected. Otherwise return None.

        """
        if IP not in packet:
            return
        if packet[IP].src not in self.dev2det:
            return
        if TCP not in packet and UDP not in packet and ICMP not in packet:
            return
        if DNS in packet or Raw not in packet:
            return

        # Flow is separated by 5-tuple (source, destination, sport, dport, proto)
        try:
            flow = (packet[IP].src, packet[IP].dst,
                    packet.sport, packet.dport, packet.proto)
        except AttributeError as e:
            flow = (packet[IP].src, packet[IP].dst, 0, 0, packet.proto)

        # IP address masking
        src_ip = packet[IP].src
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

        # link layer removal
        packet_bytes = packet[IP].build()

        # padding
        if packet.proto == self.proto_lookup['UDP']:
            byte_vector = self.padding(packet, packet_bytes, 'UDP')
        if packet.proto == self.proto_lookup['ICMP']:
            byte_vector = self.padding(packet, packet_bytes, 'ICMP')
        else:
            byte_vector = self.padding(packet, packet_bytes, 'TCP')

        # add into flow_dict, and emit if filled up to seq_length
        flow = src_ip
        if flow not in self.flow_dict:
            self.flow_dict[flow] = deque(maxlen=self.seq_length)
        self.flow_dict[flow].append(byte_vector)

        if len(self.flow_dict[flow]) == self.seq_length:
            # print('Emit a sequence from flow: {}'.format(idx))
            self.emit(src_ip, self.flow_dict[flow])
            if self.mode == 'T' or self.mode == 'S':
                self.flow_dict[flow].popleft()
            else:
                self.flow_dict[flow] = deque(maxlen=self.seq_length)

    def padding(self, packet, packet_bytes, proto):
        # UDP/ICMP header padding
        if proto == 'UDP' or proto == 'ICMP':
            idx1 = len(packet[IP]) - len(packet[proto])
            if Raw in packet:
                idx2 = len(packet[proto]) - len(packet.load)
            else:
                idx2 = len(packet[proto])
            packet_bytes = packet_bytes[:idx1 + idx2] + \
                b'\x00' * (20 - idx2) + packet_bytes[idx1 + idx2:]
        # TODO
        packet_bytes = packet[Raw].build()
        # Padding or truncating to packet_length bytes, and normalize
        packet_bytes = packet_bytes + b'\x00' * (self.packet_length - len(packet_bytes)) if len(
            packet_bytes) < self.packet_length else packet_bytes[:self.packet_length]
        byte_vector = [x / 255.0 for x in list(packet_bytes)]
        return byte_vector

    def emit(self, addr, seq):
        if addr not in self.dev2det:
            key = hash(random.random())
            print('Create a new detector {}'.format(key))
            self.dev2det[addr] = key
            det = Detector(key, self.packet_length, self.seq_length, self.batch_size, self.epochs)
            self.detectors[key] = det
        elif self.dev2det[addr] not in self.detectors:
            key = self.dev2det[addr]
            print('Create a new detector {}'.format(key))
            self.dev2det[addr] = key
            det = Detector(key, self.packet_length, self.seq_length, self.batch_size, self.epochs)
            self.detectors[key] = det
        else:
            det = self.detectors[self.dev2det[addr]]

        det.update_buffer(list(seq), self.mode)
