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
        self.ip_to_domain = {}
        self.dev_to_domain = {}
        # maximum cached flows use more than 50% of memory size
        self.max_flows = int((os.sysconf('SC_PAGE_SIZE') * os.sysconf(
            'SC_PHYS_PAGES')) * 0.5 / (self.packet_length * self.seq_length))
        self.proto_lookup = {
            'ICMP': 1,
            'TCP': 6,
            'UDP': 17
        }
        self.mode = mode

        self.dev_to_det = {}
        self.detectors = {}
        # self.device_list = {}
        if config:
            with open(config, 'r') as f:
                reader = csv.reader(f)
                # next(reader)
                for row in reader:
                    self.dev_to_det[row[0]] = row[1]

    def parse(self, packet):
        """
        Parse a packet and add it into its flow list. Return a sequence and
        its mac address if a sequence is collected. Otherwise return None.

        """
        if Ether not in packet:
            return
        if packet[Ether].src in self.dev_to_det:
            addr = packet[Ether].src
            direction = 0
            if DNS in packet:
                return
        elif packet[Ether].dst in self.dev_to_det:
            addr = packet[Ether].dst
            direction = 1
            if DNSRR in packet:
                self.dnsrr_process(addr, packet)
                return
        else:
            return
        if TCP not in packet and UDP not in packet:
            return
        if (direction == 0 and packet[IP].dst.startswith('192.168.')) or (
                direction == 1 and packet[IP].src.startswith('192.168.')) or (
                direction == 0 and packet[IP].dst == '255.255.255.255') or (
                direction == 0 and packet[IP].dst == '239.255.255.250'):
            if packet[Ether].src != '3c:33:00:98:ee:fd' and packet[Ether].dst != '3c:33:00:98:ee:fd' and \
                    packet[Ether].src != '00:50:56:be:02:54' and packet[Ether].dst != '00:50:56:be:02:54':
                return
        if DHCP in packet or BOOTP in packet:
            return
        if Raw not in packet and TCP in packet:
            # ACK, FIN, PSH, SYN
            if packet[TCP].flags & 0x10 or \
                    packet[TCP].flags & 0x01 or \
                    packet[TCP].flags & 0x04 or \
                    packet[TCP].flags & 0x02:
                return
        # Flow is separated by 4-tuple (dev_mac, domain, sport, dport)
        # if domain not cached, use ip
        # if one port is in system port range, ignore the other one
        if direction == 0:
            ip = packet[IP].dst
            sport, dport = packet.sport, packet.dport
        else:
            ip = packet[IP].src
            dport, sport = packet.sport, packet.dport
        if sport < 1024 <= dport:
            dport = None
        elif dport < 1024 <= sport:
            sport = None
        elif packet.proto == self.proto_lookup['UDP']:
            sport, dport = None, None

        if ip in self.ip_to_domain:
            flow = (addr, self.ip_to_domain[ip], sport, dport)
        else:
            flow = (addr, ip, sport, dport)

        # IP address mask
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
        if flow not in self.flow_dict:
            self.flow_dict[flow] = deque(maxlen=self.seq_length)
        self.flow_dict[flow].append(byte_vector)

        if len(self.flow_dict[flow]) == self.seq_length:
            # print('Emit a sequence from flow: {}'.format(idx))
            print(flow)
            self.emit(addr, self.flow_dict[flow])
            if self.mode == 'T':
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
        # packet_bytes = packet[Raw].build()
        # Padding or truncating to packet_length bytes, and normalize
        packet_bytes = packet_bytes + b'\x00' * (self.packet_length - len(packet_bytes)) if len(
            packet_bytes) < self.packet_length else packet_bytes[:self.packet_length]
        byte_vector = [x / 255.0 for x in list(packet_bytes)]
        return byte_vector

    def emit(self, addr, seq):
        if addr not in self.dev_to_det:
            key = hash(random.random())
            print('Create a new detector {}'.format(key))
            self.dev_to_det[addr] = key
            det = Detector(key, self.packet_length, self.seq_length, self.batch_size, self.epochs)
            self.detectors[key] = det
        elif self.dev_to_det[addr] not in self.detectors:
            key = self.dev_to_det[addr]
            print('Create a new detector {}'.format(key))
            self.dev_to_det[addr] = key
            det = Detector(key, self.packet_length, self.seq_length, self.batch_size, self.epochs)
            self.detectors[key] = det
        else:
            det = self.detectors[self.dev_to_det[addr]]

        det.update_buffer(list(seq), self.mode)

    def dnsrr_process(self, addr, packet):
        if not packet.qd:
            return
        domain = packet.qd.qname
        if addr not in self.dev_to_domain:
            self.dev_to_domain[addr] = []
        if domain not in self.dev_to_domain[addr]:
            self.dev_to_domain[addr].append(domain)
        if domain.endswith(b'.local.'):
            return
        ans_ip = []
        for i in range(packet.ancount):
            if packet.an[i].type != 1:
                continue
            ans_ip.append(packet.an[i].rdata)
        if ans_ip:
            for ip in ans_ip:
                self.ip_to_domain[ip] = domain

    def wrap_up(self):
        if self.mode == 'T':
            for key in self.detectors:
                det = self.detectors[key]
                det.save()
        elif self.mode == 'S':
            for addr in self.dev_to_domain:
                key = self.dev_to_det[addr]
                det = self.detectors[key]
                det.set_threshold(len(self.dev_to_domain[addr]))
