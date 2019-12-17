"""
This file provides a class that captures packets from a stream or a pcap file.
It emits a packet at a time and you need a callback function to handle the 
incremental packet. The packet won't be stored after the callback.
Execution needs sudo privilege.
"""
__author__ = 'Ruoyu Li'


from scapy.all import *


class PacketCapturer(object):
	def __init__(self, stream_type):
		super(PacketCapturer, self).__init__()
		self.stream_type = stream_type

	def capture(self, source, callback):
		if self.stream_type == 'pcap':
			sniff(offline=source, prn=callback, store=0)
		if self.stream_type == 'network':
			sniff(iface=source, prn=callback, store=0)
