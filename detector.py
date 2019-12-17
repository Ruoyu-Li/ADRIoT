"""
This file provides a class for one anomaly detector.
"""
__author__ = 'Ruoyu Li'


import numpy as np
import os
from datetime import datetime
from copy import deepcopy
import random
random.seed(7)
from model import Autoencoder
from sklearn.metrics import mean_squared_error


class Detector(object):
	def __init__(self, key, packet_length=1500, seq_length=6):
		super(Detector, self).__init__()
		self.key = str(key)
		self.mini_batch = 64
		self.threshold = -1
		self.buffer = []
		self.max_round = 20
		self.train_round = 0
		self.model = Autoencoder(packet_length, seq_length)
		self.path = os.path.join('model', self.key)


	def update_buffer(self, seq):
		seq = deepcopy(seq)
		if self.train_round <= self.max_round:
			self.buffer.append(seq)
			if len(self.buffer) == self.mini_batch:
				random.shuffle(self.buffer)
				X = np.array(self.buffer)
				# print('update buffer shape array {} {} {}'.format(X.shape, len(X[0]), type(X[0])))
				# self.train(convert_to_tensor(self.buffer))
				self.train(np.array(self.buffer))
				self.buffer = []
				self.train_round += 1
		else:
			X = np.array(seq)
			X = X.reshape(1, X.shape[0], X.shape[1])
			self.execute(X)


	def train(self, X):
		self.model.fit(X)
		Y = self.model.predict(X)
		thres_list = []
		for i in range(X.shape[0]):
			thres_list.append(mean_squared_error(X[i], Y[i]))
		if max(thres_list) > self.threshold:
			self.threshold = max(thres_list)
			print('Threshold updated {}'.format(self.threshold))
		print('Detector {} saved'.format(self.key))
		self.model.save(os.path.join(self.path))
		print('Threshold {}'.format(self.threshold))


	def execute(self, X):
		Y = self.model.predict(X)
		thres_list = []
		for i in range(X.shape[0]):
			thres_list.append(mean_squared_error(X[i], Y[i]))
		print('MSE {}'.format(str(thres_list)))




