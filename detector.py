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
from math import inf
import os
import csv


class Detector(object):
    def __init__(self, key, packet_length=1500, seq_length=6, batch_size=128, epoches=10):
        super(Detector, self).__init__()
        self.key = str(key)
        self.mini_batch = batch_size
        self.threshold = -1
        self.buffer = []
        self.max_round = inf
        self.train_round = 0
        self.model = Autoencoder(packet_length, seq_length, epoches)
        self.path = os.path.join('model', self.key)
        if os.path.exists(self.path + '.json'):
            self.model.load(self.path)
        if os.path.exists(os.path.join('threshold', self.key)):
            f = open(os.path.join('threshold', self.key), 'r')
            self.threshold = float(f.readline())
            f.close()
        if not os.path.exists(os.path.join('evaluation', self.key)):
            os.mkdir(os.path.join('evaluation', self.key))
        self.log_path = os.path.join('evaluation', self.key, str(packet_length)+'_'+str(seq_length)+'_'+str(batch_size)+'_'+str(epoches)+'.csv')

    def update_buffer(self, seq, mode):
        seq = deepcopy(seq)
        if mode == 'T' and self.train_round <= self.max_round:
            self.buffer.append(seq)
            if len(self.buffer) == self.mini_batch:
                random.shuffle(self.buffer)
                X = np.array(self.buffer)
                self.train(np.array(self.buffer))
                self.buffer = []
                self.train_round += 1
        elif mode == 'S':
            X = np.array(seq)
            X = X.reshape(1, X.shape[0], X.shape[1])
            self.set_thres(X)
        elif mode == 'E':
            X = np.array(seq)
            X = X.reshape(1, X.shape[0], X.shape[1])
            self.execute(X)

    def train(self, X):
        self.model.fit(X)
        Y = self.model.predict(X)
        # thres_list = []
        # for i in range(X.shape[0]):
            # thres_list.append(mean_squared_error(X[i], Y[i]))
        # print(max(thres_list))
        # if max(thres_list) > self.threshold:
            # self.threshold = max(thres_list)
            # print('Threshold updated {}'.format(self.threshold))
            # with open(os.path.join('threshold', self.key), 'w') as f:
                # f.write(str(self.threshold))
        print('Detector {} saved'.format(self.key))
        self.model.save(os.path.join(self.path))
        # print('Threshold {}'.format(self.threshold))

    def set_thres(self, X):
        Y = self.model.predict(X)
        mse = mean_squared_error(X[0], Y[0])
        print('Calculating threshold of {}'.format(self.key))
        if mse > self.threshold:
            self.threshold = mse
            print('Threshold updated {}'.format(self.threshold))
            with open(os.path.join('threshold', self.key), 'w') as f:
                f.write(str(self.threshold))

    def execute(self, X):
        Y = self.model.predict(X)
        mse = mean_squared_error(X[0], Y[0])
        print('Execute on {}'.format(self.key))
        with open(self.log_path, 'a') as f:
            writer = csv.writer(f)
            writer.writerow([str(mse), str(self.threshold), 'Normal' if mse <= self.threshold else 'Malicious'])

