"""
This file provides a class for one anomaly detector.
"""
__author__ = 'Ruoyu Li'

import numpy as np
import os
from copy import deepcopy
import random
from model import Autoencoder
from sklearn.metrics import mean_squared_error
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import pickle
from math import inf, sqrt
import csv
import time
random.seed(7)


class Detector(object):
    def __init__(self, key, packet_length=1500, seq_length=6, batch_size=128, epochs=10):
        super(Detector, self).__init__()
        self.key = str(key)
        self.mini_batch = batch_size
        # 5 tuple stats - count, linear sum, squared sum, max, min
        self.stats = [1, 0]
        self.count = 0
        self.buffer = []
        self.fit_buffer = []
        self.mse_buffer = []
        self.max_round = inf
        self.train_round = 0
        self.model = Autoencoder(packet_length, seq_length, epochs)
        self.scaler = StandardScaler()

        self.model_path = os.path.join('model_{}'.format(seq_length), self.key)
        # self.model_path = os.path.join('model')
        self.stats_path = os.path.join('stats_{}'.format(seq_length), self.key + '.csv')
        # self.stats_path = os.path.join('stats', self.key + '.csv')
        self.eval_path = os.path.join('evaluation_{}'.format(seq_length), self.key + '_test.csv')
        # self.eval_path = os.path.join('evaluation', self.key + '.csv')
        # self.loss_path = os.path.join('evaluation_{}'.format(seq_length), self.key + '_loss.csv')
        if os.path.exists(self.model_path + '.json'):
            print('Using existing model: {}'.format(self.key))
            self.model.load(self.model_path)
        if os.path.exists(self.stats_path):
            with open(self.stats_path, 'r') as f:
                reader = csv.reader(f)
                stats_string = next(reader)
                for i in range(len(stats_string)):
                    self.stats[i] = float(stats_string[i])

    def update_buffer(self, seq, mode):
        seq = deepcopy(seq)
        if mode == 'T' and self.train_round <= self.max_round:
            self.buffer.append(seq)
            if len(self.buffer) == self.mini_batch:
                random.shuffle(self.buffer)
                X = np.array(self.buffer)
                self.train(X)
                self.buffer = []
                self.train_round += 1
        elif mode == 'E':
            self.fit_buffer.append(seq)
            if len(self.fit_buffer) == 1:
                X = np.array(self.fit_buffer)
                self.execute(X)
                self.fit_buffer = []
        else:
            X = np.array(seq)
            X = X.reshape((1, X.shape[0], X.shape[1]))
            self.eval(X)

    def train(self, X):
        history = self.model.fit(X)
        # self.count += 1
        # with open(self.loss_path, 'a') as f:
        #     writer = csv.writer(f)
        #     if self.count == 1:
        #         writer.writerow([history.history['loss'][0]])
        #     writer.writerow([history.history['loss'][-1]])
        # print('Detector {} saved'.format(self.key))
        # self.model.save(self.model_path)

    def save(self):
        self.model.save(self.model_path)

    def eval(self, X):
        # if self.count > 500:
        #     return
        Y = self.model.predict(X)
        mse = mean_squared_error(X[0], Y[0])
        print('Calculating mse of {}: {}'.format(self.key, mse))
        self.mse_buffer.append(mse)

    def set_threshold(self, n):
        clf = LocalOutlierFactor(n_neighbors=n, contamination=0.05)
        idx = clf.fit_predict(np.array(self.mse_buffer).reshape(-1, 1))
        for i in range(len(self.mse_buffer)):
            if idx[i] == -1:
                continue
            if self.mse_buffer[i] > self.stats[1]:
                self.stats[1] = self.mse_buffer[i]
            if self.mse_buffer[i] < self.stats[0]:
                self.stats[0] = self.mse_buffer[i]
        with open(self.stats_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(self.stats)

    def execute(self, X):
        start = time.time()
        Y = self.model.predict(X)
        dur = time.time() - start
        with open(self.eval_path, 'a') as f:
            for x, y in zip(X, Y):
                mse = mean_squared_error(x, y)
                print('Execute on {}: {}'.format(self.key, mse))
                result = 'Normal' if self.stats[0] <= mse <= self.stats[1] else 'Malicious'
                writer = csv.writer(f)
                writer.writerow([str(mse), result])
                # writer.writerow([str(dur)])

    def feature(self, X):
        Y = self.model.output_feature(X)
        with open(self.eval_path, 'a') as f:
            writer = csv.writer(f)
            writer.writerow([x for x in Y[0]])

