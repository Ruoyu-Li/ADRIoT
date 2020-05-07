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
from sklearn.cluster import KMeans
import pickle
from math import inf, sqrt
import csv
random.seed(7)


class Detector(object):
    def __init__(self, key, packet_length=1500, seq_length=6, batch_size=128, epochs=10):
        super(Detector, self).__init__()
        self.key = str(key)
        self.mini_batch = batch_size
        # 5 tuple stats - count, linear sum, squared sum, max, min
        # self.stats = [0, 0, 0, 0, 1]
        self.stats = [1, 0]
        self.count = 0
        self.buffer = []
        self.mse_buffer = []
        self.max_round = inf
        self.train_round = 0
        self.model = Autoencoder(packet_length, seq_length, epochs)
        self.scaler = StandardScaler()

        self.model_path = os.path.join('model2', self.key)
        self.stats_path = os.path.join('stats2', self.key + '.csv')
        # self.stats_path = os.path.join('stats', self.key + '.pkl')
        self.eval_path = os.path.join('evaluation2', self.key + '_udp_ddos.csv')
        if os.path.exists(self.model_path + '.json'):
            print('Using existing model: {}'.format(self.key))
            self.model.load(self.model_path)
        if os.path.exists(self.stats_path):
            with open(self.stats_path, 'r') as f:
                reader = csv.reader(f)
                stats_string = next(reader)
                for i in range(len(stats_string)):
                    self.stats[i] = float(stats_string[i])
        # if os.path.exists(self.stats_path):
        #     print('Using existing stats')
        #     self.scaler = pickle.load(open(self.stats_path, 'rb'))
        # self.save_flag = False

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
        else:
            X = np.array(seq)
            X = X.reshape((1, X.shape[0], X.shape[1]))
            if mode == 'S':
                self.eval(X)
            elif mode == 'E':
                self.execute(X)
            elif mode == 'F':
                self.feature(X)

    def train(self, X):
        self.model.fit(X)
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
        # self.stats[0] += 1
        # self.stats[1] += mse
        # self.stats[2] += mse * mse
        # self.stats[1] = self.stats[1] + 0.002 if mse > self.stats[1] else self.stats[1]
        # self.stats[0] = self.stats[0] - 0.002 if mse < self.stats[0] else self.stats[0]
        # with open(self.stats_path, 'w') as f:
        #     writer = csv.writer(f)
        #     writer.writerow(self.stats)
        # self.count += 1
        # self.scaler.partial_fit(np.array([[mse]]))
        # pickle.dump(self.scaler, open(self.stats_path, 'wb'))

    def set_threshold(self, n):
        n = 20 if n > 20 else n
        kmeans = KMeans(n_clusters=n, random_state=0).fit(np.array(self.mse_buffer).reshape(-1, 1))
        centers = kmeans.cluster_centers_.reshape(-1)
        centers.sort()
        print(centers)
        self.stats[0], self.stats[1] = centers[0], centers[-1]
        with open(self.stats_path, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(self.stats)

    # def adjust(self, X):
    #     Y = self.model.predict(X)
    #     mse = mean_squared_error(X[0], Y[0])
    #     print('Calculating mse of {}: {}'.format(self.key, mse))
    #     # if mse >= self.stats[0]:
    #     #     self.stats[0] += 0.001
    #     # else:
    #     #     self.stats[0] -= 0.003
    #     # if mse <= self.stats[1]:
    #     #     self.stats[1] -= 0.001
    #     # else:
    #     #     self.stats[1] += 0.003
    #     print(self.stats)
    #     with open(self.stats_path, 'w') as f:
    #         writer = csv.writer(f)
    #         writer.writerow(self.stats)

    def execute(self, X):
        Y = self.model.predict(X)
        mse = mean_squared_error(X[0], Y[0])
        print('Execute on {}: {}'.format(self.key, mse))
        # avg, sigma = self.scaler.mean_, 1
        # min_max = 'Normal' if self.stats[3] >= mse >= self.stats[4] else 'Malicious'
        # avg = self.stats[1] / self.stats[0]
        # sigma = sqrt(self.stats[2] / self.stats[0] - avg * avg)
        # one_sigma = 'Normal' if avg + sigma >= mse >= avg - sigma else 'Malicious'
        # two_sigma = 'Normal' if avg + sigma * 2 >= mse >= avg - sigma * 2 else 'Malicious'
        # three_sigma = 'Normal' if avg + sigma * 3 >= mse >= avg - sigma * 3 else 'Malicious'
        # one_sigma = 'Normal' if avg + sigma >= self.scaler.transform(np.array([[mse]]))[0] >= avg - sigma else 'Malicious'
        # two_sigma = 'Normal' if avg + sigma * 2 >= self.scaler.transform(np.array([[mse]]))[0] >= avg - sigma * 2 else 'Malicious'
        # three_sigma = 'Normal' if avg + sigma * 3 >= self.scaler.transform(np.array([[mse]]))[0] >= avg - sigma * 3 else 'Malicious'
        result = 'Normal' if self.stats[0] <= mse <= self.stats[1] else 'Malicious'
        with open(self.eval_path, 'a') as f:
            writer = csv.writer(f)
            # writer.writerow([str(mse), min_max, one_sigma, two_sigma, three_sigma])
            # writer.writerow([str(mse), one_sigma, two_sigma, three_sigma])
            writer.writerow([str(mse), result])

    def feature(self, X):
        Y = self.model.output_feature(X)
        with open(self.eval_path, 'a') as f:
            writer = csv.writer(f)
            writer.writerow([x for x in Y[0]])

