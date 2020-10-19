"""
This file provides a class for an anomaly detector on sequential packets
and a detector on single packets.
"""
__author__ = 'Ruoyu Li'

import numpy as np
import os
from copy import deepcopy
import random
from model import Autoencoder, AutoencoderLite, Baseline
from sklearn.metrics import mean_squared_error
from sklearn.svm import OneClassSVM
import joblib
from math import inf
import csv
import time
from abc import ABCMeta, abstractmethod
random.seed(7)


class DetectorBase(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, key, seq_length=10):
        pass

    @abstractmethod
    def update_buffer(self, data, mode, info=None):
        pass

    @abstractmethod
    def train(self, X):
        pass

    @abstractmethod
    def execute(self, X, info=None):
        pass

    @abstractmethod
    def wrap_up(self, mode):
        pass


class Detector(DetectorBase):
    def __init__(self, key, seq_length=10):
        super(Detector, self).__init__(key, seq_length)
        self.key = str(key)
        self.packet_length = 1500
        self.mini_batch = 30
        self.epochs = 50
        self.train_buffer = []
        self.exec_buffer = []
        self.set_buffer = []
        self.max_round = inf
        self.train_round = 0
        self.model = Autoencoder(self.packet_length, seq_length, self.epochs)
        self.clf = OneClassSVM(kernel='rbf', gamma=0.1, nu=0.05)

        self.model_path = os.path.join('model_{}'.format(seq_length), self.key)
        self.stats_path = os.path.join('stats_{}'.format(seq_length), self.key + '.pkl')
        self.eval_path = os.path.join('evaluation_{}'.format(seq_length), self.key + '.csv')
        self.loss_path = os.path.join('evaluation_{}'.format(seq_length), self.key + '_loss.csv')
        if self.model.exist(self.model_path):
            print('Using existing model: {}'.format(self.key))
            self.model.load(self.model_path)
        if os.path.exists(self.stats_path):
            print('Using existing stats')
            self.clf = joblib.load(self.stats_path)

    def update_buffer(self, seq, mode, info=None):
        seq = deepcopy(seq)
        if mode == 'T' and self.train_round <= self.max_round:
            self.train_buffer.append(seq)
            if len(self.train_buffer) == self.mini_batch:
                random.shuffle(self.train_buffer)
                X = np.array(self.train_buffer)
                self.train(X)
                self.train_buffer = []
                self.train_round += 1
        elif mode == 'E':
            self.exec_buffer.append(seq)
            if len(self.exec_buffer) == 1:
                X = np.array(self.exec_buffer)
                self.execute(X, info)
                self.exec_buffer = []
        else:
            X = np.array(seq)
            X = X.reshape((1, X.shape[0], X.shape[1]))
            self.eval(X)

    def train(self, X):
        if self.train_round < self.max_round:
            history = self.model.fit(X)
            with open(self.loss_path, 'a') as f_loss:
                writer_loss = csv.writer(f_loss)
                if self.train_round == 0:
                    writer_loss.writerow([history.history['loss'][0]])
                writer_loss.writerow([history.history['loss'][-1]])
            print('Detector {} saved'.format(self.key))

    def eval(self, X):
        Y = self.model.predict(X)
        mse = mean_squared_error(X[0], Y[0])
        print('Calculating mse of {}: {}'.format(self.key, mse))
        self.set_buffer.append(mse)

    def set_threshold(self):
        self.clf = OneClassSVM(kernel='rbf', gamma=0.1, nu=0.05)
        self.clf.fit(np.array(self.set_buffer).reshape(-1, 1))
        joblib.dump(self.clf, self.stats_path)

    def execute(self, X, info=None):
        start = time.time()
        Y = self.model.predict(X)
        dur = time.time() - start
        with open(self.eval_path, 'a') as f:
            writer = csv.writer(f)
            for x, y in zip(X, Y):
                mse = mean_squared_error(x, y)
                print('Execute on {}: {}'.format(self.key, mse))
                label = self.clf.predict(np.array(mse).reshape(-1, 1))
                result = 'Normal' if label == 1 else 'Malicious'
                if info:
                    writer.writerow([str(mse), result, str(info)])
                else:
                    writer.writerow([str(mse), result])

    def wrap_up(self, mode):
        if mode == 'T':
            self.model.save(self.model_path)
        elif mode == 'S':
            self.set_threshold()


class DetectorSinglePacket(DetectorBase):
    def __init__(self, key, seq_length=1):
        super().__init__(key, seq_length)
        self.key = str(key)
        self.train_buffer = []
        self.exec_buffer = []
        self.model_name = 'svm'
        self.model = Baseline(self.model_name)
        self.model_path = os.path.join('model_{}_baseline'.format(seq_length), self.key)
        self.eval_path = os.path.join('evaluation_{}_baseline'.format(seq_length),
                                      self.key + '_{}_test.csv'.format(self.model_name))
        if self.model.exist(self.model_path):
            print('Using existing model: {}'.format(self.key))
            self.model.load(self.model_path)

    def update_buffer(self, seq, mode, info=None):
        seq = deepcopy(seq)
        if mode == 'T':
            self.train_buffer.append(seq[0])
        elif mode == 'E':
            self.exec_buffer += seq
        else:
            return

    def train(self, X):
        self.model.fit(X)

    def execute(self, X, info=None):
        scores, labels = self.model.predict(X)
        with open(self.eval_path, 'w') as f:
            writer = csv.writer(f)
            for score, label in zip(scores, labels):
                result = 'Normal' if label == 1 else 'Malicious'
                writer.writerow([score, result])

    def wrap_up(self, mode):
        if mode == 'T':
            print('training...')
            self.train(np.array(self.train_buffer))
            self.model.save(self.model_path)
        elif mode == 'E':
            print('executing...')
            self.execute(np.array(self.exec_buffer))
