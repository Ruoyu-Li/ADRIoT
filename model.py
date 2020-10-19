"""
This file provides a class for LSTM autoencoder model, LSTM autoencoder model with TFLite,
and several baseline models.
"""
__author__ = 'Ruoyu Li'

import numpy as np
from abc import ABCMeta, abstractmethod
import os
from tensorflow.keras.models import Sequential, Model, model_from_json
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed
from tensorflow import lite
from tensorflow.keras import optimizers
from tensorflow import random
from sklearn.svm import OneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.mixture import GaussianMixture
from sklearn.covariance import EllipticEnvelope
import joblib

np.random.seed(7)
random.set_seed(7)
# os.environ['CUDA_VISIBLE_DEVICES'] = ''
CUDA_VISIBLE_DEVICES = 1
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'


class ModelBase(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, packet_length=1500, seq_length=10, epochs=50):
        pass

    @abstractmethod
    def fit(self, X):
        pass

    @abstractmethod
    def predict(self, X):
        pass

    @abstractmethod
    def save(self, name):
        pass

    @abstractmethod
    def load(self, name):
        pass

    @abstractmethod
    def exist(self, name):
        pass


class Autoencoder(ModelBase):
    def __init__(self, packet_length=1500, seq_length=10, epochs=50):
        super().__init__(packet_length, seq_length, epochs)
        self.epochs = epochs
        self.model = Sequential()
        self.model.add(
            LSTM(64, activation='relu', return_sequences=False, input_shape=(seq_length, packet_length), name='LSTM_1'))
        self.model.add(RepeatVector(seq_length))
        self.model.add(LSTM(64, activation='relu', return_sequences=True))
        self.model.add(TimeDistributed(Dense(packet_length)))
        self.model.compile(optimizer='adam', loss='mse', metrics=['accuracy'])
        self.model.summary()

    def fit(self, X):
        history = self.model.fit(X, X, epochs=self.epochs, verbose=True)
        return history

    def predict(self, X):
        Y = self.model.predict(X)
        return Y

    def save(self, name):
        model_json = self.model.to_json()
        with open(name + '.json', 'w') as f:
            f.write(model_json)
        self.model.save_weights(name + '.h5')

    def load(self, name):
        with open(name + '.json', 'r') as f:
            loaded_model_json = f.read()
        self.model = model_from_json(loaded_model_json)
        self.model.load_weights(name + '.h5')
        for layer in self.model.layers[:3]:
            layer.trainable = False
        self.model.compile(optimizer=optimizers.SGD(), loss='mse')

    def exist(self, name):
        return os.path.exists(name + '.json') and os.path.exists(name + '.h5')


class AutoencoderLite(ModelBase):
    def __init__(self, packet_length=1500, seq_length=10, epochs=50):
        super().__init__(packet_length, seq_length, epochs)
        self.epochs = epochs
        self.model = bytes()
        self.interpreter = None
        self.input_index = self.output_index = 0

    def fit(self, X):
        pass

    def predict(self, X):
        X = np.array(X, dtype='float32')
        self.interpreter.set_tensor(self.input_index, X)
        self.interpreter.invoke()
        Y = self.interpreter.get_tensor(self.output_index)
        return Y

    def save(self, name):
        with open(name + '.tflite', 'wb') as f:
            f.write(self.model)

    def load(self, name):
        if os.path.exists(name + '.tflite'):
            with open(name + '.tflite', 'rb') as f:
                self.model = f.read()
        elif os.path.exists(name + '.json') and os.path.exists(name + '.h5'):
            with open(name + '.json', 'r') as f:
                loaded_model_json = f.read()
            model = model_from_json(loaded_model_json)
            model.load_weights(name + '.h5')
            print('convert keras model to lite')
            converter = lite.TFLiteConverter.from_keras_model(model)
            converter.optimizations = [lite.Optimize.OPTIMIZE_FOR_SIZE]
            self.model = converter.convert()
        self.interpreter = lite.Interpreter(model_content=self.model)
        self.interpreter.allocate_tensors()
        self.input_index = self.interpreter.get_input_details()[0]["index"]
        self.output_index = self.interpreter.get_output_details()[0]["index"]

    def exist(self, name):
        return os.path.exists(name + '.h5') or os.path.exists(name + '.tflite')


class Baseline(ModelBase):
    def __init__(self, model_name, packet_length=1500, seq_length=1, epochs=1):
        super().__init__(packet_length, seq_length, epochs)
        self.model_name = model_name
        if model_name == 'svm':
            self.model = OneClassSVM(kernel='rbf', nu=0.05)
        elif model_name == 'if':
            self.model = IsolationForest(contamination=0.05, max_features=15, random_state=0)
        elif model_name == 'lof':
            self.model = LocalOutlierFactor(contamination=0.05, novelty=True)
        elif model_name == 'gm':
            self.model = GaussianMixture(random_state=0)
        elif model_name == 'ee':
            self.model = EllipticEnvelope(contamination=0.05, random_state=0)

    def fit(self, X):
        self.model.fit(X)

    def predict(self, X):
        labels = self.model.predict(X)
        scores = self.model.score_samples(X)
        return scores, labels

    def save(self, name):
        joblib.dump(self.model, name + '_{}.pkl'.format(self.model_name))

    def load(self, name):
        self.model = joblib.load(name + '_{}.pkl'.format(self.model_name))

    def exist(self, name):
        return os.path.exists(name + '_{}.pkl'.format(self.model_name))
