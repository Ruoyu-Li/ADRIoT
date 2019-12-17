"""
This file provides a class for CNN-LSTM autoencoder model.
"""
__author__ = 'Ruoyu Li'


import numpy as np
import pandas as pd
import os
from keras.models import Sequential
from keras.layers import LSTM
from keras.layers import Dense
from keras.layers import RepeatVector
from keras.layers import TimeDistributed
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D
from keras.layers import UpSampling1D
from keras.models import Model
from keras.utils import plot_model
from keras.models import model_from_json
np.random.seed(7)


class Autoencoder(object):
	def __init__(self, packet_length=1500, seq_length=6, epochs=1):
		super(Autoencoder, self).__init__()
		self.epochs = epochs

		self.model = Sequential()
		self.model.add(Conv1D(filters=128, kernel_size=3, activation='relu', padding='same', input_shape=(seq_length, packet_length)))
		self.model.add(MaxPooling1D(pool_size=2, padding='same'))
		self.model.add(LSTM(64, activation='relu'))
		self.model.add(RepeatVector(3))
		self.model.add(LSTM(64, activation='relu', return_sequences=True))
		# self.model.add(Conv1D(filters=128, kernel_size=3, activation='relu', padding='same'))
		self.model.add(UpSampling1D(2))
		self.model.add(TimeDistributed(Dense(1500)))
		self.model.compile(optimizer='adam', loss='mse')
		self.model.summary()


	def fit(self, X):
		self.model.fit(X, X, epochs=self.epochs, verbose=True)


	def predict(self, X):
		Y = self.model.predict(X)
		return Y


	def save(self, name):
		model_json = self.model.to_json()
		with open(name + '.json', 'w') as f:
			f.write(model_json)
		self.model.save_weights(name + '.h5')


	def load(self, name):
		with open(name + 'json', 'r') as f:
			loaded_model_json = f.read()
		loaded_model = model_from_json(loaded_model_json)
		loaded_model.load_weights(name + '.h5')


