"""
This file provides a class that collaboratively trains a CNN-LSTM autoencoder 
with batch gradient descent.
"""
__author__ = 'Ruoyu Li'


import numpy as np
import pandas as pd
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
from sklearn.metrics import mean_squared_error
np.random.seed(7)


class Trainer(object):
	def __init__(self, arg):
		super(Trainer, self).__init__()
		self.arg = arg
