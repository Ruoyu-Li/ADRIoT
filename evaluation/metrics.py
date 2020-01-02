import pandas as pd
import csv
import os


d_list = ['blink-camera', 'google-home-mini', 'smartthings-hub', 'tplink-plug', 'xiaomi-cleaner']

with open('result/metrics.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['device', 'TN', 'FP', 'TP', 'FN', 'precision', 'recall', 'F1'])
    for d in os.listdir('./'):
        if d == 'result' or d.endswith('.py'): continue
        if d in d_list:
            print('Dealing with {}'.format(d))
            df = pd.read_csv(os.path.join(d, d+'.csv'), header=None)
            n1 = df.shape[0]
            mini_max = one_sigma = two_sigma = three_sigma = 0
            for i in range(n1):
                if df[1][i] == 'Normal': mini_max += 1
                if df[2][i] == 'Normal': one_sigma += 1
                if df[3][i] == 'Normal': two_sigma += 1
                if df[4][i] == 'Normal': three_sigma += 1
            TN = two_sigma 
            FP = n1 - TN
            df = pd.read_csv(os.path.join(d, d+'_test.csv'), header=None)
            n2 = df.shape[0]
            mini_max = one_sigma = two_sigma = three_sigma = 0
            for i in range(n2):
                if df[1][i] == 'Malicious': mini_max += 1
                if df[2][i] == 'Malicious': one_sigma += 1
                if df[3][i] == 'Malicious': two_sigma += 1
                if df[4][i] == 'Malicious': three_sigma += 1
            TP = two_sigma * 1.0 / n2
            FN = 1 - TP
            scale = n2 * 1.0 / n1
            TN = TN * 1.0 / n1
            FP = 1 - TN
            precision = TP * 1.0 / (TP + FP)
            recall = TP * 1.0 / (TP + FN)
            F1 = 2*precision*recall / (precision + recall)
            writer.writerow([d, TN, FP, TP, FN, precision, recall, F1])

