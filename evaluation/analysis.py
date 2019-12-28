import os
import csv
import statistics as s


for d in os.listdir('./'):
    result = {}
    if d.endswith('.py'): continue
    if d == 'result': continue
    for file_name in os.listdir(d):
        stats = {}
        with open(os.path.join(d, file_name), 'r') as csv_file:
            reader = csv.reader(csv_file)
            var = []
            for row in reader:
                var.append(float(row[0]))
        stats['mean'] = s.mean(var)
        stats['median'] = s.median(var)
        stats['stdev'] = s.stdev(var)
        result[file_name] = stats
    with open(os.path.join('result', 'result_3_' + d + '.csv'), 'w') as fin:
        writer = csv.writer(fin)
        writer.writerow(['parameter', 'mean', 'median', 'stdev'])
        for f in result:
            writer.writerow([f, result[f]['mean'], result[f]['median'], result[f]['stdev']])

    with open(os.path.join('result', 'result_3.csv'), 'a') as fin:
        para_mean = None
        cand_mean = 1
        for f in result:
            if result[f]['mean'] < cand_mean:
                cand_mean = result[f]['mean']
                para_mean = f
        writer = csv.writer(fin)
        writer.writerow([d, para_mean])

