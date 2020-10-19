# ADRIoT: An Edge-assistant Anomaly Detection Framework against IoT-based Network Attacks

## Abstract
Internet of Things (IoT) has entered a stage of rapid development and increasing deployment. Meanwhile, these low-power devices typically cannot support complex security mechanisms, and thus highly susceptible to being exploited and compromised by malware. An attacker can remotely control an IoT botnet to sabotage other entities, such as launching Distributed Denial-of-Service (DDoS) attacks. Unfortunately, IoT consumers usually have little expert knowledge to detect and handle these anomalies. In this paper, we propose ADRIoT, an anomaly detection framework for IoT networks which leverages edge computing to uncover potential threats. It serves as a security service provided for IoT manufacturers to realize an early-stage anomaly detection on their compromised devices. We also consider two types of edge used in different IoT scenarios and design two operating modes within an edge-cloud architecture. Each edge is empowered with an anomaly detection module that is able to capture emerging unknown attacks by using an unsupervised learning model. The evaluation demonstrates that ADRIoT can detect a wide range of IoT based attacks effectively on two types of edge, showing that ADRIoT can feasibly help build a more secure IoT environment.

## Requirements
Install Python3:

    sudo apt install python3
    
Install virtualenv and create virtual environment:

    pip3 install virtualenv
    virtualenv venv --python=python3
    
Use virtual environment and install required packages:

    source venv/bin/activate
    pip install -r requirements.txt

## Run
To train the detector, choose the dataset in eval.py and run:

    python eval.py

Since the IoT dataset is not completely public, to access the dataset, please refer to the paper "Information Exposure From Consumer IoT Devices: A Multidimensional, Network-Informed Measurement Approach" and their research group for approval.

To detect attack traffic, run:

    python test.py
    
The attack dataset are public. Please refer to the bibliography in our paper.
  