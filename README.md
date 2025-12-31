# SentinelAuth — Hybrid Log Intrusion Detector (Rules + ML)

SentinelAuth is a Python-based intrusion detection tool that analyzes authentication logs to detect brute-force attacks and anomalous login behavior.

## Features
- Parses Linux auth logs (sshd-style)
- Detects brute-force, password spraying, and distributed login attempts
- Trains an unsupervised ML baseline (IsolationForest) on hourly behavior
- Flags anomalous IP and user activity with explainable reasons
- Outputs JSON and CSV reports suitable for SIEM ingestion

## Tech Stack
- Python
- scikit-learn
- joblib

## How It Works
1. Parse logs into structured events (IP, user, timestamp, action)
2. Apply rule-based detection using sliding windows
3. Extract hourly behavioral features
4. Train an unsupervised anomaly detection model
5. Score new logs and generate reports

## Usage

### Train baseline model
```bash
python main.py train --log sample_auth.log --model-out baseline_model.joblib
