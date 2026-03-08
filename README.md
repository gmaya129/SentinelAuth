# SentinelAuth — Hybrid Log Intrusion Detector (Rules + ML)

![Python](https://img.shields.io/badge/Python-3.8+-blue) ![ML](https://img.shields.io/badge/ML-IsolationForest-green) ![Status](https://img.shields.io/badge/Status-Active-brightgreen)

SentinelAuth is a Python-based intrusion detection system that analyzes authentication logs to detect brute-force attacks, password spraying, and anomalous login behavior using a hybrid approach — combining rule-based detection with unsupervised machine learning.

Built as a practical alternative to signature-only IDS tools, SentinelAuth learns what normal login behavior looks like and flags deviations without requiring pre-labeled attack data — making it effective against novel and evolving threats in real-world environments.

---

## Features

- Parses Linux auth logs (sshd-style)
- Detects brute-force, password spraying, and distributed login attempts
- Trains an unsupervised ML baseline (IsolationForest) on hourly behavioral patterns
- Flags anomalous IP and user activity with explainable reasons
- Outputs JSON and CSV reports suitable for SIEM ingestion
- No labeled attack data required — works on real production logs

---

## Tech Stack

- Python 3.8+
- scikit-learn (IsolationForest)
- joblib (model persistence)
- pandas (log parsing and feature extraction)

---

## How It Works

SentinelAuth uses a two-layer detection approach:

1. **Parse** — Auth logs are parsed into structured events (IP, user, timestamp, action)
2. **Rule-based detection** — Sliding window analysis flags brute-force patterns and password spraying attempts based on configurable thresholds
3. **Feature extraction** — Hourly behavioral features are extracted per IP and user (login frequency, failure rate, unique user attempts, time-of-day patterns)
4. **ML baseline training** — An IsolationForest model learns the baseline of normal login behavior from clean log data
5. **Anomaly scoring** — New logs are scored against the trained baseline and deviations are flagged with confidence scores
6. **Report generation** — Findings are exported as JSON and CSV reports ready for SIEM ingestion or analyst review

The unsupervised approach was chosen deliberately — in real-world security environments, attacks are not labeled in advance. SentinelAuth detects what is abnormal rather than only what is known.

---

## Usage

### Train baseline model
```bash
python main.py train --log sample_auth.log --model-out baseline_model.joblib
```

### Detect anomalies on new logs
```bash
python main.py detect --log new_auth.log --model baseline_model.joblib --out report
```

### Output files generated
```
report.json   — Detailed findings with IP, user, anomaly score, and reason
report.csv    — Flat format suitable for SIEM ingestion
```

---

## Sample Output

```json
{
  "timestamp": "2025-01-15T03:42:17",
  "source_ip": "192.168.1.105",
  "user": "admin",
  "event_type": "brute_force",
  "anomaly_score": -0.47,
  "reason": "52 failed login attempts in 4-minute window from single IP",
  "severity": "HIGH"
}
```

```json
{
  "timestamp": "2025-01-15T04:15:33",
  "source_ip": "10.0.0.88",
  "user": "multiple (12 unique users)",
  "event_type": "password_spraying",
  "anomaly_score": -0.61,
  "reason": "Low-frequency attempts across 12 accounts — distributed spray pattern detected",
  "severity": "HIGH"
}
```

---

## Detection Capabilities

| Attack Type | Detection Method |
|---|---|
| Brute Force | Rule-based sliding window (failure threshold) |
| Password Spraying | Rule-based multi-account pattern detection |
| Distributed Login Attempts | ML anomaly scoring (IsolationForest) |
| Off-hours Access | ML behavioral baseline deviation |
| New IP Access | ML anomaly scoring |

---

## Why Unsupervised ML?

Most IDS tools rely on signature-based detection — they only catch known attacks. SentinelAuth uses IsolationForest, an unsupervised anomaly detection algorithm, because:

- Real-world attack data is rarely labeled in advance
- Novel attack patterns evade signature-based rules
- Behavioral baselines adapt to the specific environment being monitored

The hybrid approach combines the precision of rule-based detection for known patterns with the adaptability of ML for unknown threats.

---

## Project Status

Active — developed as part of undergraduate cybersecurity research at the University of the Pacific.

---

## Author

Gorge Maya — Computer Science, University of the Pacific  
GitHub: github.com/gmaya129  
LinkedIn: linkedin.com/in/gorgemaya
