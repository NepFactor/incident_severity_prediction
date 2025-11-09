# Incident Severity Prediction Using Naïve Bayes

This repository contains the code and data for the project:

**Incident Severity Prediction Using Naïve Bayes Classification of Windows Security Events**

by **Nephi Nielsen** and **Daniel Sancho Arbizu**  
Mathematics for Data Science and AI, University of Denver (2025).

## Overview

Security Operations Centers (SOCs) ingest large volumes of Windows Security logs and must quickly distinguish benign activity from potentially high-impact incidents.  
This project demonstrates how a simple, interpretable **Naïve Bayes classifier** can be used to predict incident severity (Low / Medium / High) from engineered features derived from Windows Security event logs.

The pipeline:

1. Parse and normalize raw Windows Security log data.
2. Engineer features that capture key security-relevant signals.
3. Apply rule-based labeling to define incident severity.
4. Train and evaluate a Gaussian Naïve Bayes classifier.
5. Inspect accuracy, confusion matrix, and posterior probabilities.

## Repository Contents

- `build_windows_incidents.py`  
  Parses `windows-security.txt` into structured events and computes:
  `event_id`, `privileged_logon`, `admin_group_touch`, `suspicious_process`,
  `time_bucket`, and `burst_count`. Outputs `windows_incidents.csv`.

- `train_naive_bayes_incidents.py`  
  Loads the labeled CSV, performs a 70/30 train-test split, trains a Naïve Bayes classifier,
  and prints:
  - overall accuracy,
  - confusion matrix,
  - per-class precision/recall,
  - example posterior probabilities.

- `windows-security.txt`  
  Sample Windows Security log file derived from public attack simulation data.

- `windows_incidents.csv`  
  Processed dataset with engineered features and severity labels
  (Low / Medium / High) used for training and evaluation.

- `example_output.txt`  
  Example console output from running `train_naive_bayes_incidents.py`
  showing the achieved performance on this dataset.
