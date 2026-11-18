# NIDS Test Sample Datasets Guide

This folder contains pre-configured test CSV files extracted from the authentic CICIDS2017 benchmark dataset for testing the Network Intrusion Detection System Web Application.

---

## Summary of Available Test Datasets

| File Name | Primary Traffic Class | Number of Flows | Ground Truth Label Included? | Expected App Detection |
| :--- | :--- | :---: | :---: | :--- |
| `01_Benign_Normal_Traffic.csv` | Normal Traffic (HTTP, DNS, HTTPS) | 25 | Yes (`BENIGN`) | Normal Traffic / Safe |
| `02_DDoS_Attack_Traffic.csv` | DDoS Volumetric Attack | 20 | Yes (`DDoS`) | 100% Threat Detected (`DDoS`) |
| `03_PortScan_Attack_Traffic.csv` | PortScan Reconnaissance Probe | 20 | Yes (`PortScan`) | Threat Detected (`PortScan`) |
| `04_DoS_Hulk_Attack_Traffic.csv` | DoS Hulk (Web Application Flood) | 20 | Yes (`DoS Hulk`) | 95% Threat Detected (`DoS Hulk`) |
| `05_FTP_Patator_BruteForce.csv` | FTP Credential Brute Force | 20 | Yes (`FTP-Patator`) | 95% Threat Detected (`FTP-Patator`) |
| `06_SSH_Patator_BruteForce.csv` | SSH Credential Brute Force | 15 | Yes (`SSH-Patator`) | 100% Threat Detected (`SSH-Patator`) |
| `07_DoS_GoldenEye_Attack.csv` | DoS GoldenEye HTTP Exhaustion | 15 | Yes (`DoS GoldenEye`) | 100% Threat Detected (`DoS GoldenEye`) |
| `08_Mixed_Traffic_MultiClass.csv` | Multiclass Mix (Normal + 5 Attacks) | 50 | Yes (Individual per flow) | Multiclass Threat Breakdown |
| `09_Unlabeled_Live_Capture.csv` | Unlabeled Simulated Live Sniffer Capture | 30 | No (Pure 70 Features) | Live Classification on Unknown Traffic |

---

## How to Verify That a CSV Belongs to a Specific Class

You can verify the class of any test file in two ways:

### 1. Directly in the File
- Files `01` through `08` contain a dedicated column named **`Ground_Truth_Label`**.
- You can open any of these CSV files in Excel, VS Code, or Notepad and check the `Ground_Truth_Label` column to see the exact class assigned to each packet in the benchmark.

### 2. In the Web Application
- When you upload any of files `01` through `08` into the app:
  1. **Ground Truth Banner:** The app automatically detects `Ground_Truth_Label` and displays a green banner showing the overall batch accuracy (e.g., `100.00% (20/20 flows matched perfectly)`).
  2. **Detailed Flow Inspection Table:** In the table, the app places `Actual_Ground_Truth` right next to `Predicted_Class` along with a `Validation_Match` column (`MATCH` or `MISMATCH`), allowing you to verify row-by-row that the model accurately detected the class.
- When you upload `09_Unlabeled_Live_Capture.csv`:
  - The app treats it as raw unclassified network traffic, predicts the threat category for every packet, and displays the distribution.
