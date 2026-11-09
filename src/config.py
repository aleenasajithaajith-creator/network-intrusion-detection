"""
Configuration module for Network Intrusion Detection System (CICIDS2017).
Defines paths, feature column rules, class mappings, and hyperparameters.
"""
import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

# Reproducibility
RANDOM_STATE = 42

# Columns that cause Data Leakage or have zero analytical value for generalized packet inspection:
# Source IP / Dest IP: Model memorizes attacker/victim IP instead of packet behavior.
# Timestamp: Model overfits to attack execution schedule.
# Flow ID: Synthetic compound key.
LEAKAGE_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Src IP",
    "Source Port",
    "Destination IP",
    "Dst IP",
    "Timestamp",
    "SimillarHTTP"
]

# Standard 12 Class Consolidation Mapping
# Raw CICIDS2017 has 15 labels with acute sparsity in Web Attacks and Heartbleed.
LABEL_CONSOLIDATION_MAP = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS Hulk",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "DoS GoldenEye": "DoS GoldenEye",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS slowloris": "DoS slowloris",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "Bot": "Bot",
    "Web Attack \x96 Brute Force": "Web Attack",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack \x96 XSS": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack \x96 Sql Injection": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Infiltration": "Infiltration",
    "Heartbleed": "Infiltration"  # Consolidated due to extreme sparsity (11 samples in raw)
}

TARGET_COLUMN = "Label"
