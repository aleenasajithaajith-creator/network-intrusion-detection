# Network Intrusion Detection System Using Supervised Machine Learning

Author: Aleena S Ajith  
Dataset: CICIDS2017  
Status: In Progress (Day 1 - Data Cleaning Complete)

---

## Project Overview
The objective of this project is to develop a supervised machine learning classification model to identify network traffic flows as normal (BENIGN) or as various cyber attacks using the CICIDS2017 dataset.

---

## Day 1 Milestone: Data Cleaning and Preprocessing (Task 1)

All data preprocessing steps were executed and verified in Google Colab:

1. Dataset Ingestion and Memory Optimization:
   - Extracted all 8 raw CSV files of CICIDS2017 and combined them into a master dataframe (2,830,743 rows and 79 columns).
   - Downcasted float64 features to float32 to reduce memory usage in Google Colab.

2. Handling Infinite and Missing Values:
   - Handled division-by-zero values in flow rates by replacing infinite values with NaN.
   - Removed 2,867 rows with missing or corrupted values.

3. Label Consolidation to 12 Multiclass Categories:
   - Grouped rare web attacks (Sql Injection, XSS, Brute Force) into a single Web Attack class.
   - Merged Heartbleed (11 instances) into Infiltration.
   - Standardized target labels into 12 clean classes.

4. Constant Feature Removal:
   - Dropped 8 zero-variance constant columns (Bwd PSH Flags, Bwd URG Flags, Fwd Avg Bytes/Bulk, etc.) that provided no predictive value.
   - Final cleaned dataset shape: 2,827,876 rows and 71 columns.

---

## Repository Structure (Day 1)
```
├── .gitignore
├── README.md
└── notebooks/
    └── 01_CICIDS2017_Data_Cleaning.ipynb
```
