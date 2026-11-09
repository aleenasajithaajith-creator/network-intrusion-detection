# Network Intrusion Detection System Using Supervised Machine Learning

**Author:** Aleena S Ajith  
**Dataset:** CICIDS2017  
**Status:** In Progress (Day 1 - Data Cleaning Complete)

---

## 📌 Project Overview
The objective of this project is to develop a supervised machine learning classification system that accurately identifies network traffic flows as normal (**BENIGN**) or as different types of **network cyber attacks** using the **CICIDS2017** benchmark dataset.

---

## 📅 Day 1 Milestone: Data Cleaning & Preprocessing (Task 1)

All data preprocessing steps were executed and validated in Google Colab:

1. **Dataset Ingestion & Memory Optimization:**
   - Unpacked and merged all 8 raw CSV files containing 2,830,743 network flows and 79 features.
   - Downcasted numeric datatypes from `float64` to `float32` to avoid Colab RAM exhaustion.

2. **Handling Infinite & Missing Values:**
   - Handled division-by-zero errors in flow rate calculations by replacing `inf` with `NaN`.
   - Removed 2,867 corrupted rows containing missing values.

3. **Standardizing to 12 Multiclass Categories:**
   - Addressed class imbalance and sample starvation by grouping sparse web attacks (`Sql Injection`, `XSS`, `Brute Force`) into a unified **`Web Attack`** class.
   - Consolidated `Heartbleed` (11 samples) into **`Infiltration`**.
   - Result: Exactly 12 statistically balanced attack classes.

4. **Zero-Variance Feature Elimination:**
   - Identified and removed 8 constant columns with zero variance (`Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Avg Bytes/Bulk`, etc.) that provide no discriminative information.
   - Final clean dataset shape: **2,827,876 rows and 71 columns**.

---

## 📂 Repository Structure (Day 1)
```
├── .gitignore
├── README.md
└── notebooks/
    └── 01_CICIDS2017_Data_Cleaning.ipynb  # Task 1 Colab Notebook
```
