# Network Intrusion Detection System Using Supervised Machine Learning

Author: Aleena S Ajith  
Dataset: CICIDS2017  
Status: In Progress (Day 2 - Model Training, Evaluation, and Pipeline Export Complete)

---

## Project Overview
The objective of this project is to develop a supervised machine learning classification model to identify network traffic flows as normal (BENIGN) or as various cyber attacks using the CICIDS2017 dataset.

---

## Day 1 Milestones (Data Preprocessing and EDA)

1. Data Cleaning and Ingestion:
   - Extracted all 8 raw CSV files of CICIDS2017 (2,830,743 rows and 79 columns).
   - Downcasted float64 features to float32 to reduce memory usage in Google Colab.
   - Handled infinite and missing values (removed 2,867 corrupted rows).
   - Standardized target labels into 12 clean multiclass categories.
   - Removed 8 zero-variance constant features.
   - Removed 329,691 duplicate rows and negative flow durations.
   - Cleaned dataset shape: 2,498,078 rows and 71 columns.

2. Exploratory Data Analysis (EDA):
   - Plotted the distribution of the 12 traffic classes on a logarithmic scale.
   - Performed outlier detection across the three pillars of network traffic (Size: Packet Length Mean, Volume: Total Forward Packets, Time: Flow Duration) using boxplots.
   - Generated a correlation heatmap for key network flow features.

3. Data Preparation for Machine Learning:
   - Applied LabelEncoder to map the 12 text classes into integer labels (0 to 11).
   - Separated features (X: 70 columns) and target (y: 1 column).
   - Conducted Stratified Train-Test Split (80% train: 1,998,462 rows; 20% test: 499,616 rows) with stratify=y.
   - Applied StandardScaler fitted strictly on X_train and transformed X_test.

---

## Day 2 Milestones: Supervised Model Training, Evaluation, and Model Export

### 1. 3-Model Training and Comparison
We trained and compared three supervised learning algorithms using cost-sensitive learning (class_weight='balanced') to handle class imbalance:
- **Decision Tree Classifier (Baseline):** Accuracy: 98.19% | Macro F1-Score: 82.08%
- **Random Forest Classifier (Bagging Ensemble):** Accuracy: 99.27% | Macro F1-Score: 90.04% (Winner / Champion Model)
- **LightGBM Classifier (Gradient Boosting):** Accuracy: 95.24% | Macro F1-Score: 59.75% (Over-penalized minority classes on extreme 1:40,000 imbalance ratio)

### 2. In-Depth Evaluation of Champion Model (Random Forest)
Evaluated on the unseen test set of 499,616 network flows:
- Overall Accuracy: 99.27%
- Macro-Averaged Recall: 96.70%
- Macro-Averaged F1-Score: 90.04%
- Per-Class Detection Highlights:
  - FTP-Patator: 100.00% precision, 100.00% recall
  - DDoS: 100.00% precision, 99.95% recall
  - DoS Hulk: 99.05% precision, 99.87% recall
  - PortScan: 98.90% precision, 99.92% recall
  - Web Attack: 79.00% precision, 99.07% recall
  - Infiltration: 100.00% precision, 66.67% recall (6 out of 9 stealth attacks caught with 0 false alarms)

### 3. Feature Importance Analysis
Identified the top most critical network features driving attack detection:
1. Destination Port (Service port targeted by attacks)
2. Init_Win_bytes_backward (TCP window size revealing automated attack tools)
3. Fwd Packet Length Max (Differentiating large payloads from probing packets)
4. Subflow Fwd Bytes
5. Average Packet Size

### 4. Model Pipeline Serialization
Exported the trained Random Forest classifier, fitted StandardScaler, and LabelEncoder into a single deployment file:
- `models/random_forest_nids_model.joblib` (11.3 MB)

---

## Repository Structure
```
├── .gitignore
├── README.md
├── notebooks/
│   └── 01_CICIDS2017_Data_Cleaning.ipynb  # End-to-end Preprocessing, EDA, Model Training, and Evaluation
├── models/
│   └── random_forest_nids_model.joblib   # Trained Champion Model Pipeline
├── data/
└── app/
```
