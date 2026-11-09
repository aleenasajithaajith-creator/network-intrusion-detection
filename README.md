# Network Intrusion Detection System Using Supervised Machine Learning

Author: Aleena S Ajith  
Dataset: CICIDS2017  
Status: In Progress (Day 1 - Data Cleaning, EDA, and Preprocessing Complete)

---

## Project Overview
The objective of this project is to develop a supervised machine learning classification model to identify network traffic flows as normal (BENIGN) or as various cyber attacks using the CICIDS2017 dataset.

---

## Day 1 Milestones

All tasks were executed, verified, and saved in Google Colab:

### 1. Data Cleaning and Ingestion
- Extracted and combined all 8 raw CSV files of CICIDS2017 into a single dataframe (2,830,743 rows and 79 columns).
- Downcasted float64 features to float32 to optimize memory in Google Colab.
- Replaced infinite values caused by zero-duration division with NaN and removed 2,867 corrupted rows.
- Standardized target attack labels into 12 clean multiclass categories.
- Removed 8 constant columns with zero variance (Bwd PSH Flags, Bwd URG Flags, etc.).
- Removed 329,691 duplicate rows and filtered out negative flow duration values.
- Cleaned dataset shape: 2,498,078 rows and 71 columns.

### 2. Exploratory Data Analysis (EDA)
- Plotted the distribution of the 12 traffic classes on a logarithmic scale to account for class imbalance (BENIGN vs minority attacks).
- Inspected data types: verified 70 numerical features and 1 categorical target column.
- Performed outlier detection across the three pillars of network traffic (Size: Packet Length Mean, Volume: Total Forward Packets, Time: Flow Duration) using boxplots.
- Generated a correlation heatmap for key network flow features to analyze bivariate relationships.

### 3. Data Preparation for Machine Learning
- Applied LabelEncoder to map the 12 text classes into integer labels (0 to 11).
- Separated features (X: 70 columns) and target (y: 1 column).
- Conducted Stratified Train-Test Split (80% training set: 1,998,462 rows; 20% testing set: 499,616 rows) with stratify=y to preserve class distribution across splits.
- Applied StandardScaler fitted strictly on X_train and transformed X_test to prevent data snooping.

---

## Repository Structure (Day 1)
```
├── .gitignore
├── README.md
└── notebooks/
    └── 01_CICIDS2017_Data_Cleaning.ipynb
```
