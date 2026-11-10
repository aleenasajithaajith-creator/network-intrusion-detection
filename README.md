# Network Intrusion Detection System Using Supervised Machine Learning

Author: Aleena S Ajith  
Dataset: CICIDS2017  
Status: In Progress (Day 2 - Model Training and 3-Model Comparison Complete)

---

## Project Overview
The objective of this project is to develop a supervised machine learning classification model to identify network traffic flows as normal (BENIGN) or as various cyber attacks using the CICIDS2017 dataset.

---

## Day 1 Milestones (Completed)

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

## Day 2 Milestones: Supervised Model Training and Comparison

We trained and compared three supervised machine learning algorithms using cost-sensitive learning (class_weight='balanced') to address class imbalance without creating synthetic noise:

1. Model 1: Decision Tree Classifier (Baseline)
   - Rule-based single decision tree with max_depth=15.
   - Evaluated as a baseline benchmark.
   - Results: Accuracy: 98.19% | Macro F1-Score: 82.08%

2. Model 2: Random Forest Classifier (Bagging Ensemble)
   - Ensemble of 50 decision trees trained in parallel with majority voting.
   - Reduced variance on minority attack classes.
   - Results: Accuracy: 99.27% | Macro F1-Score: 90.04%

3. Model 3: LightGBM Classifier (Gradient Boosting)
   - Sequential gradient boosted decision trees with histogram binning.
   - Results: Accuracy: 95.24% | Macro F1-Score: 59.75%
   - Analysis: In extreme class imbalance (1:40,000 ratio), gradient-based balanced loss over-penalized majority errors and reduced precision on rare classes.

### 3-Model Comparison Summary Table

| Model Name | Accuracy (%) | Macro F1-Score (%) | Verdict |
| :--- | :--- | :--- | :--- |
| **Decision Tree (Baseline)** | 98.19% | 82.08% | Baseline Benchmark |
| **Random Forest (Bagging)** | **99.27%** | **90.04%** | **WINNER / Selected Champion** |
| **LightGBM (Boosting)** | 95.24% | 59.75% | Over-penalized rare classes |

**Selected Champion Model:** Random Forest Classifier (Accuracy: 99.27%, Macro F1-Score: 90.04%).

---

## Repository Structure
```
├── .gitignore
├── README.md
├── notebooks/
│   └── 01_CICIDS2017_Data_Cleaning.ipynb  # Contains Data Preprocessing, EDA, and Model Comparison
├── data/
├── models/
└── app/
```
