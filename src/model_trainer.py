"""
Model training module for Network Intrusion Detection System.
Provides stratified splitting, preprocessing pipeline, baseline models,
ensemble classifiers, and artifact serialization.
"""
import joblib
import json
from pathlib import Path
from typing import Dict, Any, Tuple, List
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import lightgbm as lgb

from src.config import RANDOM_STATE, TARGET_COLUMN, MODELS_DIR

def prepare_train_test_split(
    df: pd.DataFrame,
    test_size: float = 0.20,
    val_size: float = 0.10
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series, LabelEncoder]:
    """
    Performs stratified Train-Validation-Test splitting.
    Stratification is essential due to acute class imbalance.
    """
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # First split: Train+Val vs Test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y_encoded, test_size=test_size, random_state=RANDOM_STATE, stratify=y_encoded
    )

    # Second split: Train vs Val (from Train+Val)
    relative_val_size = val_size / (1.0 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=relative_val_size, random_state=RANDOM_STATE, stratify=y_train_val
    )

    return X_train, X_val, X_test, y_train, y_val, y_test, le

def get_candidate_models(n_classes: int) -> Dict[str, Any]:
    """
    Returns a dictionary of candidate models ranging from sanity baselines
    to production-grade gradient boosted decision trees.
    """
    models = {
        "Baseline_Majority": DummyClassifier(strategy="most_frequent"),
        "Logistic_Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),
        "Decision_Tree": DecisionTreeClassifier(
            max_depth=15,
            class_weight="balanced",
            random_state=RANDOM_STATE
        ),
        "Random_Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=150,
            learning_rate=0.08,
            num_leaves=63,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
            verbosity=-1
        )
    }
    return models

def save_model_artifacts(
    model: Any,
    scaler: StandardScaler,
    label_encoder: LabelEncoder,
    feature_names: List[str],
    output_dir: Path = MODELS_DIR,
    model_name: str = "lightgbm_nids_model.joblib"
) -> Path:
    """
    Serializes model artifacts including the fitted scaler, label encoder,
    and exact feature column schema for safe deployment in Streamlit.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_payload = {
        "model": model,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "feature_names": feature_names,
        "classes": label_encoder.classes_.tolist()
    }
    model_path = output_dir / model_name
    joblib.dump(artifact_payload, model_path)
    
    # Save metadata JSON for lightweight inspection
    metadata = {
        "num_features": len(feature_names),
        "feature_names": feature_names,
        "classes": label_encoder.classes_.tolist(),
        "model_type": type(model).__name__
    }
    with open(output_dir / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"Artifact successfully saved to {model_path}")
    return model_path
