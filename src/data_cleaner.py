"""
Data cleaning and hygiene pipeline for CICIDS2017 dataset.
Handles infinities, missing values, column formatting, label consolidation,
leakage removal, and memory downcasting.
"""
import numpy as np
import pandas as pd
from typing import Tuple, List, Optional
from src.config import LEAKAGE_COLUMNS, LABEL_CONSOLIDATION_MAP, TARGET_COLUMN, RANDOM_STATE

def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strips whitespace and standardizes column names."""
    df.columns = df.columns.str.strip()
    return df

def drop_leakage_and_metadata(df: pd.DataFrame, extra_cols: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Drops features that lead to data leakage (IP addresses, Timestamps, Flow IDs).
    A robust IDS must generalize to traffic flow dynamics, not memorize IP addresses.
    """
    cols_to_drop = [c for c in LEAKAGE_COLUMNS if c in df.columns]
    if extra_cols:
        cols_to_drop.extend([c for c in extra_cols if c in df.columns])
    return df.drop(columns=cols_to_drop, errors="ignore")

def consolidate_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Consolidates sparse attack classes into the standardized 12-class format."""
    if TARGET_COLUMN not in df.columns:
        raise KeyError(f"Target column '{TARGET_COLUMN}' not found in dataframe.")
    
    # Strip string labels if needed
    if df[TARGET_COLUMN].dtype == "object":
        df[TARGET_COLUMN] = df[TARGET_COLUMN].astype(str).str.strip()
    
    df[TARGET_COLUMN] = df[TARGET_COLUMN].map(LABEL_CONSOLIDATION_MAP).fillna(df[TARGET_COLUMN])
    return df

def clean_inf_and_nulls(df: pd.DataFrame) -> pd.DataFrame:
    """
    Replaces +/- infinity with NaN and drops records with missing values.
    CICIDS2017 contains Flow Bytes/s and Flow Packets/s with division-by-zero infs.
    """
    df = df.replace([np.inf, -np.inf], np.nan)
    initial_rows = len(df)
    df = df.dropna()
    dropped_rows = initial_rows - len(df)
    print(f"Dropped {dropped_rows:,} rows containing NaN or Infinite values.")
    return df

def drop_zero_variance_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """
    Identifies and removes features with zero variance (single unique value).
    Constant features offer zero predictive power and inflate training time.
    """
    constant_features = [col for col in df.columns if col != TARGET_COLUMN and df[col].nunique() <= 1]
    if constant_features:
        print(f"Dropping {len(constant_features)} zero-variance features: {constant_features}")
        df = df.drop(columns=constant_features)
    return df, constant_features

def downcast_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """
    Downcasts float64 to float32 and int64 to int32.
    Reduces memory consumption by 50%+ in Google Colab.
    """
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype(np.float32)
    for col in df.select_dtypes(include=["int64"]).columns:
        df[col] = df[col].astype(np.int32)
    return df

def run_full_cleaning_pipeline(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """
    Executes the end-to-end cleaning and hygiene pipeline.
    """
    print(f"Initial shape: {df.shape}")
    df = clean_column_names(df)
    df = drop_leakage_and_metadata(df)
    df = consolidate_labels(df)
    df = clean_inf_and_nulls(df)
    df, dropped_constants = drop_zero_variance_features(df)
    df = downcast_dtypes(df)
    print(f"Cleaned shape: {df.shape}")
    print(f"Classes present ({df[TARGET_COLUMN].nunique()}): {df[TARGET_COLUMN].unique().tolist()}")
    return df, dropped_constants

def create_stratified_sample(df: pd.DataFrame, n_samples: int = 200000) -> pd.DataFrame:
    """
    Extracts a representative stratified sample for rapid experimentation in Colab.
    Guarantees that ultra-rare attack classes are preserved proportionally.
    """
    if len(df) <= n_samples:
        return df
    
    # Calculate sample fraction
    frac = n_samples / len(df)
    sample_df = df.groupby(TARGET_COLUMN, group_keys=False).apply(
        lambda x: x.sample(max(min(len(x), 50), int(len(x) * frac)), random_state=RANDOM_STATE)
    )
    return sample_df.reset_index(drop=True)
