"""
Evaluation and error analysis suite for Network Intrusion Detection.
Computes Macro/Weighted F1, Precision, Recall, Confusion Matrix,
False Positive Rate (FPR), and False Negative Rate (FNR) per attack class.
"""
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, List
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score
)

def compute_intrusion_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    target_names: List[str]
) -> Dict[str, Any]:
    """
    Computes rigorous intrusion detection metrics.
    Highlights Macro F1, Weighted F1, and per-class FPR / FNR.
    """
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    macro_prec = precision_score(y_true, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average="macro", zero_division=0)

    # Detailed report dictionary
    report_dict = classification_report(
        y_true, y_pred, target_names=target_names, output_dict=True, zero_division=0
    )

    # Compute False Positive Rate (FPR) and False Negative Rate (FNR) from Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    class_metrics = {}
    
    for idx, class_name in enumerate(target_names):
        tp = cm[idx, idx]
        fn = np.sum(cm[idx, :]) - tp
        fp = np.sum(cm[:, idx]) - tp
        tn = np.sum(cm) - (tp + fp + fn)

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        class_metrics[class_name] = {
            "Precision": report_dict[class_name]["precision"],
            "Recall": report_dict[class_name]["recall"],
            "F1-Score": report_dict[class_name]["f1-score"],
            "FPR (Alert Fatigue)": fpr,
            "FNR (Undetected Risk)": fnr,
            "Support": report_dict[class_name]["support"]
        }

    return {
        "Accuracy": acc,
        "Macro_F1": macro_f1,
        "Weighted_F1": weighted_f1,
        "Macro_Precision": macro_prec,
        "Macro_Recall": macro_rec,
        "Confusion_Matrix": cm,
        "Per_Class_Analysis": pd.DataFrame.from_dict(class_metrics, orient="index")
    }

def plot_confusion_matrix(
    cm: np.ndarray,
    class_names: List[str],
    normalize: bool = True,
    save_path: str = None
):
    """
    Plots an annotated confusion matrix heatmap.
    Normalization reveals classification accuracy across minority classes.
    """
    if normalize:
        cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
        cm_norm = np.nan_to_num(cm_norm)
        fmt = ".2f"
        data_to_plot = cm_norm
        title = "Normalized Confusion Matrix (Recall per Class)"
    else:
        fmt = "d"
        data_to_plot = cm
        title = "Raw Confusion Matrix Counts"

    plt.figure(figsize=(12, 10))
    sns.heatmap(
        data_to_plot,
        annot=True,
        fmt=fmt,
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names
    )
    plt.title(title, fontsize=14, pad=15)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.ylabel("True Label", fontsize=12)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300)
        print(f"Confusion matrix saved to {save_path}")
    plt.close()
