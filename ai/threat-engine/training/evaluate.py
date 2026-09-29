import os
import json
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)
from .config import LABEL2ID, ID2LABEL

def compute_evaluation_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    id2label: Dict[int, str] = None,
) -> Dict[str, Any]:
    """
    Compute comprehensive classification metrics for multi-class threat model.
    Returns dictionary with overall metrics, per-class breakdown, and confusion matrix.
    """
    id2lbl = id2label or ID2LABEL
    classes = sorted(list(id2lbl.keys()))
    target_names = [id2lbl[idx] for idx in classes]

    acc = float(accuracy_score(y_true, y_pred))

    # Macro and Weighted metrics
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    # Per-class metrics
    p_per_class, r_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )

    per_class_dict = {}
    for idx, name in enumerate(target_names):
        per_class_dict[name] = {
            "label_id": classes[idx],
            "precision": round(float(p_per_class[idx]), 4),
            "recall": round(float(r_per_class[idx]), 4),
            "f1": round(float(f1_per_class[idx]), 4),
            "support": int(support_per_class[idx]),
        }

    # Confusion matrix: rows = true labels, columns = predicted labels
    cm = confusion_matrix(y_true, y_pred, labels=classes).tolist()

    return {
        "accuracy": round(acc, 4),
        "macro_precision": round(float(p_macro), 4),
        "macro_recall": round(float(r_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_precision": round(float(p_weighted), 4),
        "weighted_recall": round(float(r_weighted), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "per_class": per_class_dict,
        "confusion_matrix": cm,
        "class_labels": target_names,
    }

def save_evaluation_artifacts(
    metrics: Dict[str, Any],
    output_dir: str,
) -> Dict[str, str]:
    """
    Save evaluation results to machine-readable JSON and CSV files.
    Optional confusion matrix plot saved if matplotlib is available.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved_files = {}

    # 1. Save metrics.json
    json_path = os.path.join(output_dir, "metrics.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    saved_files["metrics_json"] = json_path

    # 2. Save class_metrics.csv
    if "per_class" in metrics:
        rows = []
        for class_name, vals in metrics["per_class"].items():
            row = {"class": class_name, **vals}
            rows.append(row)
        class_df = pd.DataFrame(rows)
        csv_path = os.path.join(output_dir, "class_metrics.csv")
        class_df.to_csv(csv_path, index=False)
        saved_files["class_metrics_csv"] = csv_path

    # 3. Optional confusion matrix plot
    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt

        cm = np.array(metrics["confusion_matrix"])
        labels = metrics["class_labels"]

        fig, ax = plt.subplots(figsize=(6, 5))
        cax = ax.matshow(cm, cmap="Blues")
        fig.colorbar(cax)

        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="left")
        ax.set_yticklabels(labels)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_title("Confusion Matrix", pad=20)

        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", color="black")

        plt.tight_layout()
        plot_path = os.path.join(output_dir, "confusion_matrix.png")
        plt.savefig(plot_path, dpi=150)
        plt.close(fig)
        saved_files["confusion_matrix_png"] = plot_path
    except Exception:
        # Plotting is optional; ignore if matplotlib is absent
        pass

    return saved_files

def hf_compute_metrics(eval_pred):
    """Callback for Hugging Face Trainer evaluation."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    metrics = compute_evaluation_metrics(labels, preds)
    return {
        "accuracy": metrics["accuracy"],
        "precision": metrics["macro_precision"],
        "recall": metrics["macro_recall"],
        "f1": metrics["macro_f1"],
        "macro_f1": metrics["macro_f1"],
        "weighted_f1": metrics["weighted_f1"],
        "weighted_precision": metrics["weighted_precision"],
        "weighted_recall": metrics["weighted_recall"],
    }
