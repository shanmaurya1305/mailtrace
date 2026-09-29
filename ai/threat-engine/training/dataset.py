import os
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from .config import LABEL2ID, ID2LABEL, training_settings
from .preprocess import clean_dataset

class ThreatDataset:
    """Encapsulates raw data loading, stratified splitting, and PyTorch dataset prep."""

    def __init__(self, data_path: str = None):
        self.data_path = data_path or training_settings.MAILTRACE_DATA_PATH
        self.df: pd.DataFrame = pd.DataFrame()
        self.cleaning_report: Dict[str, Any] = {}
        self.train_df: pd.DataFrame = pd.DataFrame()
        self.val_df: pd.DataFrame = pd.DataFrame()
        self.test_df: pd.DataFrame = pd.DataFrame()

    def load_and_preprocess(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Load CSV and apply preprocessing & label validation."""
        if not os.path.exists(self.data_path):
            raise FileNotFoundError(
                f"Training dataset not found at '{self.data_path}'.\n"
                f"Please provide a CSV with columns: 'text' (or 'subject' and 'body') and 'label'.\n"
                f"Allowed labels: {list(LABEL2ID.keys())}."
            )

        raw_df = pd.read_csv(self.data_path)
        if raw_df.empty:
            raise ValueError(f"Dataset at '{self.data_path}' is empty.")

        self.df, self.cleaning_report = clean_dataset(raw_df)
        if len(self.df) < len(LABEL2ID) * 2:
            raise ValueError(
                f"Dataset contains only {len(self.df)} valid samples. "
                f"At least {len(LABEL2ID) * 2} samples are required for stratified train/val/test splits."
            )

        return self.df, self.cleaning_report

    def calculate_class_distribution(self, df: pd.DataFrame = None) -> Dict[str, Any]:
        """Compute sample count and percentage per label."""
        target_df = self.df if df is None else df
        total = len(target_df)
        if total == 0:
            return {"total_samples": 0, "classes": {}}

        counts = target_df["label"].value_counts().to_dict()
        distribution = {}
        for label_name in LABEL2ID.keys():
            cnt = int(counts.get(label_name, 0))
            pct = round((cnt / total) * 100, 2)
            distribution[label_name] = {"count": cnt, "percentage": pct}

        return {
            "total_samples": total,
            "classes": distribution,
        }

    def split_data(
        self,
        seed: int = None,
        train_ratio: float = None,
        val_ratio: float = None,
        test_ratio: float = None,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
        """
        Split dataset into train, val, and test partitions with stratification.
        Default: 70% train, 15% validation, 15% test.
        """
        if self.df.empty:
            self.load_and_preprocess()

        seed = seed if seed is not None else training_settings.MAILTRACE_TRAIN_SEED
        train_r = train_ratio if train_ratio is not None else training_settings.MAILTRACE_TRAIN_SPLIT
        val_r = val_ratio if val_ratio is not None else training_settings.MAILTRACE_VAL_SPLIT
        test_r = test_ratio if test_ratio is not None else training_settings.MAILTRACE_TEST_SPLIT

        if not np.isclose(train_r + val_r + test_r, 1.0):
            raise ValueError(f"Train ({train_r}), Val ({val_r}), and Test ({test_r}) ratios must sum to 1.0.")

        # Check each class has at least 2 samples for stratification
        class_counts = self.df["label_id"].value_counts()
        min_class_count = class_counts.min()
        if min_class_count < 2:
            raise ValueError(
                f"Cannot perform stratified split: class '{ID2LABEL[class_counts.idxmin()]}' "
                f"has only {min_class_count} sample(s). Minimum is 2."
            )

        # 1. First split: Train vs (Val + Test)
        eval_ratio = val_r + test_r
        train_df, eval_df = train_test_split(
            self.df,
            test_size=eval_ratio,
            random_state=seed,
            stratify=self.df["label_id"],
        )

        # 2. Second split: Val vs Test
        val_share = val_r / eval_ratio
        val_df, test_df = train_test_split(
            eval_df,
            test_size=(1.0 - val_share),
            random_state=seed,
            stratify=eval_df["label_id"],
        )

        self.train_df = train_df.reset_index(drop=True)
        self.val_df = val_df.reset_index(drop=True)
        self.test_df = test_df.reset_index(drop=True)

        # Leakage prevention: verify zero overlapping content hashes across partitions
        leakage_detected = False
        if "content_hash" in self.df.columns:
            tr_hashes = set(self.train_df["content_hash"])
            va_hashes = set(self.val_df["content_hash"])
            te_hashes = set(self.test_df["content_hash"])
            if tr_hashes.intersection(va_hashes) or tr_hashes.intersection(te_hashes) or va_hashes.intersection(te_hashes):
                leakage_detected = True
                raise ValueError("Data leakage detected: identical content hashes appear across train/val/test splits.")

        summary = {
            "seed": seed,
            "train_samples": len(self.train_df),
            "val_samples": len(self.val_df),
            "test_samples": len(self.test_df),
            "leakage_detected": leakage_detected,
            "train_distribution": self.calculate_class_distribution(self.train_df),
            "val_distribution": self.calculate_class_distribution(self.val_df),
            "test_distribution": self.calculate_class_distribution(self.test_df),
        }

        return self.train_df, self.val_df, self.test_df, summary

    def compute_class_weights(self) -> Dict[int, float]:
        """
        Compute inverse class weights strictly from the TRAINING set.
        Never touches validation or test samples.
        Formula: weight = total_samples / (num_classes * class_count)
        """
        if self.train_df.empty:
            raise ValueError("Training split is empty. Call split_data() first.")

        total_train = len(self.train_df)
        num_classes = len(LABEL2ID)
        counts = self.train_df["label_id"].value_counts().to_dict()

        weights = {}
        for class_id in range(num_classes):
            c_count = counts.get(class_id, 0)
            if c_count > 0:
                weights[class_id] = total_train / (num_classes * c_count)
            else:
                weights[class_id] = 1.0

        return weights
