import os
import sys
import tempfile
import json
from pathlib import Path
import pytest
import pandas as pd
import numpy as np
from unittest.mock import MagicMock, patch

# Locate project root and threat-engine dynamically
_curr = Path(__file__).resolve()
for _parent in _curr.parents:
    _candidate = _parent / "ai" / "threat-engine"
    if _candidate.is_dir():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break

from training.config import (
    LABEL2ID,
    ID2LABEL,
    NUM_LABELS,
    TrainingConfig,
    training_settings,
)
from training.preprocess import clean_dataset, assemble_email_text, normalize_whitespace
from training.dataset import ThreatDataset
from training.evaluate import compute_evaluation_metrics, hf_compute_metrics
from training.train import EmailDataset, build_training_arguments, run_training

# 1. Missing dataset produces a clear failure
def test_missing_dataset_produces_clear_failure():
    """Verify ThreatDataset raises FileNotFoundError with actionable instructions when file is absent."""
    missing_path = os.path.join("nonexistent", "path", "to", "dataset.csv")
    dataset = ThreatDataset(data_path=missing_path)
    with pytest.raises(FileNotFoundError) as exc_info:
        dataset.load_and_preprocess()
    assert "Training dataset not found" in str(exc_info.value)
    assert "Please provide a CSV with columns" in str(exc_info.value)
    assert "Allowed labels" in str(exc_info.value)

# 2. Training runner does not silently fabricate data when dataset is missing
def test_training_runner_missing_dataset_no_fabrication():
    """Verify run_training halts with FileNotFoundError and does not create synthetic files or weights."""
    missing_path = os.path.join("nonexistent", "path", "dataset.csv")
    cfg = TrainingConfig(MAILTRACE_DATA_PATH=missing_path)
    with pytest.raises(FileNotFoundError) as exc_info:
        run_training(cfg)
    assert "Training dataset not found at configured path" in str(exc_info.value)
    assert "A real email threat dataset is required for training" in str(exc_info.value)

# 3. Invalid label is rejected
def test_invalid_label_rejected():
    """Verify clean_dataset rejects unknown labels outside the canonical 4-class taxonomy."""
    raw_df = pd.DataFrame({
        "text": ["Suspicious malware attachment included"],
        "label": ["trojan_malware"]
    })
    with pytest.raises(ValueError) as exc_info:
        clean_dataset(raw_df)
    assert "Dataset contains unknown labels" in str(exc_info.value)
    assert "Allowed labels are" in str(exc_info.value)

# 4. Missing text and body is rejected
def test_missing_text_and_body_rejected():
    """Verify clean_dataset rejects datasets lacking both 'text' and 'body' columns."""
    raw_df = pd.DataFrame({
        "subject": ["Only subject without body"],
        "label": ["benign"]
    })
    with pytest.raises(ValueError) as exc_info:
        clean_dataset(raw_df)
    assert "Dataset must contain either a 'text' column or a 'body' column" in str(exc_info.value)

# 5. Missing label column is rejected
def test_missing_label_column_rejected():
    """Verify clean_dataset rejects datasets without a 'label' column."""
    raw_df = pd.DataFrame({
        "text": ["Email text content without classification"]
    })
    with pytest.raises(ValueError) as exc_info:
        clean_dataset(raw_df)
    assert "Dataset must contain a 'label' column" in str(exc_info.value)

# 6. Dataset schema validation, whitespace normalization, and deduplication
def test_dataset_schema_validation_and_cleaning():
    """Verify schema normalization, assembly of subject+body, and duplicate removal."""
    raw_df = pd.DataFrame({
        "subject": ["  Urgent Alert   ", "Duplicate Subject", "Duplicate Subject"],
        "body": ["Please verify   account   details.\n\n\n\nLink below.", "Same body text", "Same body text"],
        "label": ["phishing", "benign", "benign"]
    })
    cleaned_df, report = clean_dataset(raw_df)
    assert len(cleaned_df) == 2
    assert report["duplicates_removed"] == 1
    assert "label_id" in cleaned_df.columns
    assert cleaned_df.iloc[0]["label_id"] == LABEL2ID["phishing"]
    assert "Subject: Urgent Alert\n\nBody: Please verify account details.\n\nLink below." in cleaned_df.iloc[0]["text"]

# 7. Deterministic label mapping and 4-class taxonomy
def test_deterministic_label_mapping():
    """Verify the exact 4-class taxonomy mapping."""
    expected_mapping = {
        "benign": 0,
        "suspicious": 1,
        "phishing": 2,
        "business_email_compromise": 3,
    }
    assert LABEL2ID == expected_mapping
    assert NUM_LABELS == 4
    for label_name, idx in expected_mapping.items():
        assert ID2LABEL[idx] == label_name

# 8. Stratified split remains deterministic with seed 42
def test_stratified_split_deterministic_with_seed_42():
    """Verify stratified splitting produces identical deterministic splits across runs with seed 42."""
    rows = []
    for label_name in ["benign", "suspicious", "phishing", "business_email_compromise"]:
        for i in range(10):  # 10 samples per class = 40 samples total
            rows.append({"text": f"Sample {label_name} email {i}", "label": label_name, "label_id": LABEL2ID[label_name]})
    df = pd.DataFrame(rows)

    dataset1 = ThreatDataset()
    dataset1.df = df.copy()
    train1, val1, test1, summary1 = dataset1.split_data(seed=42)

    dataset2 = ThreatDataset()
    dataset2.df = df.copy()
    train2, val2, test2, summary2 = dataset2.split_data(seed=42)

    # Determinism check
    pd.testing.assert_frame_equal(train1, train2)
    pd.testing.assert_frame_equal(val1, val2)
    pd.testing.assert_frame_equal(test1, test2)

    # Ratio check (70% train = 28, 15% val = 6, 15% test = 6)
    assert len(train1) == 28
    assert len(val1) == 6
    assert len(test1) == 6

# 9. Output directory configuration and device resolution
def test_training_config_defaults_and_override():
    """Verify TrainingConfig loads default settings and respects overrides."""
    cfg = TrainingConfig()
    assert cfg.MAILTRACE_BASE_MODEL == "roberta-base"
    assert cfg.MAILTRACE_TRAIN_SEED == 42
    assert cfg.MAILTRACE_TRAIN_EPOCHS == 3
    assert cfg.MAILTRACE_TRAIN_BATCH_SIZE == 8
    assert cfg.MAILTRACE_TRAIN_LEARNING_RATE == 2e-5
    assert cfg.resolved_device in ["cpu", "cuda"]

    # Verify custom output directory configuration
    custom_cfg = TrainingConfig(MAILTRACE_OUTPUT_DIR="custom_models/target_threat_model")
    assert custom_cfg.sanitized_output_dir == "target_threat_model"
    assert "C:" not in custom_cfg.sanitized_output_dir

# 10. TrainingArguments builder configuration
def test_build_training_arguments():
    """Verify build_training_arguments creates valid TrainingArguments matching config."""
    cfg = TrainingConfig()
    args = build_training_arguments(cfg)
    assert args.num_train_epochs == 3
    assert args.per_device_train_batch_size == 8
    assert args.per_device_eval_batch_size == 8
    assert args.learning_rate == 2e-5
    assert args.metric_for_best_model == "macro_f1"
    assert args.greater_is_better is True
    assert args.seed == 42

# 11. PyTorch EmailDataset wrapper functionality
def test_email_dataset_pytorch_wrapper():
    """Verify EmailDataset tokenizes without external dependencies and exposes standard PyTorch interface."""
    mock_tokenizer = MagicMock()
    mock_tokenizer.return_value = {
        "input_ids": [[101, 102], [201, 202]],
        "attention_mask": [[1, 1], [1, 1]],
    }
    texts = ["Sample email one", "Sample email two"]
    labels = [0, 2]

    ds = EmailDataset(texts, labels, mock_tokenizer, max_length=128)
    assert len(ds) == 2

    item0 = ds[0]
    assert item0["input_ids"] == [101, 102]
    assert item0["labels"] == 0

    item1 = ds[1]
    assert item1["input_ids"] == [201, 202]
    assert item1["labels"] == 2

# 12. Evaluation metrics callback functionality
def test_evaluation_metrics_computation():
    """Verify compute_evaluation_metrics accurately computes accuracy, F1, and per-class breakdown."""
    y_true = np.array([0, 1, 2, 3, 0, 1, 2, 3])
    y_pred = np.array([0, 1, 2, 3, 0, 1, 2, 3])
    metrics = compute_evaluation_metrics(y_true, y_pred)
    assert metrics["accuracy"] == 1.0
    assert metrics["macro_f1"] == 1.0
    assert metrics["weighted_f1"] == 1.0
    assert "per_class" in metrics
    assert len(metrics["per_class"]) == 4

# 13. Training runner orchestration with isolated mocks (Zero internet access)
def test_training_runner_orchestration_mocked():
    """Verify run_training orchestrates loading, splitting, tokenizing, and saving with isolated mocks."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create minimal valid CSV in temporary directory
        data_csv = os.path.join(tmp_dir, "dataset.csv")
        output_dir = os.path.join(tmp_dir, "model_output")
        metrics_dir = os.path.join(tmp_dir, "metrics_output")

        rows = []
        for label_name in ["benign", "suspicious", "phishing", "business_email_compromise"]:
            for i in range(10):  # 10 samples per class allows proper stratified 70/15/15 split
                rows.append({"text": f"Email text {label_name} {i}", "label": label_name})
        pd.DataFrame(rows).to_csv(data_csv, index=False)

        cfg = TrainingConfig(
            MAILTRACE_DATA_PATH=data_csv,
            MAILTRACE_OUTPUT_DIR=output_dir,
            MAILTRACE_METRICS_DIR=metrics_dir,
        )

        mock_tokenizer = MagicMock()
        mock_tokenizer.return_value = {
            "input_ids": [[1, 2]],
            "attention_mask": [[1, 1]]
        }

        mock_model = MagicMock()
        mock_trainer = MagicMock()
        mock_trainer.train.return_value = MagicMock()
        mock_trainer.evaluate.return_value = {"eval_loss": 0.1, "eval_macro_f1": 0.95}

        # Predict output for 6 test samples (15% of 40 = 6)
        mock_pred_output = MagicMock()
        mock_pred_output.predictions = np.zeros((6, 4))
        mock_pred_output.predictions[:, 0] = 1.0
        mock_trainer.predict.return_value = mock_pred_output

        with patch("training.train.AutoTokenizer.from_pretrained", return_value=mock_tokenizer) as mock_tok_init, \
             patch("training.train.AutoModelForSequenceClassification.from_pretrained", return_value=mock_model) as mock_mod_init, \
             patch("training.train.Trainer", return_value=mock_trainer) as mock_trainer_cls:

            result = run_training(cfg)

            assert result["status"] == "completed"
            assert mock_tok_init.called
            # Verify model was initialized with exactly 4 labels and proper id2label/label2id
            mock_mod_init.assert_called_once_with(
                cfg.MAILTRACE_BASE_MODEL,
                num_labels=4,
                id2label=ID2LABEL,
                label2id=LABEL2ID,
            )
            assert mock_trainer.train.called
            assert mock_trainer.evaluate.called
            assert mock_trainer.save_model.called
            assert mock_tokenizer.save_pretrained.called

            # Verify training_metadata.json was saved without personal filesystem paths
            metadata_file = os.path.join(output_dir, "training_metadata.json")
            assert os.path.exists(metadata_file)
            with open(metadata_file, "r", encoding="utf-8") as f:
                saved_meta = json.load(f)
            assert saved_meta["num_labels"] == 4
            assert saved_meta["seed"] == 42
            assert "C:" not in saved_meta["model_output_dir"]
