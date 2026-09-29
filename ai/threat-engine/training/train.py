import os
import sys
import json
import inspect
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
)

# Robust path resolution for direct script, module, and package executions
_curr_file = Path(__file__).resolve()
_threat_engine_dir = _curr_file.parents[1]  # ai/threat-engine
_project_root = _curr_file.parents[3]       # workspace root

if str(_threat_engine_dir) not in sys.path:
    sys.path.insert(0, str(_threat_engine_dir))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

try:
    from .config import (
        LABEL2ID,
        ID2LABEL,
        NUM_LABELS,
        TrainingConfig,
        training_settings,
    )
    from .dataset import ThreatDataset
    from .evaluate import (
        compute_evaluation_metrics,
        save_evaluation_artifacts,
        hf_compute_metrics,
    )
except (ImportError, ValueError):
    from training.config import (
        LABEL2ID,
        ID2LABEL,
        NUM_LABELS,
        TrainingConfig,
        training_settings,
    )
    from training.dataset import ThreatDataset
    from training.evaluate import (
        compute_evaluation_metrics,
        save_evaluation_artifacts,
        hf_compute_metrics,
    )

logger = logging.getLogger("mailtrace-training")

class EmailDataset(Dataset):
    """
    Lightweight PyTorch Dataset for tokenized email threat samples.
    Seamlessly integrates with Hugging Face Trainer and DataCollatorWithPadding
    without requiring external dataset library dependencies.
    """

    def __init__(
        self,
        texts: List[str],
        labels: List[int],
        tokenizer: Any,
        max_length: int = 512,
    ):
        self.encodings = tokenizer(
            texts,
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        self.labels = labels

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        item = {key: self.encodings[key][idx] for key in self.encodings}
        item["labels"] = self.labels[idx]
        return item

def build_training_arguments(
    config: TrainingConfig,
    checkpoint_dir: Optional[str] = None,
) -> TrainingArguments:
    """Build production-grade TrainingArguments derived from config."""
    ckpt_dir = checkpoint_dir or os.path.join(config.MAILTRACE_OUTPUT_DIR, "checkpoints")
    use_cpu_flag = (config.resolved_device == "cpu")

    return TrainingArguments(
        output_dir=ckpt_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=config.MAILTRACE_TRAIN_LEARNING_RATE,
        per_device_train_batch_size=config.MAILTRACE_TRAIN_BATCH_SIZE,
        per_device_eval_batch_size=config.MAILTRACE_EVAL_BATCH_SIZE,
        num_train_epochs=config.MAILTRACE_TRAIN_EPOCHS,
        weight_decay=config.MAILTRACE_WEIGHT_DECAY,
        warmup_steps=config.MAILTRACE_WARMUP_STEPS,
        seed=config.MAILTRACE_TRAIN_SEED,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_strategy="epoch",
        use_cpu=use_cpu_flag,
        report_to="none",
        save_total_limit=2,
    )

def run_training(config: Optional[TrainingConfig] = None) -> Dict[str, Any]:
    """
    Execute full fine-tuning pipeline for RoBERTa threat classification:
    1. Dataset verification and loading via ThreatDataset.
    2. Validation of schema and strict 4-class taxonomy.
    3. Deterministic stratified 70/15/15 split with seed 42.
    4. Tokenizer & model initialization for 4 canonical classes.
    5. Training & validation evaluation using Hugging Face Trainer.
    6. Final evaluation on held-out test partition.
    7. Artifact persistence (model, tokenizer, metrics, sanitized metadata).
    """
    cfg = config or training_settings
    logger.info(f"Initiating MAILTRACE training orchestration with base model '{cfg.MAILTRACE_BASE_MODEL}'...")

    # 1. Dataset Verification & Ingestion
    if not os.path.exists(cfg.MAILTRACE_DATA_PATH):
        err_msg = (
            f"Training dataset not found at configured path '{cfg.MAILTRACE_DATA_PATH}'. "
            "A real email threat dataset is required for training. "
            "Ensure a valid CSV exists at this location or configure MAILTRACE_DATA_PATH."
        )
        logger.error(err_msg)
        raise FileNotFoundError(err_msg)

    dataset_handler = ThreatDataset(data_path=cfg.MAILTRACE_DATA_PATH)
    _, cleaning_report = dataset_handler.load_and_preprocess()

    logger.info(
        f"Dataset loaded: {cleaning_report.get('final_rows', 0)} samples retained "
        f"({cleaning_report.get('duplicates_removed', 0)} duplicates removed, "
        f"{cleaning_report.get('null_removed', 0)} nulls removed)."
    )

    # 2. Stratified Train / Val / Test Split (70/15/15)
    train_df, val_df, test_df, split_summary = dataset_handler.split_data(
        seed=cfg.MAILTRACE_TRAIN_SEED,
        train_ratio=cfg.MAILTRACE_TRAIN_SPLIT,
        val_ratio=cfg.MAILTRACE_VAL_SPLIT,
        test_ratio=cfg.MAILTRACE_TEST_SPLIT,
    )

    logger.info(
        f"Stratified split complete: {len(train_df)} train, {len(val_df)} val, {len(test_df)} test samples "
        f"(random seed: {cfg.MAILTRACE_TRAIN_SEED})."
    )

    # 3. Tokenizer & Dataset Wrapping
    logger.info(f"Loading tokenizer for base model '{cfg.MAILTRACE_BASE_MODEL}'...")
    tokenizer = AutoTokenizer.from_pretrained(cfg.MAILTRACE_BASE_MODEL)

    train_dataset = EmailDataset(
        texts=train_df["text"].tolist(),
        labels=train_df["label_id"].tolist(),
        tokenizer=tokenizer,
        max_length=cfg.MAILTRACE_MODEL_MAX_LENGTH,
    )
    val_dataset = EmailDataset(
        texts=val_df["text"].tolist(),
        labels=val_df["label_id"].tolist(),
        tokenizer=tokenizer,
        max_length=cfg.MAILTRACE_MODEL_MAX_LENGTH,
    )
    test_dataset = EmailDataset(
        texts=test_df["text"].tolist(),
        labels=test_df["label_id"].tolist(),
        tokenizer=tokenizer,
        max_length=cfg.MAILTRACE_MODEL_MAX_LENGTH,
    )

    # 4. Model Initialization (Exactly 4 Classes)
    logger.info(
        f"Initializing AutoModelForSequenceClassification ({NUM_LABELS} labels) on device '{cfg.resolved_device}'..."
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        cfg.MAILTRACE_BASE_MODEL,
        num_labels=NUM_LABELS,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    # 5. Trainer Initialization
    training_args = build_training_arguments(cfg)
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer_kwargs = {
        "model": model,
        "args": training_args,
        "train_dataset": train_dataset,
        "eval_dataset": val_dataset,
        "data_collator": data_collator,
        "compute_metrics": hf_compute_metrics,
    }
    trainer_init_params = inspect.signature(Trainer.__init__).parameters
    if "processing_class" in trainer_init_params:
        trainer_kwargs["processing_class"] = tokenizer
    elif "tokenizer" in trainer_init_params:
        trainer_kwargs["tokenizer"] = tokenizer

    trainer = Trainer(**trainer_kwargs)

    # 6. Training & Validation Execution
    logger.info("Executing model training...")
    trainer.train()
    val_eval_metrics = trainer.evaluate()
    logger.info(f"Validation evaluation: {val_eval_metrics}")

    # 7. Held-out Test Partition Evaluation
    logger.info("Evaluating on held-out test partition...")
    predictions_output = trainer.predict(test_dataset)
    y_pred = np.argmax(predictions_output.predictions, axis=-1)
    y_true = np.array(test_df["label_id"].tolist())
    test_metrics = compute_evaluation_metrics(y_true, y_pred, id2label=ID2LABEL)
    logger.info(
        f"Test metrics: Accuracy={test_metrics.get('accuracy')}, "
        f"Macro-F1={test_metrics.get('macro_f1')}, "
        f"Weighted-F1={test_metrics.get('weighted_f1')}"
    )

    # 8. Artifact Persistence
    os.makedirs(cfg.MAILTRACE_OUTPUT_DIR, exist_ok=True)
    os.makedirs(cfg.MAILTRACE_METRICS_DIR, exist_ok=True)

    # Save test metrics and breakdown artifacts
    saved_metrics_files = save_evaluation_artifacts(test_metrics, cfg.MAILTRACE_METRICS_DIR)

    # Save final model weights and tokenizer to configured path
    logger.info(f"Saving final trained model and tokenizer to '{cfg.sanitized_output_dir}'...")
    trainer.save_model(cfg.MAILTRACE_OUTPUT_DIR)
    tokenizer.save_pretrained(cfg.MAILTRACE_OUTPUT_DIR)

    # Save training reproducibility metadata (sanitized, no secrets or personal filesystem paths)
    metadata_path = os.path.join(cfg.MAILTRACE_OUTPUT_DIR, "training_metadata.json")
    training_metadata = {
        "base_model": cfg.MAILTRACE_BASE_MODEL,
        "model_output_dir": cfg.sanitized_output_dir,
        "seed": cfg.MAILTRACE_TRAIN_SEED,
        "device_used": cfg.resolved_device,
        "num_labels": NUM_LABELS,
        "taxonomy": LABEL2ID,
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "split_ratios": {
            "train": cfg.MAILTRACE_TRAIN_SPLIT,
            "val": cfg.MAILTRACE_VAL_SPLIT,
            "test": cfg.MAILTRACE_TEST_SPLIT,
        },
        "hyperparameters": {
            "epochs": cfg.MAILTRACE_TRAIN_EPOCHS,
            "batch_size": cfg.MAILTRACE_TRAIN_BATCH_SIZE,
            "learning_rate": cfg.MAILTRACE_TRAIN_LEARNING_RATE,
            "weight_decay": cfg.MAILTRACE_WEIGHT_DECAY,
            "warmup_ratio": cfg.MAILTRACE_WARMUP_RATIO,
            "max_length": cfg.MAILTRACE_MODEL_MAX_LENGTH,
        },
        "cleaning_report": cleaning_report,
        "test_metrics": {
            "accuracy": test_metrics.get("accuracy"),
            "macro_f1": test_metrics.get("macro_f1"),
            "weighted_f1": test_metrics.get("weighted_f1"),
        },
        "saved_metrics_artifacts": {k: os.path.basename(v) for k, v in saved_metrics_files.items()},
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(training_metadata, f, indent=2)

    logger.info("Training pipeline completed successfully.")
    return {
        "status": "completed",
        "model_output_dir": cfg.sanitized_output_dir,
        "test_metrics": test_metrics,
        "metadata_file": os.path.basename(metadata_path),
    }

# Convenient functional alias
train = run_training

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    try:
        run_training()
    except FileNotFoundError as fnf:
        logger.error(f"Cannot start training: {fnf}")
        sys.exit(1)
    except Exception as exc:
        logger.error(f"Training run failed: {exc}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
