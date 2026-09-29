import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

# Setup path resolution for both direct script and module execution
_curr_file = Path(__file__).resolve()
_threat_engine_dir = _curr_file.parents[2]
_project_root = _curr_file.parents[4]

for _p in [str(_threat_engine_dir), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from training.config import LABEL2ID

logger = logging.getLogger("mailtrace-dataset-validate")

CANONICAL_COLUMNS = [
    "id",
    "text",
    "subject",
    "body",
    "label",
    "label_id",
    "source",
    "source_label",
    "source_reference",
    "content_hash",
]

DEFAULT_SOURCES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "sources.json"
)

DEFAULT_DATASET_CSV = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "dataset.csv"
)

def validate_dataset_file(
    dataset_csv: str = DEFAULT_DATASET_CSV,
    sources_file: str = DEFAULT_SOURCES_PATH,
) -> Dict[str, Any]:
    """
    Validate dataset against strict production standards:
    - Schema compliance
    - Canonical 4-class taxonomy
    - Verified provenance & licensing
    - Non-empty content & deterministic hashes
    - Zero duplicate IDs & zero duplicate hashes
    - Special zero-count support for suspicious class
    """
    blocking_reasons: List[str] = []
    warnings: List[str] = []

    # 1. Check sources catalog
    if not os.path.exists(sources_file):
        blocking_reasons.append(f"Provenance catalog missing: '{sources_file}' not found.")
        sources_catalog = {}
    else:
        try:
            with open(sources_file, "r", encoding="utf-8") as f:
                s_data = json.load(f)
            sources_catalog = {
                src.get("name", "").lower(): src
                for src in s_data.get("sources", [])
            }
        except Exception as exc:
            blocking_reasons.append(f"Invalid sources.json format: {exc}")
            sources_catalog = {}

    # 2. Check dataset file existence
    if not os.path.exists(dataset_csv):
        blocking_reasons.append(f"Target dataset file missing: '{dataset_csv}' does not exist.")
        return {
            "dataset_ready": False,
            "training_allowed": False,
            "total_samples": 0,
            "classes": {},
            "blocking_reasons": blocking_reasons,
            "warnings": warnings,
        }

    # 3. Read dataset
    try:
        df = pd.read_csv(dataset_csv, encoding="utf-8")
    except UnicodeDecodeError:
        blocking_reasons.append("Dataset is not valid UTF-8 encoded.")
        return {
            "dataset_ready": False,
            "training_allowed": False,
            "total_samples": 0,
            "classes": {},
            "blocking_reasons": blocking_reasons,
            "warnings": warnings,
        }
    except Exception as exc:
        blocking_reasons.append(f"Error parsing dataset CSV: {exc}")
        return {
            "dataset_ready": False,
            "training_allowed": False,
            "total_samples": 0,
            "classes": {},
            "blocking_reasons": blocking_reasons,
            "warnings": warnings,
        }

    total_samples = len(df)
    if total_samples == 0:
        blocking_reasons.append("Dataset file is empty (0 samples).")
        return {
            "dataset_ready": False,
            "training_allowed": False,
            "total_samples": 0,
            "classes": {},
            "blocking_reasons": blocking_reasons,
            "warnings": warnings,
        }

    # 4. Check Required Columns
    missing_cols = [c for c in CANONICAL_COLUMNS if c not in df.columns]
    if missing_cols:
        blocking_reasons.append(f"Missing required canonical columns: {missing_cols}")

    # 5. Check Empty Text / Missing Body
    empty_text_mask = df["text"].isna() | (df["text"].astype(str).str.strip() == "")
    empty_count = int(empty_text_mask.sum())
    if empty_count > 0:
        blocking_reasons.append(f"Found {empty_count} records with empty 'text' content.")

    # 6. Check Duplicate IDs
    if "id" in df.columns:
        duplicate_ids = df[df["id"].duplicated()]
        if len(duplicate_ids) > 0:
            blocking_reasons.append(f"Found {len(duplicate_ids)} duplicate IDs in dataset.")

    # 7. Check Duplicate Content Hashes
    if "content_hash" in df.columns:
        duplicate_hashes = df[df["content_hash"].duplicated()]
        if len(duplicate_hashes) > 0:
            blocking_reasons.append(f"Found {len(duplicate_hashes)} duplicate content hashes (deduplication required).")

    # 8. Check Target Labels against Strict Taxonomy
    class_counts: Dict[str, int] = {}
    for c_name in LABEL2ID.keys():
        class_counts[c_name] = 0

    if "label" in df.columns:
        val_labels = df["label"].astype(str).str.lower().str.strip()
        invalid_labels = set(val_labels.unique()) - set(LABEL2ID.keys())
        if invalid_labels:
            blocking_reasons.append(f"Found unauthorized target labels: {list(invalid_labels)}. Allowed: {list(LABEL2ID.keys())}")

        counts = val_labels.value_counts().to_dict()
        for c_name in LABEL2ID.keys():
            class_counts[c_name] = int(counts.get(c_name, 0))

        # Check label_id parity
        if "label_id" in df.columns:
            mismatches = df[df["label"].map(LABEL2ID) != df["label_id"]]
            if len(mismatches) > 0:
                blocking_reasons.append(f"Found {len(mismatches)} records where label and label_id do not match.")

    # 9. Verify Source Provenance and Licenses
    if "source" in df.columns:
        unknown_sources = set()
        unverified_sources = set()
        for src_name in df["source"].dropna().unique():
            key = str(src_name).lower().strip()
            if key not in sources_catalog:
                unknown_sources.add(str(src_name))
            else:
                s_entry = sources_catalog[key]
                if not s_entry.get("license_verified", False):
                    unverified_sources.add(str(src_name))
                if not s_entry.get("allowed_for_training", False):
                    blocking_reasons.append(f"Dataset contains samples from source marked disallowed for training: '{src_name}'")

        if unknown_sources:
            blocking_reasons.append(f"Dataset contains unregistered sources: {list(unknown_sources)}")
        if unverified_sources:
            blocking_reasons.append(f"Dataset contains sources with unverified licenses: {list(unverified_sources)}")

    # 10. Check Special Suspicious Class Handling
    if class_counts.get("suspicious", 0) == 0:
        warnings.append(
            "Suspicious class count is 0. Per Phase 2B Part 2 rules, no artificial suspicious samples were manufactured. "
            "Model training may require 4 populated classes or minimum class count adjustments."
        )

    # 11. Warnings for Edge Cases
    if "subject" in df.columns:
        missing_subj = int(df["subject"].isna().sum())
        if missing_subj > 0:
            warnings.append(f"{missing_subj} sample(s) have missing or empty subject header.")

    if "text" in df.columns:
        short_count = int((df["text"].astype(str).str.len() < 20).sum())
        if short_count > 0:
            warnings.append(f"{short_count} sample(s) have very short text content (< 20 characters).")

        large_count = int((df["text"].astype(str).str.len() > 50000).sum())
        if large_count > 0:
            warnings.append(f"{large_count} sample(s) have unusually large text content (> 50,000 characters).")

    is_ready = (len(blocking_reasons) == 0) and (total_samples > 0)
    training_allowed = is_ready and (class_counts.get("benign", 0) >= 2) and (class_counts.get("phishing", 0) >= 2)

    return {
        "dataset_ready": is_ready,
        "training_allowed": training_allowed,
        "total_samples": total_samples,
        "classes": class_counts,
        "blocking_reasons": blocking_reasons,
        "warnings": warnings,
    }

def main():
    parser = argparse.ArgumentParser(description="MAILTRACE 2.0 Dataset Quality Validation Tool")
    parser.add_argument("--dataset-csv", type=str, default=DEFAULT_DATASET_CSV, help="Path to dataset.csv")
    parser.add_argument("--sources-file", type=str, default=DEFAULT_SOURCES_PATH, help="Path to sources.json")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    result = validate_dataset_file(
        dataset_csv=args.dataset_csv,
        sources_file=args.sources_file
    )
    print(json.dumps(result, indent=2))
    if not result["dataset_ready"]:
        sys.exit(1)

if __name__ == "__main__":
    main()
