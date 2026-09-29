import os
import sys
import json
import hashlib
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set
import pandas as pd

# Setup path resolution for both direct script and module execution
_curr_file = Path(__file__).resolve()
_threat_engine_dir = _curr_file.parents[2]
_project_root = _curr_file.parents[4]

for _p in [str(_threat_engine_dir), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from training.config import LABEL2ID
from training.preprocess import normalize_whitespace

logger = logging.getLogger("mailtrace-dataset-normalize")

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

DEFAULT_RAW_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "raw"
)

DEFAULT_NORMALIZED_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "normalized"
)

DEFAULT_OUTPUT_CSV = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "dataset.csv"
)

DEFAULT_REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "reports"
)

def compute_content_hash(text: str) -> str:
    """Compute deterministic SHA-256 hash of normalized text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def assemble_email_content(subject: Optional[str], body: Optional[str], fallback_text: Optional[str] = None) -> str:
    """
    Construct canonical email text:
    If subject and body exist:
        Subject: <subject>\n\nBody: <body>
    If subject missing:
        <body>
    If body missing but fallback_text exists:
        <fallback_text>
    """
    subj = normalize_whitespace(str(subject)) if subject and pd.notna(subject) else ""
    bdy = normalize_whitespace(str(body)) if body and pd.notna(body) else ""
    
    if subj and bdy:
        return f"Subject: {subj}\n\nBody: {bdy}"
    elif bdy:
        return bdy
    elif subj:
        return f"Subject: {subj}"
    elif fallback_text and pd.notna(fallback_text):
        return normalize_whitespace(str(fallback_text))
    return ""

def load_source_mappings(sources_file: str = DEFAULT_SOURCES_PATH) -> Dict[str, Dict[str, Any]]:
    """Load valid label mappings from sources.json."""
    if not os.path.exists(sources_file):
        raise FileNotFoundError(f"Sources catalog file not found at '{sources_file}'.")
    with open(sources_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    catalog: Dict[str, Dict[str, Any]] = {}
    for src in data.get("sources", []):
        name = src.get("name")
        if name:
            catalog[name.lower()] = {
                "allowed_for_training": src.get("allowed_for_training", False),
                "license_verified": src.get("license_verified", False),
                "dataset_type": src.get("dataset_type", "unknown"),
                "mapping": src.get("mapping", {}),
            }
    return catalog

def normalize_sample_record(
    index: int,
    subject: Optional[str],
    body: Optional[str],
    raw_text: Optional[str],
    source_name: str,
    source_label: str,
    source_reference: str,
    source_catalog: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Normalize a single email record according to strict taxonomy rules."""
    src_key = source_name.lower().strip()
    if src_key not in source_catalog:
        logger.warning(f"Skipping sample from unregistered source: '{source_name}'")
        return None

    source_entry = source_catalog[src_key]
    if not source_entry.get("allowed_for_training", False):
        return None

    mapping = source_entry.get("mapping", {})
    label_info = mapping.get(str(source_label).lower().strip())
    if not label_info or not label_info.get("allowed", False):
        return None

    target_label = label_info.get("mailtrace_label")
    if target_label not in LABEL2ID:
        return None

    text_content = assemble_email_content(subject, body, raw_text)
    if not text_content or not text_content.strip():
        return None

    content_hash = compute_content_hash(text_content)
    sample_id = f"MT-{index:08d}"

    return {
        "id": sample_id,
        "text": text_content,
        "subject": str(subject).strip() if subject and pd.notna(subject) else "",
        "body": str(body).strip() if body and pd.notna(body) else "",
        "label": target_label,
        "label_id": LABEL2ID[target_label],
        "source": source_name,
        "source_label": str(source_label),
        "source_reference": str(source_reference),
        "content_hash": content_hash,
    }

def deduplicate_records(
    records: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Deduplicate normalized records by content_hash.
    Tracks exact duplicates and cross-source duplicates.
    """
    seen_hashes: Dict[str, Dict[str, Any]] = {}
    unique_records: List[Dict[str, Any]] = []
    
    duplicate_records: List[Dict[str, Any]] = []
    cross_source_duplicates: List[Dict[str, Any]] = []

    for rec in records:
        h = rec["content_hash"]
        if h in seen_hashes:
            orig = seen_hashes[h]
            dup_info = {
                "duplicate_id": rec["id"],
                "original_id": orig["id"],
                "content_hash": h,
                "original_source": orig["source"],
                "duplicate_source": rec["source"],
            }
            duplicate_records.append(dup_info)
            if orig["source"].lower() != rec["source"].lower():
                cross_source_duplicates.append(dup_info)
        else:
            seen_hashes[h] = rec
            unique_records.append(rec)

    # Re-index unique records for clean contiguous IDs
    for idx, rec in enumerate(unique_records, start=1):
        rec["id"] = f"MT-{idx:08d}"

    dedup_stats = {
        "initial_records": len(records),
        "unique_records": len(unique_records),
        "duplicate_count": len(duplicate_records),
        "cross_source_duplicate_count": len(cross_source_duplicates),
        "duplicate_percentage": round((len(duplicate_records) / len(records) * 100), 2) if records else 0.0,
    }

    return unique_records, dedup_stats

def normalize_dataset_pipeline(
    raw_dir: str = DEFAULT_RAW_DIR,
    output_csv: str = DEFAULT_OUTPUT_CSV,
    sources_file: str = DEFAULT_SOURCES_PATH,
    reports_dir: str = DEFAULT_REPORTS_DIR,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Execute end-to-end normalization pipeline from raw data files.
    If raw data directory has no dataset files, returns clear audit result.
    """
    source_catalog = load_source_mappings(sources_file)
    os.makedirs(reports_dir, exist_ok=True)

    raw_files = []
    if os.path.exists(raw_dir):
        for root, _, files in os.walk(raw_dir):
            for f in files:
                if f.endswith((".csv", ".tsv", ".json", ".txt")):
                    raw_files.append(os.path.join(root, f))

    if not raw_files:
        logger.info(f"No raw dataset files found in '{raw_dir}'.")
        return {
            "status": "no_raw_data_found",
            "raw_dir": raw_dir,
            "raw_files_count": 0,
            "unique_records": 0,
            "output_csv": output_csv,
            "dry_run": dry_run,
        }

    all_normalized: List[Dict[str, Any]] = []
    counter = 1

    for filepath in raw_files:
        try:
            if filepath.endswith(".csv"):
                df = pd.read_csv(filepath)
                for _, row in df.iterrows():
                    rec = normalize_sample_record(
                        index=counter,
                        subject=row.get("subject"),
                        body=row.get("body"),
                        raw_text=row.get("text"),
                        source_name=row.get("source", "Unknown"),
                        source_label=row.get("source_label", row.get("label", "unknown")),
                        source_reference=os.path.basename(filepath),
                        source_catalog=source_catalog,
                    )
                    if rec:
                        all_normalized.append(rec)
                        counter += 1
        except Exception as exc:
            logger.error(f"Error parsing raw file '{filepath}': {exc}")

    unique_records, dedup_stats = deduplicate_records(all_normalized)

    if not dry_run and unique_records:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        out_df = pd.DataFrame(unique_records)[CANONICAL_COLUMNS]
        out_df.to_csv(output_csv, index=False, encoding="utf-8")
        logger.info(f"Saved canonical normalized dataset with {len(unique_records)} samples to '{output_csv}'.")

        # Save duplicate audit report
        dup_report_path = os.path.join(reports_dir, "duplicates.json")
        with open(dup_report_path, "w", encoding="utf-8") as f:
            json.dump(dedup_stats, f, indent=2)

    return {
        "status": "completed",
        "raw_files_processed": len(raw_files),
        "dedup_stats": dedup_stats,
        "output_csv": output_csv,
        "dry_run": dry_run,
    }

def main():
    parser = argparse.ArgumentParser(description="MAILTRACE 2.0 Dataset Normalization Tool")
    parser.add_argument("--raw-dir", type=str, default=DEFAULT_RAW_DIR, help="Path to raw corpora directory")
    parser.add_argument("--output-csv", type=str, default=DEFAULT_OUTPUT_CSV, help="Output canonical dataset CSV")
    parser.add_argument("--sources-file", type=str, default=DEFAULT_SOURCES_PATH, help="Path to sources.json")
    parser.add_argument("--reports-dir", type=str, default=DEFAULT_REPORTS_DIR, help="Path to save audit reports")
    parser.add_argument("--dry-run", action="store_true", help="Audit without writing dataset.csv")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    result = normalize_dataset_pipeline(
        raw_dir=args.raw_dir,
        output_csv=args.output_csv,
        sources_file=args.sources_file,
        reports_dir=args.reports_dir,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
