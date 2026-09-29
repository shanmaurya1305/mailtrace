import os
import sys
import json
import argparse
import logging
from datetime import datetime, timezone
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
from training.scripts.validate_dataset import validate_dataset_file

logger = logging.getLogger("mailtrace-dataset-report")

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

DEFAULT_REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "reports"
)

BEC_LIMITATION_STATEMENT = (
    "Public BEC data is substantially more limited than general legitimate/phishing email data. "
    "BEC-2 provides 279 generated samples based on real-world BEC examples rather than a large authentic mailbox corpus."
)

SUSPICIOUS_CLASS_STATEMENT = (
    "No verified source currently supplies a defensible standalone suspicious label. "
    "Suspicious count remains 0 to prevent label fabrication."
)

def generate_comprehensive_report(
    dataset_csv: str = DEFAULT_DATASET_CSV,
    sources_file: str = DEFAULT_SOURCES_PATH,
    reports_dir: str = DEFAULT_REPORTS_DIR,
) -> Dict[str, Any]:
    """
    Generate dataset quality, distribution, license, and provenance audit reports.
    Writes dataset_report.json and dataset_report.md into reports_dir.
    """
    os.makedirs(reports_dir, exist_ok=True)
    val_result = validate_dataset_file(dataset_csv, sources_file)

    # 1. Sources audit with distinct count semantics
    sources_summary: List[Dict[str, Any]] = []
    license_status: Dict[str, Any] = {}
    provenance_status: Dict[str, Any] = {}

    if os.path.exists(sources_file):
        with open(sources_file, "r", encoding="utf-8") as f:
            sources_data = json.load(f)
        for s in sources_data.get("sources", []):
            s_name = s.get("name", "Unknown")
            source_count = s.get("source_sample_count")
            down_count = s.get("downloaded_count", 0)
            norm_count = s.get("normalized_count", 0)

            s_meta = {
                "name": s_name,
                "authoritative_source": s.get("authoritative_source"),
                "source_url": s.get("source_url"),
                "provenance_type": s.get("provenance_type", s.get("dataset_type")),
                "license": s.get("license"),
                "license_verified": s.get("license_verified", False),
                "access_type": s.get("access_type", "unknown"),
                "allowed_for_training": s.get("allowed_for_training", False),
                "source_sample_count": source_count,
                "downloaded_count": down_count,
                "normalized_count": norm_count,
                "limitations": s.get("limitations", []),
                "verification_notes": s.get("verification_notes", ""),
            }
            sources_summary.append(s_meta)
            license_status[s_name] = {
                "license": s.get("license"),
                "license_verified": s.get("license_verified", False),
                "allowed_for_training": s.get("allowed_for_training", False),
            }
            provenance_status[s_name] = {
                "provenance_type": s_meta["provenance_type"],
                "source_sample_count": source_count,
                "provenance_notes": s.get("provenance_notes"),
            }

    # 2. Check if normalized dataset exists and compute distributions
    total_samples = 0
    class_counts: Dict[str, int] = {k: 0 for k in LABEL2ID.keys()}
    class_percentages: Dict[str, float] = {k: 0.0 for k in LABEL2ID.keys()}
    source_counts: Dict[str, int] = {}
    source_label_counts: Dict[str, int] = {}
    duplicate_count = 0
    cross_source_duplicate_count = 0
    empty_text_count = 0
    missing_subject_count = 0
    missing_body_count = 0
    invalid_label_count = 0

    if os.path.exists(dataset_csv):
        try:
            df = pd.read_csv(dataset_csv, encoding="utf-8")
            total_samples = len(df)
            if total_samples > 0:
                if "label" in df.columns:
                    counts = df["label"].astype(str).str.lower().str.strip().value_counts().to_dict()
                    for k in LABEL2ID.keys():
                        c_val = int(counts.get(k, 0))
                        class_counts[k] = c_val
                        class_percentages[k] = round((c_val / total_samples) * 100, 2)
                    
                    invalid_series = df[~df["label"].astype(str).str.lower().str.strip().isin(LABEL2ID.keys())]
                    invalid_label_count = len(invalid_series)

                if "source" in df.columns:
                    source_counts = {str(k): int(v) for k, v in df["source"].value_counts().to_dict().items()}

                if "source_label" in df.columns:
                    source_label_counts = {str(k): int(v) for k, v in df["source_label"].value_counts().to_dict().items()}

                if "text" in df.columns:
                    empty_text_count = int((df["text"].isna() | (df["text"].astype(str).str.strip() == "")).sum())

                if "subject" in df.columns:
                    missing_subject_count = int((df["subject"].isna() | (df["subject"].astype(str).str.strip() == "")).sum())

                if "body" in df.columns:
                    missing_body_count = int((df["body"].isna() | (df["body"].astype(str).str.strip() == "")).sum())

                if "content_hash" in df.columns:
                    dup_mask = df["content_hash"].duplicated()
                    duplicate_count = int(dup_mask.sum())
        except Exception as exc:
            logger.error(f"Failed to read dataset for detailed report: {exc}")

    # Check duplicates registry if exists
    dup_file = os.path.join(reports_dir, "duplicates.json")
    if os.path.exists(dup_file):
        try:
            with open(dup_file, "r", encoding="utf-8") as f:
                dup_data = json.load(f)
                duplicate_count = dup_data.get("duplicate_count", duplicate_count)
                cross_source_duplicate_count = dup_data.get("cross_source_duplicate_count", 0)
        except Exception:
            pass

    # Compile final structured report
    report_dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_samples": total_samples,
        "class_counts": class_counts,
        "class_percentages": class_percentages,
        "source_counts": source_counts,
        "source_label_counts": source_label_counts,
        "duplicate_count": duplicate_count,
        "cross_source_duplicate_count": cross_source_duplicate_count,
        "empty_text_count": empty_text_count,
        "missing_subject_count": missing_subject_count,
        "missing_body_count": missing_body_count,
        "invalid_label_count": invalid_label_count,
        "sources_summary": sources_summary,
        "license_status": license_status,
        "provenance_status": provenance_status,
        "train_ready": val_result["dataset_ready"] and val_result["training_allowed"],
        "blocking_reasons": val_result["blocking_reasons"],
        "warnings": val_result["warnings"],
        "project_limitations": {
            "bec_limitation": BEC_LIMITATION_STATEMENT,
            "suspicious_limitation": SUSPICIOUS_CLASS_STATEMENT,
        },
        "status": {
            "phase": "2B-part2A",
            "dataset_ready": val_result["dataset_ready"],
            "training_allowed": val_result["training_allowed"],
            "total_samples": total_samples,
            "classes": class_counts,
            "blocking_reasons": val_result["blocking_reasons"],
            "warnings": val_result["warnings"],
        }
    }

    # Write JSON report
    json_path = os.path.join(reports_dir, "dataset_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    # Write Markdown report
    md_path = os.path.join(reports_dir, "dataset_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# MAILTRACE 2.0 — Phase 2B Part 2A Dataset Provenance & Readiness Report\n\n")
        f.write(f"**Generated**: `{report_dict['timestamp_utc']}`\n\n")
        f.write(f"**Dataset Readiness**: `{'READY' if report_dict['train_ready'] else 'NOT READY FOR TRAINING'}`\n")
        f.write(f"**Training Allowed**: `{'YES' if val_result['training_allowed'] else 'NO'}`\n\n")
        
        f.write("## 1. Class Distribution\n\n")
        f.write("| Canonical Class | Count | Percentage |\n")
        f.write("| :--- | :---: | :---: |\n")
        for c_name in LABEL2ID.keys():
            cnt = class_counts.get(c_name, 0)
            pct = class_percentages.get(c_name, 0.0)
            f.write(f"| `{c_name}` | {cnt} | {pct}% |\n")
        f.write(f"| **Total** | **{total_samples}** | **100%** |\n\n")

        f.write("## 2. Dataset Count Semantics\n\n")
        f.write("| Source Name | Source Count (Available) | Downloaded | Normalized |\n")
        f.write("| :--- | :---: | :---: | :---: |\n")
        for s in sources_summary:
            s_avail = s["source_sample_count"] if s["source_sample_count"] is not None else "null (unverified)"
            f.write(f"| {s['name']} | `{s_avail}` | `{s['downloaded_count']}` | `{s['normalized_count']}` |\n")
        f.write("\n")

        f.write("## 3. Data Quality & Duplicates\n\n")
        f.write(f"* **Total Samples**: `{total_samples}`\n")
        f.write(f"* **Exact Content Duplicates**: `{duplicate_count}`\n")
        f.write(f"* **Cross-Source Duplicates**: `{cross_source_duplicate_count}`\n")
        f.write(f"* **Empty Text Records**: `{empty_text_count}`\n")
        f.write(f"* **Invalid Target Labels**: `{invalid_label_count}`\n")
        f.write(f"* **Missing Subject Headers**: `{missing_subject_count}`\n\n")

        f.write("## 4. Source Verification & Provenance Status\n\n")
        f.write("| Source Name | Provenance Type | License | License Verified | Training Allowed |\n")
        f.write("| :--- | :--- | :--- | :---: | :---: |\n")
        for s in sources_summary:
            f.write(f"| {s['name']} | `{s['provenance_type']}` | {s['license']} | {'YES' if s['license_verified'] else 'NO'} | {'YES' if s['allowed_for_training'] else 'NO'} |\n")
        f.write("\n")

        f.write("## 5. Explicit Project Limitations\n\n")
        f.write(f"> **BEC Limitation**: {BEC_LIMITATION_STATEMENT}\n\n")
        f.write(f"> **Suspicious Class Limitation**: {SUSPICIOUS_CLASS_STATEMENT}\n\n")

        if report_dict["blocking_reasons"]:
            f.write("## 6. Blocking Reasons\n\n")
            for r in report_dict["blocking_reasons"]:
                f.write(f"- ❌ **{r}**\n")
            f.write("\n")

        if report_dict["warnings"]:
            f.write("## 7. Warnings & Quality Observations\n\n")
            for w in report_dict["warnings"]:
                f.write(f"- ⚠️ {w}\n")
            f.write("\n")

    logger.info(f"Generated dataset readiness report at '{json_path}' and '{md_path}'.")
    return report_dict

def main():
    parser = argparse.ArgumentParser(description="MAILTRACE 2.0 Dataset Report Generator")
    parser.add_argument("--dataset-csv", type=str, default=DEFAULT_DATASET_CSV, help="Path to dataset.csv")
    parser.add_argument("--sources-file", type=str, default=DEFAULT_SOURCES_PATH, help="Path to sources.json")
    parser.add_argument("--reports-dir", type=str, default=DEFAULT_REPORTS_DIR, help="Path to reports directory")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    result = generate_comprehensive_report(
        dataset_csv=args.dataset_csv,
        sources_file=args.sources_file,
        reports_dir=args.reports_dir
    )
    print(json.dumps(result["status"], indent=2))

if __name__ == "__main__":
    main()
