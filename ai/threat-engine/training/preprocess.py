import re
import hashlib
from typing import Tuple, Dict, Any
import pandas as pd
from .config import LABEL2ID

def compute_content_hash(text: str) -> str:
    """Compute deterministic SHA-256 hash of normalized text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def assemble_email_text(row: pd.Series) -> str:
    """
    Construct canonical email text from row fields.
    If 'subject' and 'body' are provided, formats as 'Subject: ...\n\nBody: ...'.
    Otherwise returns 'text' column.
    """
    if "text" in row and pd.notna(row["text"]) and str(row["text"]).strip():
        return str(row["text"]).strip()

    subject = str(row["subject"]).strip() if "subject" in row and pd.notna(row["subject"]) else ""
    body = str(row["body"]).strip() if "body" in row and pd.notna(row["body"]) else ""

    parts = []
    if subject:
        parts.append(f"Subject: {subject}")
    if body:
        parts.append(f"Body: {body}")

    return "\n\n".join(parts) if parts else ""

def normalize_whitespace(text: str) -> str:
    """
    Normalize consecutive horizontal spaces while preserving linebreaks,
    URLs, email addresses, and security indicators.
    """
    if not text:
        return ""
    # Normalize carriage returns
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse multiple horizontal spaces/tabs
    text = re.sub(r"[ \t]+", " ", text)
    # Collapse excessive vertical breaks (more than 2)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def clean_dataset(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Clean and validate raw input dataframe.
    - Resolves text column from 'text' or ('subject', 'body').
    - Normalizes whitespace without stripping URLs/emails.
    - Computes deterministic SHA-256 content_hash.
    - Validates labels against canonical 4-class taxonomy.
    - Removes empty samples and exact duplicates.
    - Preserves provenance columns if present.
    - Returns (cleaned_df, cleaning_report).
    """
    initial_rows = len(df)
    report = {
        "initial_rows": initial_rows,
        "null_removed": 0,
        "duplicates_removed": 0,
        "invalid_labels_removed": 0,
        "final_rows": 0,
    }

    if df.empty:
        report["final_rows"] = 0
        return pd.DataFrame(columns=["text", "label", "label_id", "content_hash"]), report

    # Make working copy
    work_df = df.copy()

    # 1. Assemble 'text' column if needed
    if "text" not in work_df.columns:
        if "body" in work_df.columns:
            work_df["text"] = work_df.apply(assemble_email_text, axis=1)
        else:
            raise ValueError("Dataset must contain either a 'text' column or a 'body' column.")

    # 2. Check required 'label' column
    if "label" not in work_df.columns:
        raise ValueError("Dataset must contain a 'label' column.")

    # 3. Drop null/empty values
    work_df["text"] = work_df["text"].astype(str).apply(normalize_whitespace)
    work_df["label"] = work_df["label"].astype(str).str.strip().str.lower()

    non_empty_mask = (work_df["text"] != "") & (work_df["label"] != "") & (work_df["label"] != "nan")
    dropped_empty = initial_rows - int(non_empty_mask.sum())
    report["null_removed"] = dropped_empty
    work_df = work_df[non_empty_mask].copy()

    # 4. Validate labels against strict taxonomy
    valid_mask = work_df["label"].isin(LABEL2ID.keys())
    invalid_count = len(work_df) - int(valid_mask.sum())
    report["invalid_labels_removed"] = invalid_count
    if invalid_count > 0:
        invalid_labels = set(work_df[~valid_mask]["label"].unique())
        raise ValueError(f"Dataset contains unknown labels: {invalid_labels}. Allowed labels are: {list(LABEL2ID.keys())}")

    # Map label to numerical ID
    work_df["label_id"] = work_df["label"].map(LABEL2ID)

    # 5. Deterministic content hash computation
    if "content_hash" not in work_df.columns:
        work_df["content_hash"] = work_df["text"].apply(compute_content_hash)

    # 6. Remove exact duplicates (matching content_hash)
    before_dedup = len(work_df)
    work_df = work_df.drop_duplicates(subset=["content_hash"]).reset_index(drop=True)
    report["duplicates_removed"] = before_dedup - len(work_df)

    report["final_rows"] = len(work_df)

    # Preserve canonical columns while maintaining standard contract
    canonical_set = [
        "id", "text", "subject", "body", "label", "label_id",
        "source", "source_label", "source_reference", "content_hash"
    ]
    retained_cols = [c for c in canonical_set if c in work_df.columns]
    for required_col in ["text", "label", "label_id"]:
        if required_col not in retained_cols:
            retained_cols.append(required_col)

    return work_df[retained_cols], report
