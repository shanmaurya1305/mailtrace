import os
import sys
import json
import tempfile
from pathlib import Path
import pytest
import pandas as pd
import numpy as np

# Locate project root and threat-engine dynamically
_curr = Path(__file__).resolve()
for _parent in _curr.parents:
    _candidate = _parent / "ai" / "threat-engine"
    if _candidate.is_dir():
        if str(_candidate) not in sys.path:
            sys.path.insert(0, str(_candidate))
        break

from training.config import LABEL2ID
from training.preprocess import compute_content_hash, normalize_whitespace
from training.dataset import ThreatDataset
from training.scripts.acquire_datasets import acquire_datasets, load_sources_catalog
from training.scripts.normalize_datasets import (
    normalize_sample_record,
    deduplicate_records,
    assemble_email_content,
    CANONICAL_COLUMNS,
)
from training.scripts.validate_dataset import validate_dataset_file
from training.scripts.generate_report import generate_comprehensive_report

@pytest.fixture
def sample_sources_json():
    """Create a temporary valid sources catalog for offline testing."""
    catalog = {
        "sources": [
            {
                "name": "Enron Email Dataset",
                "source_url": "https://example.com/enron.tar.gz",
                "license": "Public Domain",
                "license_verified": True,
                "dataset_type": "authentic_business_email",
                "allowed_for_training": True,
                "mapping": {
                    "unlabeled_corporate_correspondence": {
                        "mailtrace_label": "benign",
                        "allowed": True,
                        "rationale": "Authentic corporate correspondence"
                    }
                },
                "provenance_notes": "FERC public record"
            },
            {
                "name": "Nazario Phishing Corpus",
                "source_url": "https://example.com/nazario.tar.gz",
                "license": "CC-BY 3.0",
                "license_verified": True,
                "dataset_type": "authentic_phishing",
                "allowed_for_training": True,
                "mapping": {
                    "phishing": {
                        "mailtrace_label": "phishing",
                        "allowed": True,
                        "rationale": "Verified phishing emails"
                    }
                },
                "provenance_notes": "Security research corpus"
            },
            {
                "name": "Unverified Test Corpus",
                "source_url": "https://example.com/unverified.tar.gz",
                "license": "Unknown",
                "license_verified": False,
                "dataset_type": "synthetic",
                "allowed_for_training": False,
                "mapping": {
                    "spam": {
                        "mailtrace_label": None,
                        "allowed": False,
                        "rationale": "Unverified licensing and provenance"
                    }
                },
                "provenance_notes": "Unverified test source"
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
        json.dump(catalog, f, indent=2)
        tmp_path = f.name

    yield tmp_path
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

# 1. Deterministic content hash computation
def test_deterministic_content_hash():
    """Verify SHA-256 hash is deterministic and sensitive to content changes."""
    text1 = "Subject: Urgent Action Required\n\nBody: Please click the link to verify your password."
    text2 = "Subject: Urgent Action Required\n\nBody: Please click the link to verify your password."
    text3 = "Subject: Urgent Action Required\n\nBody: Please click the link to verify your account."

    hash1 = compute_content_hash(text1)
    hash2 = compute_content_hash(text2)
    hash3 = compute_content_hash(text3)

    assert hash1 == hash2
    assert hash1 != hash3
    assert len(hash1) == 64

# 2. Valid dataset passes quality validation
def test_valid_dataset_validation(sample_sources_json):
    """Verify clean dataset matching canonical schema passes validation without blocking reasons."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [
            {
                "id": "MT-00000001",
                "text": "Subject: Meeting Today\n\nBody: Let us discuss the quarterly project roadmap.",
                "subject": "Meeting Today",
                "body": "Let us discuss the quarterly project roadmap.",
                "label": "benign",
                "label_id": 0,
                "source": "Enron Email Dataset",
                "source_label": "unlabeled_corporate_correspondence",
                "source_reference": "enron_sample_1.txt",
                "content_hash": compute_content_hash("Subject: Meeting Today\n\nBody: Let us discuss the quarterly project roadmap.")
            },
            {
                "id": "MT-00000002",
                "text": "Subject: Invoice Overdue\n\nBody: Wire transfer requested immediately to new account.",
                "subject": "Invoice Overdue",
                "body": "Wire transfer requested immediately to new account.",
                "label": "phishing",
                "label_id": 2,
                "source": "Nazario Phishing Corpus",
                "source_label": "phishing",
                "source_reference": "nazario_sample_1.txt",
                "content_hash": compute_content_hash("Subject: Invoice Overdue\n\nBody: Wire transfer requested immediately to new account.")
            }
        ]
        pd.DataFrame(rows)[CANONICAL_COLUMNS].to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is True
        assert len(val_res["blocking_reasons"]) == 0
        assert val_res["total_samples"] == 2
        assert val_res["classes"]["benign"] == 1
        assert val_res["classes"]["phishing"] == 1
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 3. Invalid label is rejected
def test_invalid_label_rejected(sample_sources_json):
    """Verify unauthorized target label outside the 4-class taxonomy is blocked."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [{
            "id": "MT-00000001",
            "text": "Subject: Malicious Attachment\n\nBody: Run this executable immediately.",
            "subject": "Malicious Attachment",
            "body": "Run this executable immediately.",
            "label": "trojan_payload",
            "label_id": 99,
            "source": "Nazario Phishing Corpus",
            "source_label": "phishing",
            "source_reference": "test.txt",
            "content_hash": "a" * 64
        }]
        pd.DataFrame(rows).to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is False
        assert any("Found unauthorized target labels" in b for b in val_res["blocking_reasons"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 4. Empty text content is rejected
def test_empty_text_rejected(sample_sources_json):
    """Verify records with empty text content trigger blocking reasons."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [{
            "id": "MT-00000001",
            "text": "   ",
            "subject": "",
            "body": "",
            "label": "benign",
            "label_id": 0,
            "source": "Enron Email Dataset",
            "source_label": "unlabeled_corporate_correspondence",
            "source_reference": "empty.txt",
            "content_hash": "b" * 64
        }]
        pd.DataFrame(rows).to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is False
        assert any("records with empty 'text' content" in b for b in val_res["blocking_reasons"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 5. Duplicate content hash is rejected
def test_duplicate_content_hash_rejected(sample_sources_json):
    """Verify duplicate content hashes in dataset are flagged for required deduplication."""
    shared_hash = compute_content_hash("Shared email body text")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [
            {
                "id": "MT-00000001",
                "text": "Shared email body text",
                "subject": "",
                "body": "Shared email body text",
                "label": "benign",
                "label_id": 0,
                "source": "Enron Email Dataset",
                "source_label": "unlabeled_corporate_correspondence",
                "source_reference": "ref1.txt",
                "content_hash": shared_hash
            },
            {
                "id": "MT-00000002",
                "text": "Shared email body text",
                "subject": "",
                "body": "Shared email body text",
                "label": "benign",
                "label_id": 0,
                "source": "Enron Email Dataset",
                "source_label": "unlabeled_corporate_correspondence",
                "source_reference": "ref2.txt",
                "content_hash": shared_hash
            }
        ]
        pd.DataFrame(rows).to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is False
        assert any("duplicate content hashes" in b for b in val_res["blocking_reasons"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 6. Cross-source duplicate detection
def test_cross_source_duplicate_detection():
    """Verify deduplication detects identical content appearing across distinct corpora."""
    shared_text = "Urgent: Update your direct deposit account immediately."
    h = compute_content_hash(shared_text)

    records = [
        {
            "id": "MT-00000001",
            "content_hash": h,
            "text": shared_text,
            "source": "Enron Email Dataset",
            "label": "benign"
        },
        {
            "id": "MT-00000002",
            "content_hash": h,
            "text": shared_text,
            "source": "Nazario Phishing Corpus",
            "label": "phishing"
        }
    ]

    unique_recs, dedup_stats = deduplicate_records(records)
    assert len(unique_recs) == 1
    assert dedup_stats["duplicate_count"] == 1
    assert dedup_stats["cross_source_duplicate_count"] == 1

# 7. Unknown source rejected
def test_unknown_source_rejected(sample_sources_json):
    """Verify samples from unregistered sources trigger a blocking reason."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [{
            "id": "MT-00000001",
            "text": "Sample text",
            "subject": "",
            "body": "Sample text",
            "label": "benign",
            "label_id": 0,
            "source": "Completely Unregistered External Corpus",
            "source_label": "unknown",
            "source_reference": "sample.txt",
            "content_hash": compute_content_hash("Sample text")
        }]
        pd.DataFrame(rows).to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is False
        assert any("unregistered sources" in b for b in val_res["blocking_reasons"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 8. Unverified license rejected
def test_unverified_license_rejected(sample_sources_json):
    """Verify sources with license_verified=False or allowed_for_training=False are blocked."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [{
            "id": "MT-00000001",
            "text": "Sample text",
            "subject": "",
            "body": "Sample text",
            "label": "benign",
            "label_id": 0,
            "source": "Unverified Test Corpus",
            "source_label": "spam",
            "source_reference": "sample.txt",
            "content_hash": compute_content_hash("Sample text")
        }]
        pd.DataFrame(rows).to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is False
        assert any("unverified licenses" in b or "disallowed for training" in b for b in val_res["blocking_reasons"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 9. Provenance file missing
def test_provenance_file_missing():
    """Verify validation halts with clear failure when sources.json does not exist."""
    val_res = validate_dataset_file(
        dataset_csv="fake.csv",
        sources_file="nonexistent_sources_file_path.json"
    )
    assert val_res["dataset_ready"] is False
    assert any("Provenance catalog missing" in b for b in val_res["blocking_reasons"])

# 10. Label mapping from sources catalog
def test_label_mapping_from_sources_catalog():
    """Verify SpamAssassin spam is disallowed and ham maps strictly to benign."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    sa_source = next((s for s in sources if "SpamAssassin" in s["name"]), None)
    assert sa_source is not None
    # Verify spam is NOT allowed and NOT mapped to threat labels
    assert sa_source["mapping"]["spam"]["allowed"] is False
    assert sa_source["mapping"]["spam"]["mailtrace_label"] is None
    # Verify easy_ham maps strictly to benign
    assert sa_source["mapping"]["easy_ham"]["allowed"] is True
    assert sa_source["mapping"]["easy_ham"]["mailtrace_label"] == "benign"

# 11. Deterministic split and leakage prevention
def test_deterministic_split_and_leakage_prevention():
    """Verify split_data guarantees zero content_hash leakage across train, val, and test splits."""
    rows = []
    for label_name, lid in LABEL2ID.items():
        for i in range(10):
            txt = f"Unique email {label_name} sample {i}"
            rows.append({
                "text": txt,
                "label": label_name,
                "label_id": lid,
                "content_hash": compute_content_hash(txt)
            })
    df = pd.DataFrame(rows)

    ds = ThreatDataset()
    ds.df = df.copy()
    train_df, val_df, test_df, summary = ds.split_data(seed=42)

    assert summary["leakage_detected"] is False
    tr_hashes = set(train_df["content_hash"])
    va_hashes = set(val_df["content_hash"])
    te_hashes = set(test_df["content_hash"])

    assert len(tr_hashes.intersection(va_hashes)) == 0
    assert len(tr_hashes.intersection(te_hashes)) == 0
    assert len(va_hashes.intersection(te_hashes)) == 0

# 12. Zero suspicious-class handling
def test_zero_suspicious_class_handling(sample_sources_json):
    """Verify pipeline allows 0 samples in suspicious class without failure, providing a quality warning."""
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
        rows = [
            {
                "id": "MT-00000001",
                "text": "Subject: Note 1\n\nBody: Benign email sample 1.",
                "subject": "Note 1",
                "body": "Benign email sample 1.",
                "label": "benign",
                "label_id": 0,
                "source": "Enron Email Dataset",
                "source_label": "unlabeled_corporate_correspondence",
                "source_reference": "ref1.txt",
                "content_hash": compute_content_hash("Subject: Note 1\n\nBody: Benign email sample 1.")
            },
            {
                "id": "MT-00000002",
                "text": "Subject: Note 2\n\nBody: Benign email sample 2.",
                "subject": "Note 2",
                "body": "Benign email sample 2.",
                "label": "benign",
                "label_id": 0,
                "source": "Enron Email Dataset",
                "source_label": "unlabeled_corporate_correspondence",
                "source_reference": "ref2.txt",
                "content_hash": compute_content_hash("Subject: Note 2\n\nBody: Benign email sample 2.")
            },
            {
                "id": "MT-00000003",
                "text": "Subject: Phish 1\n\nBody: Phishing email sample 1.",
                "subject": "Phish 1",
                "body": "Phishing email sample 1.",
                "label": "phishing",
                "label_id": 2,
                "source": "Nazario Phishing Corpus",
                "source_label": "phishing",
                "source_reference": "phish1.txt",
                "content_hash": compute_content_hash("Subject: Phish 1\n\nBody: Phishing email sample 1.")
            },
            {
                "id": "MT-00000004",
                "text": "Subject: Phish 2\n\nBody: Phishing email sample 2.",
                "subject": "Phish 2",
                "body": "Phishing email sample 2.",
                "label": "phishing",
                "label_id": 2,
                "source": "Nazario Phishing Corpus",
                "source_label": "phishing",
                "source_reference": "phish2.txt",
                "content_hash": compute_content_hash("Subject: Phish 2\n\nBody: Phishing email sample 2.")
            }
        ]
        pd.DataFrame(rows)[CANONICAL_COLUMNS].to_csv(f.name, index=False)
        csv_path = f.name

    try:
        val_res = validate_dataset_file(dataset_csv=csv_path, sources_file=sample_sources_json)
        assert val_res["dataset_ready"] is True
        assert val_res["classes"]["suspicious"] == 0
        assert any("Suspicious class count is 0" in w for w in val_res["warnings"])
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)

# 13. Acquire datasets dry-run mode
def test_acquire_datasets_dry_run(sample_sources_json):
    """Verify acquire_datasets in dry-run mode audits sources without downloading or mutating files."""
    with tempfile.TemporaryDirectory() as tmp_raw:
        res = acquire_datasets(
            sources_file=sample_sources_json,
            raw_dir=tmp_raw,
            dry_run=True
        )
        assert res["dry_run"] is True
        assert res["sources_count"] == 3
        # Ensure zero files downloaded in raw_dir
        assert len(os.listdir(tmp_raw)) == 0

# 14. Report generator output structure
def test_generate_report_structure(sample_sources_json):
    """Verify generate_comprehensive_report outputs dataset_report.json matching schema."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        report = generate_comprehensive_report(
            dataset_csv=os.path.join(tmp_dir, "missing.csv"),
            sources_file=sample_sources_json,
            reports_dir=tmp_dir
        )
        assert "status" in report
        assert report["status"]["phase"].startswith("2B-part2")
        assert report["status"]["dataset_ready"] is False
        assert report["status"]["training_allowed"] is False
        assert os.path.exists(os.path.join(tmp_dir, "dataset_report.json"))
        assert os.path.exists(os.path.join(tmp_dir, "dataset_report.md"))

# 15. Placeholder BEC URL rejected
def test_placeholder_bec_url_rejected():
    """Verify any placeholder URL in sources catalog is flagged and rejected."""
    placeholder_catalog = {
        "sources": [
            {
                "name": "Placeholder BEC Source",
                "source_url": "https://github.com/example/bec-dataset-placeholder",
                "license": "Unverified",
                "license_verified": False,
                "dataset_type": "generated",
                "allowed_for_training": False,
            }
        ]
    }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
        json.dump(placeholder_catalog, f)
        tmp_path = f.name

    try:
        with tempfile.TemporaryDirectory() as tmp_raw:
            audit = acquire_datasets(sources_file=tmp_path, raw_dir=tmp_raw, dry_run=True)
            entry = audit["sources"][0]
            assert entry["action"] == "reject_placeholder"
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

# 16. Unsupported license claim rejected
def test_unsupported_license_claim_rejected():
    """Verify sources without verified license status are blocked from training."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    for s in sources:
        if not s.get("license_verified", False):
            assert s.get("allowed_for_training", False) is False, f"Source '{s.get('name')}' has unverified license but allowed_for_training is True!"

# 17. Zero vs null sample-count semantics
def test_zero_vs_null_sample_count_semantics():
    """Verify distinction between unknown source sample count (null) and unacquired downloads (0)."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    # Nazario and IWSPA should have source_sample_count=null (unverified count prior to full download)
    nazario = next((s for s in sources if "Nazario" in s["name"]), None)
    assert nazario is not None
    assert nazario["source_sample_count"] is None
    assert nazario["downloaded_count"] == 0
    assert nazario["normalized_count"] == 0

    # BEC-2 should have source_sample_count=279
    bec = next((s for s in sources if "BEC" in s["name"]), None)
    assert bec is not None
    assert bec["source_sample_count"] == 279
    assert bec["downloaded_count"] == 0
    assert bec["normalized_count"] == 0

# 18. Generated BEC provenance correctly represented
def test_generated_bec_provenance_correctly_represented():
    """Verify BEC-2 is strictly documented as generated from real-world examples, not authentic mailbox data."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    bec = next((s for s in sources if "BEC" in s["name"]), None)
    assert bec is not None
    assert bec["provenance_type"] == "generated_from_real_world_bec_examples"
    assert bec["provenance_type"] != "authentic"
    assert bec["sample_count"] == 279
    assert "example/bec-dataset-placeholder" not in bec["source_url"]
    assert bec["license_verified"] is False
    assert bec["allowed_for_training"] is False
    assert any("279 generated samples" in lim for lim in bec["limitations"])

# 19. Enron unlabeled-to-benign mapping requires explicit rationale
def test_enron_unlabeled_to_benign_requires_explicit_rationale():
    """Verify Enron mapping explicitly records modeling assumption note rather than claim of native benign label."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    enron = next((s for s in sources if "Enron" in s["name"]), None)
    assert enron is not None
    assert enron["mailtrace_mapping"]["unlabeled_corporate_correspondence"] == "benign"
    # Verification note must explicitly mention modeling assumption
    assert "modeling assumption" in enron["verification_notes"]
    assert enron["license_verified"] is False
    assert enron["allowed_for_training"] is False

# 20. SpamAssassin spam remains unresolved
def test_spamassassin_spam_remains_unresolved():
    """Verify commercial bulk spam is strictly unresolved and rejected from training."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    sa = next((s for s in sources if "SpamAssassin" in s["name"]), None)
    assert sa is not None
    assert sa["mailtrace_mapping"]["spam"] is None
    assert sa["mapping"]["spam"]["allowed"] is False
    assert sa["mapping"]["easy_ham"]["mailtrace_label"] == "benign"
    assert sa["mapping"]["hard_ham"]["mailtrace_label"] == "benign"

# 21. Restricted APWG corpus cannot become training-eligible automatically
def test_restricted_apwg_corpus_cannot_become_training_eligible_automatically():
    """Verify IWSPA/APWG restricted corpus is marked restricted and disallowed for training."""
    real_sources_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "ai", "threat-engine", "training", "data", "sources.json"
    )
    sources = load_sources_catalog(real_sources_path)
    iwspa = next((s for s in sources if "IWSPA" in s["name"] or "APWG" in s["name"]), None)
    assert iwspa is not None
    assert iwspa["access_type"] == "restricted"
    assert iwspa["license_verified"] is False
    assert iwspa["allowed_for_training"] is False

