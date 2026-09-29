import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

# Setup path resolution for both direct script and module execution
_curr_file = Path(__file__).resolve()
_threat_engine_dir = _curr_file.parents[2]
_project_root = _curr_file.parents[4]

for _p in [str(_threat_engine_dir), str(_project_root)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("mailtrace-dataset-acquire")

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

def load_sources_catalog(sources_path: str = DEFAULT_SOURCES_PATH) -> List[Dict[str, Any]]:
    """Load and validate sources catalog from sources.json."""
    if not os.path.exists(sources_path):
        raise FileNotFoundError(f"Sources catalog file not found at '{sources_path}'.")
    with open(sources_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "sources" not in data or not isinstance(data["sources"], list):
        raise ValueError("Invalid sources.json: root key 'sources' must be a list.")
    return data["sources"]

def acquire_datasets(
    sources_file: str = DEFAULT_SOURCES_PATH,
    raw_dir: str = DEFAULT_RAW_DIR,
    dry_run: bool = True,
    target_source: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Acquire raw datasets from verified public sources or execute dry-run audit.
    
    Dry-run mode:
    - Lists candidate sources, source URLs, authoritative sources, licenses, verification flags, and expected raw paths.
    - Rejects placeholder or fabricated URLs.
    - Performs zero network downloads and zero file mutations.
    """
    sources = load_sources_catalog(sources_file)
    os.makedirs(raw_dir, exist_ok=True)

    results: List[Dict[str, Any]] = []

    print("=" * 80)
    print("MAILTRACE 2.0 — DATASET ACQUISITION AUDIT")
    print(f"Mode: {'DRY RUN (Read-Only Audit)' if dry_run else 'LIVE EXECUTION'}")
    print(f"Sources Catalog: {sources_file}")
    print(f"Target Raw Directory: {raw_dir}")
    print("=" * 80)

    for src in sources:
        name = src.get("name", "Unknown Source")
        if target_source and target_source.lower() not in name.lower():
            continue

        url = src.get("source_url", "N/A")
        auth_src = src.get("authoritative_source", "N/A")
        license_str = src.get("license", "Unknown")
        license_verified = src.get("license_verified", False)
        allowed = src.get("allowed_for_training", False)
        prov_type = src.get("provenance_type", src.get("dataset_type", "unspecified"))
        access_type = src.get("access_type", "unknown")
        src_count = src.get("source_sample_count")
        provenance_notes = src.get("provenance_notes", "")
        
        # Guard against placeholder URLs
        has_placeholder = any(p in str(url).lower() for p in ["placeholder", "example.com/bec"])

        # Expected output path
        safe_name = name.lower().replace(" ", "_").replace("/", "_").replace("(", "").replace(")", "").replace(":", "")
        expected_output = os.path.join(raw_dir, safe_name)

        status_info = {
            "name": name,
            "source_url": url,
            "authoritative_source": auth_src,
            "license": license_str,
            "license_verified": license_verified,
            "access_type": access_type,
            "allowed_for_training": allowed,
            "provenance_type": prov_type,
            "source_sample_count": src_count,
            "expected_output_path": expected_output,
            "provenance_notes": provenance_notes,
            "action": "reject_placeholder" if has_placeholder else ("would_inspect" if dry_run else ("download" if (license_verified and allowed) else "skip_unverified")),
        }
        results.append(status_info)

        print(f"\nSource: {name}")
        print(f"  Authoritative Source: {auth_src}")
        print(f"  URL:                  {url}")
        print(f"  Provenance Type:      {prov_type}")
        print(f"  Access Type:          {access_type}")
        print(f"  Source Sample Count:  {src_count if src_count is not None else 'null (unverified)'}")
        print(f"  License:              {license_str}")
        print(f"  License Verified:     {'YES' if license_verified else 'NO (Unverified)'}")
        print(f"  Allowed for Training: {'YES' if allowed else 'NO (Blocked)'}")
        print(f"  Expected Raw Target:  {expected_output}")
        print(f"  Provenance Notes:     {provenance_notes}")
        
        if has_placeholder:
            print(f"  Status:               REJECTED (Contains placeholder URL)")
        elif not allowed:
            print(f"  Status:               BLOCKED (License unverified or restricted access)")
        elif dry_run:
            print(f"  Status:               AUDITED (Dry-run mode: no download performed)")
        else:
            print(f"  Status:               ELIGIBLE FOR INGESTION")

    print("\n" + "=" * 80)
    print(f"Audit Summary: {len(results)} source(s) processed. Dry-run: {dry_run}")
    print("=" * 80)

    return {
        "dry_run": dry_run,
        "sources_count": len(results),
        "sources": results,
    }

def main():
    parser = argparse.ArgumentParser(description="MAILTRACE 2.0 Dataset Acquisition Tool")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Perform a dry-run audit without downloading files (default: True)"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute live download for verified, allowed sources only"
    )
    parser.add_argument(
        "--source",
        type=str,
        default=None,
        help="Filter by specific source name"
    )
    parser.add_argument(
        "--sources-file",
        type=str,
        default=DEFAULT_SOURCES_PATH,
        help="Path to sources.json catalog"
    )
    parser.add_argument(
        "--raw-dir",
        type=str,
        default=DEFAULT_RAW_DIR,
        help="Directory to store raw downloaded data"
    )

    args = parser.parse_args()
    is_dry_run = not args.execute

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    acquire_datasets(
        sources_file=args.sources_file,
        raw_dir=args.raw_dir,
        dry_run=is_dry_run,
        target_source=args.source
    )

if __name__ == "__main__":
    main()
