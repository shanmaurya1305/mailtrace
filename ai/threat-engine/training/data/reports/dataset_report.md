# MAILTRACE 2.0 — Phase 2B Part 2A Dataset Provenance & Readiness Report

**Generated**: `2026-09-27T11:58:24.878829+00:00`

**Dataset Readiness**: `NOT READY FOR TRAINING`
**Training Allowed**: `NO`

## 1. Class Distribution

| Canonical Class | Count | Percentage |
| :--- | :---: | :---: |
| `benign` | 0 | 0.0% |
| `suspicious` | 0 | 0.0% |
| `phishing` | 0 | 0.0% |
| `business_email_compromise` | 0 | 0.0% |
| **Total** | **0** | **100%** |

## 2. Dataset Count Semantics

| Source Name | Source Count (Available) | Downloaded | Normalized |
| :--- | :---: | :---: | :---: |
| Enron Email Dataset | `500000` | `0` | `0` |
| Apache SpamAssassin Public Corpus | `6047` | `0` | `0` |
| Nazario Phishing Corpus | `null (unverified)` | `0` | `0` |
| BEC-2 Research Corpus | `279` | `0` | `0` |
| IWSPA APWG Phishing Corpus | `null (unverified)` | `0` | `0` |

## 3. Data Quality & Duplicates

* **Total Samples**: `0`
* **Exact Content Duplicates**: `0`
* **Cross-Source Duplicates**: `0`
* **Empty Text Records**: `0`
* **Invalid Target Labels**: `0`
* **Missing Subject Headers**: `0`

## 4. Source Verification & Provenance Status

| Source Name | Provenance Type | License | License Verified | Training Allowed |
| :--- | :--- | :--- | :---: | :---: |
| Enron Email Dataset | `authentic` | Public investigatory record released for research (no explicit formal open-source license grant) | NO | NO |
| Apache SpamAssassin Public Corpus | `authentic` | Apache SpamAssassin testing corpus / donated user email (software is Apache 2.0; individual donated emails lack separate license grants) | NO | NO |
| Nazario Phishing Corpus | `authentic` | No explicit license provided on distribution site (public research archive of adversarial emails) | NO | NO |
| BEC-2 Research Corpus | `generated_from_real_world_bec_examples` | Unverified / Author distribution upon research request | NO | NO |
| IWSPA APWG Phishing Corpus | `anonymized_research_shared_task` | Restricted APWG Member Agreement / Institutional NDA Required | NO | NO |

## 5. Explicit Project Limitations

> **BEC Limitation**: Public BEC data is substantially more limited than general legitimate/phishing email data. BEC-2 provides 279 generated samples based on real-world BEC examples rather than a large authentic mailbox corpus.

> **Suspicious Class Limitation**: No verified source currently supplies a defensible standalone suspicious label. Suspicious count remains 0 to prevent label fabrication.

## 6. Blocking Reasons

- ❌ **Target dataset file missing: 'C:\Users\nairo\Desktop\MAILTRACE\ai\threat-engine\training\data\dataset.csv' does not exist.**

