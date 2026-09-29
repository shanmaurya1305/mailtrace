# MAILTRACE AI Threat Engine Architecture

## Overview
The `ai/threat-engine` module houses the ML pipeline responsible for analyzing email content (headers, body text, metadata) to classify emails into risk categories: Phishing, BEC (Business Email Compromise), Spoofing, or Social Engineering.

## Planned Stack
* **Framework**: PyTorch
* **Transformers**: Hugging Face `transformers`
* **Base Model**: Fine-tuned RoBERTa (`roberta-base` / `roberta-large`) for sequence classification

## Current Implementation Status
> **Phase 1: Deterministic Forensic Engine & SOC Workbench (Active); Phase 2: Neural Threat Pipeline (Abstracted & Ready for Weights)**

The AI threat engine interface contracts (`model_interface.py`), tokenizer wrappers (`tokenizer.py`), inference execution wrapper (`inference.py`), and dataset preprocessing/training scripts (`training/`) are fully implemented and integrated with the investigation pipeline. When trained RoBERTa model weights are not loaded locally, the engine safely reports `status: "model_unavailable"` without generating synthetic or fabricated scores. Model weights (`pytorch_model.bin` or `model.safetensors`) can be dropped into `models/roberta-threat-classifier/` for instant live activation.
