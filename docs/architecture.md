# MAILTRACE 2.0 System Architecture

## Overview
MAILTRACE 2.0 is an enterprise-grade AI-powered email forensics and threat intelligence platform.

## High-Level Data Flow
```
Gmail / Outlook Browser Window
       │
       ▼
[ Browser Extension ] (Manifest V3 - React + TS)
       │
       ▼ (REST API / JSON Payload)
[ FastAPI Backend ] (Python + Uvicorn)
       ├──► [ Header Forensics & SPF/DKIM/DMARC Parser ]
       ├──► [ IOC Extraction Engine ] (IPs, Domains, Hashes, URLs)
       ├──► [ RoBERTa Neural Threat Engine ] (PyTorch / Transformers)
       ├──► [ Threat Intelligence APIs ] (VirusTotal, MaxMind GeoIP)
       └──► [ Explainable Risk Engine ]
       │
       ▼
[ PostgreSQL Storage ] (SQLAlchemy / Alembic)
       │
       ▼
[ SOC Investigation Dashboard ] (React + TS + Vite + Framer Motion)
```

## Service Component Breakdown

1. **`apps/extension`**: Chrome/Edge Manifest V3 extension. Ingests raw email source from active webmail session without requesting excessive browser permissions.
2. **`services/api`**: Async FastAPI service handling authentication, CORS middleware, rate limiting, and request routing to analytical modules.
3. **`ai/threat-engine`**: RoBERTa-based deep learning sequence classifier evaluating email subject, body semantic context, and social engineering indicators.
4. **`apps/dashboard`**: Security Operations Center (SOC) investigation interface providing forensic visualizers, timeline analysis, and evidence export.
5. **`shared/types`**: Monorepo TypeScript contracts enforcing strict end-to-end API type safety.
6. **`database/`**: PostgreSQL configuration and migration scripts.
