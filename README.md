# MAILTRACE 2.0 - AI-Powered Email Forensics & Threat Intelligence Platform

> **Current Status**: **Phase 1: Deterministic Forensic Engine & SOC Workbench (Active); Phase 2: Neural Threat Pipeline (Abstracted & Ready for Weights)**
> This repository represents the active architecture for MAILTRACE 2.0. Phase 1 implements RFC 822 email header parsing, Received hop timeline reconstruction, SPF/DKIM/DMARC authentication verification, IOC extraction, deterministic evidence logging, a Chrome Manifest V3 extension, and the React+TS SOC dashboard with live JSON report export. No mock security threat data or fake detection scores are generated.

---

## 🚀 Overview

**MAILTRACE 2.0** is an advanced AI-powered email forensics and threat-intelligence platform designed for Security Operations Center (SOC) analysts and cybersecurity investigators. It analyzes email headers, body content, SPF/DKIM/DMARC authentication records, infrastructure IOCs, and neural sequence patterns to identify phishing, BEC (Business Email Compromise), spoofing, and social engineering attacks.

---

## 🏗️ Monorepo Folder Structure

```
MAILTRACE/
├── apps/
│   ├── extension/             # Chrome/Edge Manifest V3 Popup (React + TS + Vite + Tailwind)
│   └── dashboard/             # SOC Forensics Dashboard Shell (React + TS + Vite + Tailwind + Framer Motion)
├── services/
│   └── api/                   # FastAPI Backend Service (Python + Pydantic + Uvicorn)
├── ai/
│   └── threat-engine/         # RoBERTa Threat Classifier Architecture Specs & Abstract Interfaces
├── database/
│   ├── migrations/            # Database Alembic Migration Scripts Placeholder
│   └── seeds/                 # Database Seed Files Placeholder
├── shared/
│   └── types/                 # Shared TypeScript API contracts
├── docs/                      # Architectural specs & security guidelines
├── tests/                     # Integration and monorepo verification tests
├── docker/                    # Container configuration files
├── .env.example               # Root environment variables template
├── .gitignore                 # Git ignore rules
├── README.md                  # Developer documentation
└── docker-compose.yml         # PostgreSQL infrastructure config
```

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Browser Extension** | Manifest V3, React, TypeScript, Vite, Tailwind CSS |
| **SOC Dashboard** | React, TypeScript, Vite, Tailwind CSS, React Router, Framer Motion |
| **Backend API** | Python 3.10+, FastAPI, Pydantic v2, Uvicorn, Pytest |
| **AI Threat Engine** | Python, PyTorch, Hugging Face Transformers (RoBERTa Architecture) |
| **Database** | PostgreSQL 16, SQLAlchemy, Alembic |
| **Infrastructure** | Docker, Docker Compose |

---

## 📋 Prerequisites

* **Python**: 3.10 or higher
* **Node.js**: v18.0.0 or higher
* **npm**: v9.0.0 or higher
* **Docker & Docker Desktop** (for PostgreSQL database)

---

## ⚙️ Development Setup (Windows PowerShell)

### 1. Environment Setup

The platform uses environment variables to configure ports, cross-origin security (CORS), service URLs, and future pipeline extensions.

#### Do Frontend and Backend Require Separate `.env` Files?
**Yes.** The backend (FastAPI) and frontend (Vite React) operate in separate runtime environments and use dedicated configuration files:
1. **Root / Backend Configuration (`.env` or `services/api/.env`)**: Read server-side by Python `pydantic-settings` for API port, allowed CORS origins, and AI engine paths.
2. **SOC Dashboard Configuration (`apps/dashboard/.env`)**: Read client-side at Vite build/dev time (`import.meta.env.VITE_API_BASE_URL`) to connect the React browser interface to the FastAPI backend.
3. **Browser Extension Configuration (`apps/extension/.env`)**: Read client-side by Vite (`import.meta.env.VITE_API_BASE_URL` and `import.meta.env.VITE_DASHBOARD_URL`).

---

#### Step 1A: Configure Monorepo Root & Backend (`.env`)

In the project root, copy `.env.example` to create `.env`:

```powershell
Copy-Item .env.example .env
```

| Variable Name | Required? | Location / Service | Purpose / Description | Value Origin | Safe Placeholder / Default |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `API_PORT` | **Yes** (Defaulted) | Backend (`services/api`) | TCP port on which FastAPI / Uvicorn server listens | Locally configured | `8000` |
| `ALLOWED_CORS_ORIGINS` | **Yes** (Defaulted) | Backend (`services/api`) | Comma-separated trusted web origins allowed to make browser API calls | Locally configured | `http://localhost:5173,http://localhost:5174,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:5174,http://127.0.0.1:3000` |
| `DATABASE_URL` | *Optional (Phase 5)* | Backend / PostgreSQL | Connection string for PostgreSQL database | Locally generated | `postgresql://mailtrace_user:change_me_in_production@localhost:5432/mailtrace_db` |
| `POSTGRES_DB` | *Optional (Phase 5)* | Docker Compose | Database name in PostgreSQL container | Locally generated | `mailtrace_db` |
| `POSTGRES_USER` | *Optional (Phase 5)* | Docker Compose | Database username | Locally generated | `mailtrace_user` |
| `POSTGRES_PASSWORD` | *Optional (Phase 5)* | Docker Compose | Database password | Locally generated | `change_me_in_production` |
| `POSTGRES_PORT` | *Optional (Phase 5)* | Docker Compose | Host port mapped to PostgreSQL container | Locally configured | `5432` |
| `VIRUSTOTAL_API_KEY` | *Optional (Phase 4)* | Threat Intel API | API key for external file/URL reputation lookup | External service (VirusTotal) | `your_virustotal_api_key_here` |
| `MAXMIND_ACCOUNT_ID` | *Optional (Phase 4)* | GeoIP Intel | Account identifier for GeoIP city/ISP resolution | External service (MaxMind) | `your_maxmind_account_id_here` |
| `MAXMIND_LICENSE_KEY` | *Optional (Phase 4)* | GeoIP Intel | License key for GeoLite2 databases | External service (MaxMind) | `your_maxmind_license_key_here` |
| `OPENAI_API_KEY` | *Optional (Phase 4)* | LLM Explanation | API key for natural language threat summaries | External service (OpenAI) | `your_openai_api_key_here` |
| `GEMINI_API_KEY` | *Optional (Phase 4)* | LLM Explanation | API key for natural language threat summaries | External service (Google AI) | `your_gemini_api_key_here` |
| `JWT_SECRET` | *Optional (Phase 5)* | Auth Security | Cryptographic secret for signing JWT analyst tokens | Locally generated secret (min 32 chars) | `your_jwt_secret_key_here_min_32_chars` |

---

#### Step 1B: Configure SOC Dashboard (`apps/dashboard/.env`)

In `apps/dashboard`, copy `.env.example` to create `.env`:

```powershell
Copy-Item apps/dashboard/.env.example apps/dashboard/.env
```

| Variable Name | Required? | Location / Service | Purpose / Description | Value Origin | Safe Placeholder / Default |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | **Yes** (Defaulted) | Frontend (`apps/dashboard`) | Backend base URL called by React client for health checks & investigations | Locally configured | `http://localhost:8000` |

---

#### Step 1C: (Optional) Configure Extension (`apps/extension/.env`)

If customizing browser extension ports, create `apps/extension/.env`:

| Variable Name | Required? | Location / Service | Purpose / Description | Value Origin | Safe Placeholder / Default |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `VITE_API_BASE_URL` | *Optional* | Extension (`apps/extension`) | Backend API base URL for investigation payload forwarding | Locally configured | `http://127.0.0.1:8000` |
| `VITE_DASHBOARD_URL` | *Optional* | Extension (`apps/extension`) | Target URL for deep-linking into SOC workbench | Locally configured | `http://localhost:5173` |

---

### 2. Backend Setup (`services/api`)

Navigate to the API service directory and start the server:

```powershell
cd services/api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

* Backend API will run on `http://localhost:8000`
* Health Check Endpoint: `http://localhost:8000/api/health`

---

### 3. SOC Dashboard Setup (`apps/dashboard`)

Open a new PowerShell terminal, navigate to the dashboard app:

```powershell
cd apps/dashboard
npm install
npm run dev
```

* Dashboard will run on `http://localhost:5173`
* Uses `import.meta.env.VITE_API_BASE_URL` (configured in `apps/dashboard/.env`) to query the backend API health status.

---

### 4. Extension Setup (`apps/extension`)

Open a new PowerShell terminal, navigate to the extension app:

```powershell
cd apps/extension
npm install
npm run build
```

* Built Manifest V3 extension files will be emitted to `apps/extension/dist/`.
* To load into Chrome/Edge: Go to `chrome://extensions/` -> Enable **Developer mode** -> Click **Load unpacked** -> Select the `apps/extension/dist/` folder.

---

### 5. PostgreSQL Setup (Docker Compose)

Start the database container using Docker Compose:

```powershell
docker compose up -d
```

---

## 🧪 Testing & Verification

Run backend unit tests:

```powershell
cd services/api
.\.venv\Scripts\Activate.ps1
pytest
```

---

## 🔒 Security Principles

1. **No Hardcoded Secrets**: Secrets and API keys remain strictly in server-side `.env` files.
2. **Untrusted Input Handling**: Email content is sanitized; `eval()` and unsafe HTML dynamic injection are forbidden.
3. **Execution Safety**: Attachments are never automatically executed; links are never automatically followed.
4. **CORS Control**: Dynamic CORS configuration enforcing explicitly trusted origins.
5. **Decoupled API URL**: Dashboard client reads backend base URL from `import.meta.env.VITE_API_BASE_URL`.

---

## 📍 Phase Roadmap

- [x] **Phase 0**: Monorepo Foundation, FastAPI Health Check, Dashboard Shell, Manifest V3 Extension Popup, Docker Setup.
- [x] **Phase 1**: Header Parsing Engine, Received Hop Analyzer, SPF/DKIM/DMARC Forensic Validator, IOC Extractor, and Downloadable Forensic JSON Report.
- [ ] **Phase 2**: RoBERTa Neural Threat Inference Pipeline (Model weights deployment).
- [x] **Phase 3**: Chrome Extension Gmail Ingestion (Zero-permission DOM extraction popup).
- [ ] **Phase 4**: VirusTotal & MaxMind GeoIP Intelligence Integration.
- [ ] **Phase 5**: Persistent Case Management Database (PostgreSQL) & PDF Evidence Report Export.
