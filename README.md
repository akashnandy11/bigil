# BIGIL – Nation-State APT Forensics Investigation Platform

**From Digital Evidence to Actionable Intelligence**

BIGIL is a command-center grade cybersecurity incident response and digital forensics platform built for the **Gurugram Police Cyber Cell**. It helps investigators reconstruct APT attack chains, catalog evidence with cryptographic integrity, track chain of custody, map IOCs, perform geospatial intelligence, analyze logs with machine learning, and compile court-admissible forensic reports.

---

## Key Modules

| Module | Description |
|--------|-------------|
| **Cyber Command Dashboard** | KPIs, case priority charts, threat alerts, and activity feeds |
| **Case Workspace** | Case management, priorities, statuses, and investigator notes |
| **Attack Timeline** | Chronological events mapped to MITRE ATT&CK techniques and phases |
| **Digital Evidence** | Secure uploads, MD5/SHA-256 hashing, chain of custody, integrity checks |
| **AI Log Analysis** | Log parsing with ML anomaly detection and threat scoring |
| **Threat Intelligence** | APT actor profiles, IOC registry, and multi-provider IOC lookup |
| **Geospatial Map** | Leaflet.js map with attack source pins and incident heatmaps |
| **Forensic Reports** | Case report compiler with client-side PDF export (jsPDF) |
| **Audit & Compliance** | Tamper-evident audit log of all user and system actions |

---

## Tech Stack

- **Backend:** Python 3.11+, Flask 3.x
- **Database:** Flask-SQLAlchemy + SQLite (`instance/bigil.db`)
- **Frontend:** HTML5, Bootstrap 5, Font Awesome 6, custom dark-theme CSS
- **Visualization:** Chart.js, Leaflet.js
- **ML Engine:** Scikit-learn, Pandas, NumPy (`ml_models/`)
- **Threat Intel:** AbuseIPDB, AlienVault OTX, VirusTotal, MalwareBazaar, URLhaus
- **Export:** html2canvas + jsPDF

---

## Prerequisites

- **Python 3.11** or higher
- **pip** (Python package manager)
- **Git** (optional, for cloning)

---

## Quick Start (Windows)

From the project root (`BIGIL/`):

```powershell
.\start.bat
```

This script creates a virtual environment if needed, installs dependencies, and starts the server.

Open **http://127.0.0.1:5000** and log in with:

- **Username:** `dcp_suresh`
- **Password:** `Gurugram@1234`

---

## Full Setup — Step-by-Step Commands

Run all commands from the **project root** (`BIGIL/`), not from the `app/` subfolder.

### A. One-Time Setup

| Sr. | Command | Purpose |
|-----|---------|---------|
| 1 | `cd path\to\BIGIL` | Navigate to project root |
| 2 | `python --version` | Verify Python 3.11+ |
| 3 | `python -m venv venv` | Create virtual environment |
| 4 | `.\venv\Scripts\activate` | Activate venv (Windows) |
| 5 | `pip install -r requirements.txt` | Install dependencies |
| 6 | `copy .env.example .env` | Create environment file |
| 7 | Edit `.env` | Set `SECRET_KEY` and optional API keys |

**macOS / Linux** — use these instead of steps 4 and 6:

```bash
source venv/bin/activate
cp .env.example .env
```

### B. Database Setup (choose one)

| Sr. | Command | Purpose |
|-----|---------|---------|
| 8a | `python seed_data.py` | **Recommended** — demo users, cases, evidence, timeline, alerts |
| 8b | `python import_real_data.py` | Import real dataset evidence (requires `datasets/` folder) |

> If you skip both, `run.py` auto-imports real data on first start when the database is empty.

### C. ML Model Training (optional but recommended)

Required for full Log Analysis and Network Analysis features. Takes approximately 5–20 minutes.

| Sr. | Command | Purpose |
|-----|---------|---------|
| 9 | `python train_all_models.py` | Train all 4 ML models at once |

**Or train individually:**

```powershell
python ml_models\train_ids_model.py    # CIC-IDS2017 intrusion detection
python ml_models\train_unsw_model.py   # UNSW-NB15 attack classification
python ml_models\train_log_model.py    # Log anomaly detection
python ml_models\train_ctu_model.py    # Botnet traffic detection
```

### D. Start the Application

| Sr. | Command | Purpose |
|-----|---------|---------|
| 10 | `python run.py` | Start the Flask development server |

### E. Access the App

| Sr. | Action | Details |
|-----|--------|---------|
| 11 | Open browser | **http://127.0.0.1:5000** |
| 12 | Log in | See [Default Credentials](#default-credentials) below |

### F. Stop the Server

| Sr. | Action | Purpose |
|-----|--------|---------|
| 13 | Press `Ctrl + C` | Stop the running server |

---

## Copy-Paste: Complete Windows Flow

```powershell
cd c:\Users\Akash\Downloads\BIGIL
python --version
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python seed_data.py
python train_all_models.py
python run.py
```

---

## Default Credentials

| Username | Role | Title | Password |
|----------|------|-------|----------|
| `dcp_suresh` | Admin | DCP Cyber Crime | `Gurugram@1234` |
| `insp_rajendra` | Investigator | Digital Forensics Lead | `Gurugram@1234` |
| `si_akash` | Analyst | Threat Intelligence | `Gurugram@1234` |
| `sp_crime` | Viewer | Supervisory SP | `Gurugram@1234` |

---

## Environment Variables

Copy `.env.example` to `.env` and configure as needed:

```env
# Flask
SECRET_KEY=your-secret-key
FLASK_ENV=development
FLASK_DEBUG=True

# Server (optional overrides)
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Database
DATABASE_URL=sqlite:///instance/bigil.db

# Threat Intelligence API Keys (optional)
ABUSEIPDB_API_KEY=
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
MALWAREBAZAAR_API_KEY=
URLHAUS_API_KEY=
```

Restart the server after editing `.env`.

**Custom port example:**

```powershell
$env:FLASK_PORT="8080"
python run.py
```

---

## Verification Checklist

After logging in, confirm these core flows work:

1. **Dashboard** — Charts and KPIs load correctly
2. **Case Workspace** — Open a case and add an investigator note
3. **Digital Evidence** — Upload a file and verify integrity hashes
4. **Log Analysis** — Upload a log/CSV and run anomaly detection
5. **Threat Intel** — Look up an IP or domain IOC
6. **Reports** — Compile a case report and export to PDF
7. **Audit Log** — Confirm login and actions are recorded

---

## Project Structure

```
BIGIL/
├── app/                         # Flask application package
│   ├── __init__.py              # App factory and blueprint registry
│   ├── models.py                # SQLAlchemy database models
│   ├── auth/                    # Login and authentication
│   ├── dashboard/               # Command dashboard
│   ├── workspace/               # Case management
│   ├── timeline/                # Attack timeline reconstruction
│   ├── evidence/                # Evidence and chain of custody
│   ├── logs/                    # Log and network flow analysis
│   ├── threat_intel/            # IOC registry and lookup UI
│   ├── apt/                     # APT campaigns and actor profiles
│   ├── geo/                     # Geospatial intelligence map
│   ├── reports/                 # Forensic report generator
│   └── audit/                   # Compliance audit log
├── ml_models/                   # ML training scripts and saved models
├── threat_intel_engine/         # Multi-provider IOC lookup engine
├── static/                      # CSS, JavaScript, assets
├── templates/                   # Jinja2 HTML templates
├── instance/                    # SQLite database (created at runtime)
├── uploads/                     # Uploaded evidence files
├── config.py                    # Application configuration
├── run.py                       # Application entry point
├── seed_data.py                 # Demo database seeder
├── import_real_data.py          # Real dataset importer
├── train_all_models.py          # Train all ML models
├── start.bat                    # Windows one-click launcher
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
└── README.md                    # This file
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Activate the venv and run `pip install -r requirements.txt` |
| Port already in use | Set a different port: `$env:FLASK_PORT="8080"` then `python run.py` |
| ML features show "model not trained" | Run `python train_all_models.py` |
| Empty database | Run `python seed_data.py` or restart `run.py` on a fresh DB |
| Threat intel lookup fails | Add API keys to `.env` and restart the server |
| Wrong working directory | Always run commands from `BIGIL/` root, not `BIGIL/app/` |

---

## License

Internal use — Gurugram Police Cyber Cell.
