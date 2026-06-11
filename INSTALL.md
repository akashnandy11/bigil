# BIGIL Installation & Startup Guide

Follow these steps to set up and run the BIGIL Nation-State APT Forensics Investigation Platform on your local workstation.

---

## 📋 Prerequisites

Ensure you have the following installed on your machine:
- **Python 3.11** or higher
- **pip** (Python package installer)

---

## 🛠️ Step-by-Step Installation

### 1. Clone or Extract the Project
Open a terminal in the directory where the BIGIL codebase is located.

### 2. Create a Virtual Environment
It is highly recommended to isolate dependencies inside a virtual environment.

**On Windows (PowerShell/CMD):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
Install all required libraries listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## 🗄️ Database Initialization & Seeding

The platform utilizes a local SQLite database file located inside the `instance/` folder. A comprehensive seeding script is provided to pre-populate users, cases, evidence registry items, timeline logs, and threat intelligence.

Run the seeder script to initialize the tables and populate the database:
```bash
python seed_data.py
```

This script will:
1. Re-create all database schema tables defined in `app/models.py`.
2. Seed 4 initial system users (Admin, Analyst, Investigator, Viewer) with their corresponding Investigator division records.
3. Seed 4 Nation-State Threat Actor profiles (Sandworm, Lazarus, APT41, APT28).
4. Seed active investigation cases, campaigns, evidence files, attack timelines, alert entries, and compliance logs.

---

## 🚀 Running the Application

Start the Flask development server:
```bash
python run.py
```

By default, the server will launch on:
**`http://localhost:5000`** (or `http://127.0.0.1:5000`)

---

## 🔑 Default Credentials

Use the following seeded credentials to log in and explore different user roles:

| Username | Role | Specialization / Title | Password |
|---|---|---|---|
| **`dcp_suresh`** | Admin | DCP Cyber Crime | `Gurugram@1234` |
| **`insp_rajendra`** | Investigator | Digital Forensics Lead | `Gurugram@1234` |
| **`si_akash`** | Analyst | Threat Intelligence | `Gurugram@1234` |
| **`sp_crime`** | Viewer | Supervisory SP | `Gurugram@1234` |

---

## 🧪 Quick Verification Checklist
Once logged in, verify the following core flows:
1. **Cyber Dashboard**: Interactive priority and incident charts load correctly.
2. **Case Management**: Check the list of active investigations, click **Open** on a case, and add a note.
3. **Digital Evidence**: Go to **Digital Evidence**, select **Ingest Evidence**, upload a log/txt file, and click **Verify Integrity**.
4. **Log Analysis**: Click **Log Analysis**, upload a sample log/csv, and run the Isolation Forest anomaly detector.
5. **Reports**: Go to **Reports**, click **Compile Case Report**, choose a case, generate it, and click **Export PDF**.
