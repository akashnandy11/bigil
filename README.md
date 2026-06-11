# BIGIL – Nation-State APT Forensics Investigation Platform

🛡️ **From Digital Evidence to Actionable Intelligence**

BIGIL is a professional, command-center grade cybersecurity incident response and digital forensics platform designed for the **Gurugram Police Cyber Cell**. It helps cybercrime investigators, forensic analysts, and threat intelligence units reconstruct sophisticated Advanced Persistent Threat (APT) attack chains, securely catalog evidence with cryptographic integrity, track Chain of Custody, map indicators of compromise (IOCs), perform geospatial targeting intelligence, analyze logs with machine learning anomaly detection, and compile court-admissible forensic reports.

---

## 🚀 Key Modules

### 1. Cyber Command Dashboard
- High-level KPIs mapping active investigations, critical alerts, registry integrity, and threat actors.
- Interactive Chart.js graphs mapping case priority distribution and category breakdown.
- Real-time system activity logs and active threat alerts feed.

### 2. Case Workspace
- Case Management tracking priorities (Critical, High, Medium, Low), statuses (Open, Active, Pending, Closed), and victim organizations.
- Investigator note editor for keeping technical and intelligence logs.
- Evidence registry linking and alert aggregations.

### 3. Attack Timeline Reconstruction
- Visual, interactive timeline of security events mapped in chronological sequence.
- Events classified by **MITRE ATT&CK** techniques and attack phases (Recon, Initial Access, Execution, Persistence, Lateral Movement, Exfiltration).
- Details of source/destination IPs and analyst notes.

### 4. Digital Evidence Repository
- Secure file upload and ingestion.
- Cryptographic hash generation (MD5 and SHA-256 computed on upload).
- Full Chain of Custody tracking history recording custodian names, badges, locations, and actions.
- Actionable integrity verification controls.

### 5. AI Log Analysis Engine
- Upload security log dumps (CSV, JSON, text) to parse parameters.
- Integrates a **Scikit-learn Isolation Forest** model for machine learning anomaly detection.
- Automatically flags outlier events, computes threat risk scores, and displays top alerts.

### 6. Threat Intelligence Center
- Knowledge base of advanced persistent threat actor groups (e.g. Lazarus, APT28, APT41, Sandworm) with risk ratings and targeting sectors.
- Mapped MITRE ATT&CK technique matrix showing cross-group TTP correlations.
- IOC database registry with IP, domain, and file signature lookup engine.

### 7. Geospatial Intelligence Map
- Interactive Leaflet.js map with OpenStreetMap tiles.
- Pins attack source coordinates, maps infrastructure targets, and displays incident heatmaps.

### 8. Forensic Report Generator
- Unified report compiler pulling case details, timeline events, evidence integrity hash tables, and triggered alerts.
- Customized Gurugram Police Cyber Cell layout with signature blocks and confidentiality markings.
- Client-side **jsPDF** integration to export report pages into print-ready PDF files.

### 9. Audit & Compliance
- Tamper-evident, read-only log recording every user login/logout, database modification, report generation, and evidence access event.
- User activity histogram mapping logs recorded over the last 7 days.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.11 + Flask 3.x
- **ORM & Database**: Flask-SQLAlchemy + SQLite (instance/bigil.db)
- **Frontend**: HTML5 + Vanilla CSS + Bootstrap 5 + FontAwesome 6
- **Visualization**: Chart.js 4.x + Leaflet.js (Geospatial maps)
- **AI/ML Engine**: Scikit-Learn (Isolation Forest) + Pandas + Numpy
- **Exporting**: html2canvas + jsPDF (client-side PDF generation)

---

## 📂 Project Structure

```
BIGIL/
├── app/
│   ├── __init__.py              # Flask app factory & blueprint registry
│   ├── models.py                # Database schema (SQLAlchemy ORM)
│   ├── auth/                    # Authentication (login, logout)
│   ├── dashboard/               # Cyber Command Dashboard blueprint
│   ├── apt/                     # APT campaign and actor profile blueprints
│   ├── logs/                    # AI Log analyzer & parsing blueprint
│   ├── evidence/                # Evidence & Chain of custody blueprint
│   ├── timeline/                # Chronological timeline Blueprint
│   ├── threat_intel/            # IOC registry and lookup blueprint
│   ├── workspace/               # Case and note management blueprint
│   ├── geo/                     # Geospatial Leaflet map blueprint
│   ├── reports/                 # Forensic report compiler blueprint
│   └── audit/                   # Compliance logging blueprint
├── static/
│   ├── css/
│   │   └── main.css             # Harmonious dark-theme CSS design system
├── templates/                   # HTML templates partitioned by blueprint
├── config.py                    # App configuration profiles
├── run.py                       # App entry point launcher
├── seed_data.py                 # Initial data seeder script
├── requirements.txt             # Python packages list
├── README.md                    # Main documentation
└── INSTALL.md                   # Installation guidelines
```
