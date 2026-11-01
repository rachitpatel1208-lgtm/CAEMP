# 🛡️ CAEMP // OMNITRIX EDITION — Unified Cybersecurity Platform
## Integrated: CAEMP Cyber Asset Exposure + PhishGuard Live URL Threat Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask_3.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![Scanner](https://img.shields.io/badge/Engine-Nmap_%2B_ML_Ensemble-00FF41.svg)](https://nmap.org/)
[![Theme](https://img.shields.io/badge/Aesthetic-Galvan_Omnitrix_Level--20-00FF41.svg)](#)

A unified, full-stack cybersecurity platform combining **CAEMP (Cyber Asset Exposure Monitoring Platform)** and **PhishGuard (Multi-Model AI URL Threat Inspector)** under a sleek, hardware-inspired **Omnitrix Galvan Level-20 interface**.

Switch effortlessly between **CAEMP** and **PhishGuard** from the unified top bar navigation!

---

## 🌟 Dual Core Capabilities

### 🟢 Section 1: CAEMP Exposure Monitoring
- 🔍 **Automated Nmap Scanning Engine**: Background host discovery, port enumeration, and service version detection using asynchronous job threading.
- ⚡ **Real-Time Scan Progress**: Visual multi-stage status loader polling 6 execution phases.
- 🛡️ **Risk Scoring Engine**: Custom weighted risk scoring algorithm evaluating service severity.
- 🌐 **NIST NVD CVE Integration**: Queries NIST API 2.0 to dynamically fetch known CVE IDs and CVSS scores.
- 🔄 **Exposure Drift Analysis**: Automatically compares scan findings against baselines.
- 📊 **Executive Dashboard**: Asset counts, critical findings, severity charts, and historical trends.

### 🛡️ Section 2: PhishGuard Live URL Inspector
- 🧠 **Triple ML Ensemble Consensus**:
  1. **Lexical Random Forest**: Structural URL & lexical feature vector classifier
  2. **Char N-Gram TF-IDF**: Subword token pattern recognition for obfuscated phishing kits
  3. **Gradient Boosting Ensemble**: Non-linear decision tree ensemble
- 🚨 **Brand Lookalike & Typosquatting Detection**: Identifies deceptive visual homoglyphs and unauthorized domain clones mimicking top brands (PayPal, Google, Apple, Chase, etc.).
- 📡 **Live Cryptographic & Host Telemetry**: Real-time port 443 SSL/TLS certificate validation, issuer checking, and live DNS resolution.
- 🔍 **Structural Heuristic Checklist**: HTTPS encryption status, high-risk TLDs (.xyz, .icu, .top), numeric IPs, URL shorteners, and sensitive path tokens.
- 🤖 **Omnitrix AI Threat Advisory**: Generates actionable defensive countermeasures and risk explanations.
- 📜 **Persistent URL Threat History**: Automatic SQLite storage of URL evaluations with instant re-scan.


---

## 🏗️ Architecture & Project Structure

```
caemp/
├── app.py                  # Flask backend, scan orchestrator, SQLite persistence, NVD CVE integration
├── requirements.txt        # Python package dependencies (Flask, python-nmap, requests)
├── scan_history.db         # SQLite database (auto-created & migrated on startup)
├── reports/                # Generated CSV vulnerability report cards
├── static/
│   ├── css/
│   │   └── style.css       # Enterprise design system (tokens, components, badges, charts)
│   └── js/
│       ├── scan.js         # Scan initialization, status polling & progress overlay
│       ├── dashboard.js    # Executive dashboard stats & Chart.js visualizations
│       ├── results.js      # Scan results, CVE tables, severity breakdown & recommendations
│       └── history.js      # History search, risk filtering & dynamic column sorting
└── templates/
    ├── base.html           # Core layout with sidebar navigation & top bar
    ├── dashboard.html      # Executive Security Dashboard page
    ├── results.html        # Per-scan detailed findings & CVE breakdown
    ├── history.html        # Searchable scan archive page
    └── reports.html        # Downloadable report repository page
```

---

## 📋 Prerequisites & Requirements

### 1. Nmap Network Scanner (Required)
CAEMP relies on the system `nmap` binary via `python-nmap`. You must install Nmap on your host machine:

- **Debian / Ubuntu**:
  ```bash
  sudo apt-get update && sudo apt-get install -y nmap
  ```
- **macOS** (via Homebrew):
  ```bash
  brew install nmap
  ```
- **Windows**:
  Download and run the installer from the official [Nmap Download Page](https://nmap.org/download.html). Ensure `nmap.exe` is added to your system `PATH`.

### 2. Python Environment
- Python **3.8+** installed.

---

## 🚀 Quick Start & Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/digucodes/caemp.git
   cd caemp
   ```

2. **Create and activate a virtual environment**:
   - **Linux / macOS**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - **Windows**:
     ```powershell
     python -m venv .venv
     \.venv\Scripts\activate
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the platform**:
   ```bash
   python app.py
   ```

5. **Access the Dashboard**:
   Open your browser and navigate to `http://127.0.0.1:5000`.

---

## ⚙️ How Scanning & Workflows Function

```
[User Request] ──> POST /api/scan ──> [Background Thread]
                                             │
   ┌─────────────────────────────────────────┴─────────────────────────────────────────┐
   │ 1. Host Discovery ──> 2. Port Enumeration ──> 3. Service & Version Detection      │
   │ 4. Risk Scoring   ──> 5. Baseline Delta    ──> 6. NVD CVE Lookup & CSV Report      │
   └─────────────────────────────────────────┬─────────────────────────────────────────┘
                                             ▼
                             [SQLite DB & CSV Report Saved]
                                             │
    Polling GET /api/scan/<id>/status ───────┴───────> Redirect to /scan/<id> Results Page
```

1. **Triggering Scans**: Initiating a scan dispatches an asynchronous worker thread in `app.py` and returns a job UUID.
2. **Polling & Progress**: The UI polls `/api/scan/<id>/status` every ~900ms to update the loading overlay across all 6 execution stages.
3. **Results & Intelligence**: Once complete, the browser redirects to `/scan/<id>` displaying findings, CVE matches from NIST NVD, CVSS metrics, exposure diffs, and security recommendations.

---

## 🔌 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan` | Initiates a background scan for target IP/domain. Returns `scan_id`. |
| `GET` | `/api/scan/<scan_id>/status` | Retrieves real-time status, execution stage, and completion flag. |
| `GET` | `/api/scan/<scan_id>` | Returns findings, risk scores, and baseline exposure diff for a completed scan. |
| `GET` | `/api/cves/<scan_id>` | Fetches mapped NIST NVD CVE details, CVSS scores, and descriptions. |
| `GET` | `/api/dashboard/stats` | Aggregates system metrics, recent findings, and charts data for the dashboard. |
| `GET` | `/reports/download/<scan_uid>` | Downloads the compiled CSV security report for a specific scan. |

---

## ⚠️ Security & Legal Disclaimer

> **IMPORTANT**: CAEMP is intended strictly for authorized security auditing, vulnerability assessment, and administrative monitoring on systems and networks you own or have explicit permission to test. Unauthorized port scanning or security testing against third-party systems is illegal and violates computer misuse laws. The developers assume no liability for misuse or damage caused by this program.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
