# 🛡️ Cyber Asset Exposure Monitoring Platform (CAEMP)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask_3.0%2B-green.svg)](https://flask.palletsprojects.com/)
[![Scanner](https://img.shields.io/badge/Engine-Nmap-orange.svg)](https://nmap.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An enterprise-style vulnerability management & asset exposure monitoring platform inspired by **Tenable Nessus**, **Qualys VMDR**, and **Rapid7 InsightVM**.

CAEMP enables security teams and network administrators to run automated Nmap-based exposure scans, score risk metrics, cross-reference real-time NIST NVD CVE data, diff exposure against baseline scans, browse scan history, and generate downloadable executive CSV reports.

---

## 🌟 Key Features

- 🔍 **Automated Nmap Scanning Engine**: Performs background host discovery, port enumeration, and service version detection using asynchronous job threading.
- ⚡ **Real-Time Scan Progress**: Visual multi-stage status loader polling 6 distinct execution phases: Discovery, Port Enumeration, Service Detection, Risk Scoring, Exposure Diff, and Report Generation.
- 🛡️ **Risk Scoring Engine**: Custom weighted risk scoring algorithm evaluating service severity (e.g., Telnet, Redis, SMB, RDP, FTP, SSH).
- 🌐 **NIST NVD CVE Integration**: Queries the NIST National Vulnerability Database API 2.0 to dynamically fetch known CVE IDs, CVSS v3.1 scores, and vulnerability descriptions.
- 🔄 **Exposure Delta & Baseline Analysis**: Automatically compares scan findings against previous baselines to highlight new open ports, closed ports, and service changes.
- 📊 **Executive Dashboard**: High-level overview displaying total monitored assets, critical findings count, average risk score, severity distributions, and historical risk trends powered by Chart.js.
- 📜 **Searchable Scan Archive**: Complete scan history with keyword search, risk-level filtering, and multi-column sorting.
- 📑 **Exportable Security Reports**: Auto-generates structured CSV reports per scan with 1-click download support.

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
