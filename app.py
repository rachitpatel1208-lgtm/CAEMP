import os
import csv
import json
import threading
import uuid
import requests
from datetime import datetime
from urllib.parse import urlparse

import nmap
from flask import Flask, render_template, request, jsonify, abort, send_file
import sqlite3
import numpy as np
import joblib

# PhishGuard ML & Heuristic Engine Modules
from phishguard_engine.feature_extraction import extract_url_features, FEATURE_NAMES
from phishguard_engine.external_apis import (
    check_dns_and_connectivity,
    check_ssl_certificate,
    query_virustotal_url,
    query_google_safe_browsing,
    generate_ai_threat_intelligence
)
from phishguard_engine.typosquatting import check_typosquatting

app = Flask(__name__)

# PhishGuard Global Models Container
PG_SAVED_MODELS_DIR = os.path.join(os.path.dirname(__file__), "phishguard_engine", "saved_models")
PG_MODELS = {
    'lexical_rf': None,
    'ngram_tfidf': None,
    'gradient_boost': None
}
PG_MODELS_META = {}

def load_phishguard_models():
    """Load pre-trained PhishGuard ML models into memory."""
    global PG_MODELS, PG_MODELS_META
    required_models = {
        'lexical_rf': 'model_lexical_rf.joblib',
        'ngram_tfidf': 'model_ngram_tfidf.joblib',
        'gradient_boost': 'model_gradient_boost.joblib'
    }
    for key, filename in required_models.items():
        model_path = os.path.join(PG_SAVED_MODELS_DIR, filename)
        if os.path.exists(model_path):
            try:
                PG_MODELS[key] = joblib.load(model_path)
            except Exception as e:
                print(f"[PhishGuard] Failed to load {filename}: {e}")
    meta_path = os.path.join(PG_SAVED_MODELS_DIR, 'models_meta.json')
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                PG_MODELS_META = json.load(f)
        except Exception:
            pass

# Initialize PhishGuard models
load_phishguard_models()


DB_PATH = os.path.join(os.path.dirname(__file__), "scan_history.db")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

RISK_SCORES = {
    "telnet": 40,
    "redis": 40,
    "ftp": 30,
    "smb": 30,
    "rdp": 30,
    "vnc": 30,
    "mongodb": 25,
    "nfs": 25,
    "mysql": 15,
    "postgresql": 15,
    "ldap": 10,
    "snmp": 10,
    "http": 10,
    "ssh": 5,
    "smtp": 5,
    "https": 3,
    "dns": 3
}

STATUS_STEPS = [
    "Discovering host",
    "Enumerating ports",
    "Detecting services",
    "Calculating risk score",
    "Analyzing exposure changes",
    "Generating report",
]

# in-memory job tracker: scan_id -> {"status": str, "step": int, "done": bool, "error": str|None}
JOBS = {}
JOBS_LOCK = threading.Lock()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_uid TEXT,
        scan_date TEXT,
        target TEXT,
        host TEXT,
        port INTEGER,
        protocol TEXT,
        state TEXT,
        service TEXT,
        version TEXT,
        severity TEXT,
        finding TEXT,
        risk_score INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_runs (
        scan_uid TEXT PRIMARY KEY,
        scan_date TEXT,
        target TEXT,
        total_risk INTEGER,
        risk_level TEXT,
        open_ports INTEGER,
        services_detected INTEGER,
        duration_seconds REAL,
        new_ports TEXT,
        removed_ports TEXT,
        changed_services TEXT,
        report_file TEXT
    )
    """)
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_uid TEXT,
        port INTEGER,
        service TEXT,
        cve_id TEXT,
        cvss_score REAL
     )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS url_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_date TEXT,
        url TEXT,
        normalized_url TEXT,
        hostname TEXT,
        threat_score INTEGER,
        threat_level TEXT,
        is_typosquat INTEGER,
        brand TEXT,
        technique TEXT,
        flagged_count INTEGER,
        total_models INTEGER,
        flags_json TEXT,
        dns_ip TEXT,
        has_ssl INTEGER
    )
    """)
    
    conn.commit()
    conn.close()


def migrate_db():
    """Additive, idempotent migration — never drops or rewrites existing data."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(cves)")
    existing_cols = {row["name"] for row in cur.fetchall()}
    if "description" not in existing_cols:
        cur.execute("ALTER TABLE cves ADD COLUMN description TEXT")
    conn.commit()
    conn.close()


init_db()
migrate_db()


def check_vulnerability(service_name, version):
    version_text = f"{service_name} {version}".lower()

    if "apache" in version_text:
        return "Medium", "Apache detected - review version for known CVEs"
    elif "openssh" in version_text:
        return "Low", "SSH service detected - verify latest version"
    elif "ftp" in version_text:
        return "High", "FTP detected - insecure protocol"
    elif "telnet" in version_text:
        return "Critical", "Telnet detected - plaintext authentication"
    elif "redis" in version_text:
        return "Critical", "Redis detected - verify access restrictions"

    elif "smb" in version_text or "microsoft-ds" in version_text:
        return "High", "SMB service detected - review exposure"

    elif "rdp" in version_text:
        return "High", "RDP service detected - review internet exposure"

    elif "mongodb" in version_text:
        return "High", "MongoDB detected - verify authentication"

    elif "mysql" in version_text:
        return "Medium", "MySQL detected - verify access controls"

    elif "postgresql" in version_text:
        return "Medium", "PostgreSQL detected - verify access controls"

    elif "snmp" in version_text:
        return "Medium", "SNMP detected - review community strings"

    elif "nfs" in version_text:
        return "High", "NFS detected - review shared directories"

    return "Info", "No immediate issue detected"

def lookup_cves(product, version):

    if not product:
        return []

    try:

        keyword = f"{product} {version}"

        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={keyword}"
            "&resultsPerPage=5"
        )

        response = requests.get(
            url,
            timeout=10
        )

        data = response.json()

        cves = []

        for vuln in data.get(
            "vulnerabilities",
            []
        ):

            cve = vuln["cve"]

            try:
                score = (
                    cve["metrics"]
                    ["cvssMetricV31"][0]
                    ["cvssData"]
                    ["baseScore"]
                )

            except:
                score = 0

            description = ""
            try:
                for desc in cve.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
            except:
                description = ""

            cves.append({
                "id": cve["id"],
                "score": score,
                "description": description
            })

        return cves

    except:
        return []
    
def get_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def set_job_step(scan_uid, step_index, status_text=None, error=None, done=False):
    with JOBS_LOCK:
        job = JOBS.setdefault(scan_uid, {})
        job["step"] = step_index
        job["status"] = status_text or STATUS_STEPS[min(step_index, len(STATUS_STEPS) - 1)]
        job["done"] = done
        job["error"] = error


def run_scan(scan_uid, target):
    start_time = datetime.now()
    try:
        set_job_step(scan_uid, 0, "Discovering host")

        scanner = nmap.PortScanner()

        conn = get_db()
        cur = conn.cursor()

        # Load previous scan for diffing
        previous_scan = {}
        cur.execute("""
            SELECT port, service
            FROM scans
            WHERE target = ?
            AND scan_date = (
                SELECT MAX(scan_date)
                FROM scans
                WHERE target = ?
            )
        """, (target, target))
        for row in cur.fetchall():
            previous_scan[row["port"]] = row["service"]

        timestamp = start_time.strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(REPORTS_DIR, f"scan_report_{timestamp}.csv")

        set_job_step(scan_uid, 1, "Enumerating ports")
        scanner.scan(target, arguments="-sV")

        set_job_step(scan_uid, 2, "Detecting services")

        current_scan = {}
        total_risk = 0
        rows_for_csv = []
        findings = []

        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                ports = scanner[host][protocol].keys()
                for port in sorted(ports):
                    service = scanner[host][protocol][port]
                    service_name = service.get("name", "unknown")
                    current_scan[port] = service_name

                    risk = RISK_SCORES.get(service_name.lower(), 1)
                    total_risk += risk

                    version = (
                        f"{service.get('product', 'Unknown')} "
                        f"{service.get('version', 'N/A')}"
                    ).strip()
                    
                    product = service.get("product", "")
                    version_num = service.get("version", "")

                    cves = lookup_cves(
                        product,
                        version_num
                    )

                    severity, finding = check_vulnerability(service_name, version)

                    cur.execute("""
                        INSERT INTO scans (
                            scan_uid, scan_date, target, host, port, protocol,
                            state, service, version, severity, finding, risk_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_uid, timestamp, target, host, port, protocol,
                        service.get("state", "unknown"), service_name, version,
                        severity, finding, risk
                    ))
                    
                    for cve in cves:

                        cur.execute("""
                        INSERT INTO cves (
                            scan_uid,
                            port,
                            service,
                            cve_id,
                            cvss_score,
                            description
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            scan_uid,
                            port,
                            service_name,
                            cve["id"],
                            cve["score"],
                            cve.get("description", "")
                        ))

                    findings.append({
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "state": service.get("state", "unknown"),
                        "service": service_name,
                        "version": version,
                        "severity": severity,
                        "finding": finding,
                    })

                    rows_for_csv.append([
                        host, port, service.get("state", "unknown"),
                        service_name, version, severity, finding
                    ])

        set_job_step(scan_uid, 3, "Calculating risk score")
        risk_level = get_risk_level(total_risk)

        set_job_step(scan_uid, 4, "Analyzing exposure changes")
        new_ports = sorted(set(current_scan.keys()) - set(previous_scan.keys()))
        removed_ports = sorted(set(previous_scan.keys()) - set(current_scan.keys()))
        changed_services = []
        for port in current_scan:
            if port in previous_scan and current_scan[port] != previous_scan[port]:
                changed_services.append({
                    "port": port,
                    "old": previous_scan[port],
                    "new": current_scan[port],
                })

        set_job_step(scan_uid, 5, "Generating report")
        with open(report_file, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Port", "State", "Service", "Version", "Severity", "Finding"])
            writer.writerows(rows_for_csv)

        duration = (datetime.now() - start_time).total_seconds()

        import json
        cur.execute("""
            INSERT INTO scan_runs (
                scan_uid, scan_date, target, total_risk, risk_level,
                open_ports, services_detected, duration_seconds,
                new_ports, removed_ports, changed_services, report_file
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_uid, timestamp, target, total_risk, risk_level,
            len(current_scan), len(set(f["service"] for f in findings)),
            duration, json.dumps([{"port": p, "service": current_scan[p]} for p in new_ports]),
            json.dumps([{"port": p, "service": previous_scan[p]} for p in removed_ports]),
            json.dumps(changed_services), report_file
        ))

        conn.commit()
        conn.close()

        set_job_step(scan_uid, 5, "Scan complete", done=True)
    except Exception as exc:  # noqa: BLE001
        set_job_step(scan_uid, 0, error=str(exc), done=True)


@app.route("/")
def dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scan_runs ORDER BY scan_date DESC")
    runs = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", runs=runs)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_uid = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[scan_uid] = {"step": 0, "status": STATUS_STEPS[0], "done": False, "error": None}

    thread = threading.Thread(target=run_scan, args=(scan_uid, target), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_uid})


@app.route("/api/scan/<scan_uid>/status")
def api_scan_status(scan_uid):
    with JOBS_LOCK:
        job = JOBS.get(scan_uid)
    if not job:
        return jsonify({"error": "Unknown scan"}), 404
    return jsonify({
        "step": job["step"],
        "status": job["status"],
        "label": STATUS_STEPS[min(job["step"], len(STATUS_STEPS) - 1)],
        "total_steps": len(STATUS_STEPS),
        "done": job["done"],
        "error": job["error"],
    })


def get_scan_run(scan_uid):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scan_runs WHERE scan_uid = ?", (scan_uid,))
    run = cur.fetchone()
    if not run:
        conn.close()
        return None, None
    cur.execute("SELECT * FROM scans WHERE scan_uid = ? ORDER BY port", (scan_uid,))
    findings = cur.fetchall()
    conn.close()
    return run, findings


@app.route("/scan/<scan_uid>")
def scan_results(scan_uid):
    run, findings = get_scan_run(scan_uid)
    if not run:
        abort(404)
    return render_template("results.html", run=run, findings=findings, scan_uid=scan_uid)


@app.route("/api/scan/<scan_uid>")
def api_scan_data(scan_uid):
    run, findings = get_scan_run(scan_uid)
    if not run:
        return jsonify({"error": "Not found"}), 404
    import json
    return jsonify({
        "scan_uid": run["scan_uid"],
        "target": run["target"],
        "scan_date": run["scan_date"],
        "total_risk": run["total_risk"],
        "risk_level": run["risk_level"],
        "open_ports": run["open_ports"],
        "services_detected": run["services_detected"],
        "duration_seconds": run["duration_seconds"],
        "new_ports": json.loads(run["new_ports"]),
        "removed_ports": json.loads(run["removed_ports"]),
        "changed_services": json.loads(run["changed_services"]),
        "findings": [dict(f) for f in findings],
    })

@app.route("/api/cves/<scan_uid>")
def api_cves(scan_uid):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT *
    FROM cves
    WHERE scan_uid = ?
    ORDER BY cvss_score DESC
    """, (scan_uid,))

    rows = cur.fetchall()

    conn.close()

    return jsonify(
        [dict(row) for row in rows]
    )
    
@app.route("/history")
def history():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scan_runs ORDER BY scan_date DESC")
    runs = cur.fetchall()
    conn.close()
    return render_template("history.html", runs=runs)


@app.route("/reports")
def reports():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scan_runs ORDER BY scan_date DESC")
    runs = cur.fetchall()
    conn.close()
    return render_template("reports.html", runs=runs)


def severity_rank(sev):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return order.get(sev, 5)


@app.route("/api/dashboard/stats")
def api_dashboard_stats():
    """Aggregated data for the executive dashboard widgets. Additive endpoint —
    reads existing tables only, no schema or behavior changes to scanning itself."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM scan_runs")
    total_scans = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(DISTINCT target) AS c FROM scan_runs")
    total_assets = cur.fetchone()["c"]

    cur.execute("SELECT COALESCE(AVG(total_risk), 0) AS a FROM scan_runs")
    avg_risk = round(cur.fetchone()["a"] or 0, 1)

    cur.execute("SELECT COUNT(*) AS c FROM scans WHERE severity = 'Critical'")
    critical_findings = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM scans WHERE severity = 'High'")
    high_findings = cur.fetchone()["c"]

    cur.execute("""
        SELECT severity, COUNT(*) AS c
        FROM scans
        GROUP BY severity
    """)
    severity_distribution = {row["severity"]: row["c"] for row in cur.fetchall()}

    cur.execute("""
        SELECT scan_uid, scan_date, target, total_risk, risk_level, open_ports
        FROM scan_runs
        ORDER BY scan_date DESC
        LIMIT 6
    """)
    recent_scans = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT scan_uid, scan_date, target, total_risk
        FROM scan_runs
        ORDER BY scan_date ASC
        LIMIT 20
    """)
    risk_trend = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT target, port, protocol, service, version, severity, finding, scan_date
        FROM scans
        WHERE severity IN ('Critical', 'High')
        ORDER BY id DESC
        LIMIT 6
    """)
    recent_findings = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT service, COUNT(*) AS c
        FROM scans
        GROUP BY service
        ORDER BY c DESC
        LIMIT 8
    """)
    service_distribution = [dict(r) for r in cur.fetchall()]

    conn.close()

    return jsonify({
        "total_scans": total_scans,
        "total_assets": total_assets,
        "avg_risk": avg_risk,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "severity_distribution": severity_distribution,
        "recent_scans": recent_scans,
        "risk_trend": risk_trend,
        "recent_findings": recent_findings,
        "service_distribution": service_distribution,
    })


@app.route("/reports/download/<scan_uid>")
def download_report(scan_uid):
    """Serve the CSV report generated for a given scan as a file download."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT report_file, target FROM scan_runs WHERE scan_uid = ?", (scan_uid,))
    row = cur.fetchone()
    conn.close()

    if not row or not os.path.exists(row["report_file"]):
        abort(404)

    download_name = f"caemp_report_{row['target']}_{scan_uid}.csv"
    return send_file(row["report_file"], as_attachment=True, download_name=download_name)


# ============================================================================
# PHISHGUARD // OMNITRIX EDITION — URL SCANNER ENGINE & ROUTES
# ============================================================================

@app.context_processor
def inject_platform_section():
    """Inject active platform section (caemp vs phishguard) into all templates."""
    is_phish = request.path.startswith('/phishguard') or request.path.startswith('/url-scanner')
    return {
        'active_section': 'phishguard' if is_phish else 'caemp',
        'is_phishguard': is_phish
    }


@app.route("/phishguard")
@app.route("/url-scanner")
def phishguard_page():
    """PhishGuard Live URL Inspector in Galvan Omnitrix Theme."""
    return render_template("phishguard.html")


@app.route("/api/models-info", methods=["GET"])
def get_phishguard_models_info():
    """Returns status and metrics of loaded PhishGuard ML models."""
    return jsonify({
        "status": "online",
        "models_loaded": {k: (v is not None) for k, v in PG_MODELS.items()},
        "metadata": PG_MODELS_META
    })


@app.route("/api/analyze-url", methods=["POST"])
def analyze_url():
    """
    Evaluates a URL across 3 distinct ML models, live DNS resolution,
    SSL handshake verification, brand typosquatting, and heuristic checks.
    """
    data = request.get_json(force=True, silent=True) or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "URL parameter is required"}), 400

    parsed = urlparse(raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}")
    hostname = (parsed.hostname or "").lower()

    # 1. Live DNS & SSL Certificate Verification
    dns_info = check_dns_and_connectivity(hostname)
    ssl_info = check_ssl_certificate(hostname)

    # Scheme Normalization
    if raw_url.lower().startswith("https://"):
        normalized_url = raw_url
        is_https_active = True
    elif raw_url.lower().startswith("http://"):
        normalized_url = raw_url
        is_https_active = ssl_info.get("has_ssl", False)
    else:
        if ssl_info.get("has_ssl", False):
            normalized_url = f"https://{raw_url}"
            is_https_active = True
        else:
            normalized_url = f"http://{raw_url}"
            is_https_active = False

    # 2. Typosquatting / Lookalike Brand Detection
    typo_info = check_typosquatting(normalized_url)
    is_typosquat = typo_info.get("is_typosquat", False)

    # 3. Feature Extraction
    feat_dict = extract_url_features(normalized_url, ssl_active=is_https_active)
    feat_vec = np.array([feat_dict[k] for k in FEATURE_NAMES]).reshape(1, -1)

    model_results = {}
    flagged_count = 0
    scores = []

    # Model 1: Lexical Random Forest
    if PG_MODELS["lexical_rf"]:
        rf = PG_MODELS["lexical_rf"]
        rf_prob = float(rf.predict_proba(feat_vec)[0][1])
        rf_pred = int(rf.predict(feat_vec)[0])
        rf_sus = (rf_prob >= 0.45 or rf_pred == 1 or is_typosquat)
        if is_typosquat:
            rf_prob = max(rf_prob, 0.94)
        if rf_sus:
            flagged_count += 1
        scores.append(rf_prob * 100)

        signals = [
            f"Entropy: {feat_dict['domain_entropy']}",
            f"Suspicious TLD: {'Yes' if feat_dict['is_suspicious_tld'] else 'No'}",
            f"Phishing Keywords: {feat_dict['phishing_keyword_count']}"
        ]
        if is_typosquat:
            signals.insert(0, f"Lookalike Alert: Mimicking {typo_info.get('brand')}")

        model_results["lexical_rf"] = {
            "name": "Lexical Random Forest",
            "type": "Structural & Lexical ML",
            "probability": round(rf_prob, 3),
            "threat_score": round(rf_prob * 100),
            "is_suspicious": rf_sus,
            "verdict": "Suspicious / Malicious" if rf_sus else "Legitimate",
            "key_signals": signals
        }

    # Model 2: Char N-Gram TF-IDF Classifier
    if PG_MODELS["ngram_tfidf"]:
        ngram = PG_MODELS["ngram_tfidf"]
        ng_prob = float(ngram.predict_proba([normalized_url])[0][1])
        ng_pred = int(ngram.predict([normalized_url])[0])
        ng_sus = (ng_prob >= 0.45 or ng_pred == 1 or is_typosquat)
        if is_typosquat:
            ng_prob = max(ng_prob, 0.92)
        if ng_sus:
            flagged_count += 1
        scores.append(ng_prob * 100)

        ng_signals = [
            f"Subword match confidence: {round(ng_prob * 100)}%",
            "Typosquatting/Obfuscation token scan complete"
        ]
        if is_typosquat:
            ng_signals.insert(0, f"Technique: {typo_info.get('technique')}")

        model_results["ngram_tfidf"] = {
            "name": "Char N-Gram TF-IDF",
            "type": "Subword Pattern Recognition",
            "probability": round(ng_prob, 3),
            "threat_score": round(ng_prob * 100),
            "is_suspicious": ng_sus,
            "verdict": "Suspicious / Malicious" if ng_sus else "Legitimate",
            "key_signals": ng_signals
        }

    # Model 3: Gradient Boosting
    if PG_MODELS["gradient_boost"]:
        gb = PG_MODELS["gradient_boost"]
        gb_prob = float(gb.predict_proba(feat_vec)[0][1])
        gb_pred = int(gb.predict(feat_vec)[0])
        gb_sus = (gb_prob >= 0.45 or gb_pred == 1 or is_typosquat)
        if is_typosquat:
            gb_prob = max(gb_prob, 0.95)
        if gb_sus:
            flagged_count += 1
        scores.append(gb_prob * 100)
        model_results["gradient_boost"] = {
            "name": "Gradient Boosting Ensemble",
            "type": "Non-linear Decision Trees",
            "probability": round(gb_prob, 3),
            "threat_score": round(gb_prob * 100),
            "is_suspicious": gb_sus,
            "verdict": "Suspicious / Malicious" if gb_sus else "Legitimate",
            "key_signals": [
                f"Ensemble score: {round(gb_prob * 100)}%",
                f"Ratio digits in host: {feat_dict['ratio_digits_host']}"
            ]
        }

    # 4. Multi-Model Consensus Calculation
    max_score = max(scores) if scores else 0
    avg_score = (sum(scores) / len(scores)) if scores else 0

    if flagged_count >= 1:
        overall_score = max_score
    else:
        overall_score = avg_score

    if is_typosquat:
        overall_score = max(overall_score, 94)

    if not dns_info.get("resolved") and overall_score > 35:
        overall_score = min(100, overall_score + 10)

    overall_score = round(overall_score)
    if overall_score >= 70:
        level = "critical" if overall_score >= 85 else "dangerous"
    elif overall_score >= 45:
        level = "suspicious"
    else:
        level = "safe"

    # Heuristic Red Flags
    flags = []
    if is_typosquat:
        flags.append({
            "title": f"Deceptive Brand Lookalike ({typo_info.get('brand')})",
            "description": typo_info.get("warning"),
            "severity": "critical",
            "icon": "!"
        })
    if feat_dict["is_ip"]:
        flags.append({
            "title": "Raw IP Address Hostname",
            "description": "The URL uses a numeric IP address instead of a registered domain name.",
            "severity": "high",
            "icon": "!"
        })
    if feat_dict["is_suspicious_tld"]:
        flags.append({
            "title": f"High-Risk TLD (.{hostname.split('.')[-1]})",
            "description": "The Top-Level Domain is disproportionately associated with spam and disposable phishing kits.",
            "severity": "high",
            "icon": "!"
        })
    if feat_dict["phishing_keyword_count"] > 0:
        flags.append({
            "title": f"{feat_dict['phishing_keyword_count']} Phishing Keyword(s) in URL",
            "description": "Contains credential harvesting or brand impersonation keywords in the path or subdomain.",
            "severity": "medium",
            "icon": "!"
        })
    if not feat_dict["has_https"] and not ssl_info.get("has_ssl"):
        flags.append({
            "title": "No HTTPS Encryption",
            "description": "The destination does not provide SSL/TLS encryption. Traffic is transmitted over unencrypted HTTP.",
            "severity": "medium",
            "icon": "!"
        })
    elif raw_url.lower().startswith("http://") and ssl_info.get("has_ssl"):
        flags.append({
            "title": "Plain HTTP Prefix Specified",
            "description": "The link explicitly requested plain HTTP, though the destination server supports secure SSL/TLS encryption.",
            "severity": "low",
            "icon": "!"
        })
    if feat_dict["subdomain_count"] >= 3:
        flags.append({
            "title": f"Deep Subdomain Nesting ({feat_dict['subdomain_count']} levels)",
            "description": "Excessive subdomains are frequently used to obfuscate the real target host.",
            "severity": "low",
            "icon": "!"
        })
    if not dns_info.get("resolved"):
        flags.append({
            "title": "Domain DNS Unresolved",
            "description": dns_info.get("message", "Failed DNS check"),
            "severity": "medium",
            "icon": "!"
        })

    # AI Threat Intelligence
    consensus_summary = {
        "overall_threat_level": level,
        "overall_score": overall_score,
        "models_flagged": flagged_count,
        "total_models": len(model_results),
        "typosquatting": typo_info if is_typosquat else None,
        "ssl_active": ssl_info.get("has_ssl", False)
    }
    ai_intel = generate_ai_threat_intelligence("URL", normalized_url, flags, consensus_summary)

    # Persist scan result to SQLite url_scans
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO url_scans (
                scan_date, url, normalized_url, hostname, threat_score,
                threat_level, is_typosquat, brand, technique, flagged_count,
                total_models, flags_json, dns_ip, has_ssl
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            raw_url,
            normalized_url,
            hostname,
            overall_score,
            level,
            1 if is_typosquat else 0,
            typo_info.get("brand") if is_typosquat else "",
            typo_info.get("technique") if is_typosquat else "",
            flagged_count,
            len(model_results),
            json.dumps(flags),
            dns_info.get("ip") or "",
            1 if ssl_info.get("has_ssl") else 0
        ))
        conn.commit()
        conn.close()
    except Exception as db_err:
        print(f"[PhishGuard DB] Error saving url scan: {db_err}")

    response = {
        "url": raw_url,
        "normalized_url": normalized_url,
        "hostname": hostname,
        "overall_threat_level": level,
        "threat_score": overall_score,
        "consensus": {
            "flagged_by_any": flagged_count > 0,
            "flagged_count": flagged_count,
            "total_models": len(model_results),
            "policy": "elevate_if_any_sus"
        },
        "models": model_results,
        "typosquatting": typo_info,
        "dns_check": dns_info,
        "ssl_check": ssl_info,
        "flags": flags,
        "features": feat_dict,
        "ai_intelligence": ai_intel
    }
    return jsonify(response)


@app.route("/api/url-history", methods=["GET"])
def get_url_history():
    """Retrieve recent URL scans from database."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, scan_date, url, normalized_url, hostname, threat_score,
               threat_level, is_typosquat, brand, technique, flagged_count, total_models
        FROM url_scans
        ORDER BY id DESC
        LIMIT 25
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/clear-url-history", methods=["POST"])
def clear_url_history():
    """Clear URL scan history."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM url_scans")
    conn.commit()
    conn.close()
    return jsonify({"success": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

