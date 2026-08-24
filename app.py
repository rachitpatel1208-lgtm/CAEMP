import os
import csv
import threading
import uuid
import requests
from datetime import datetime

import nmap
from flask import Flask, render_template, request, jsonify, abort, send_file
import sqlite3

app = Flask(__name__)

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
    return render_template("dashboard.html")


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


if __name__ == "__main__":
    app.run(debug=True, port=5000)
