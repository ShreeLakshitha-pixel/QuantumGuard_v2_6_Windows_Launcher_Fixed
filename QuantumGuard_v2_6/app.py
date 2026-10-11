"""
QuantumGuard Web Application & REST API Server (Flask).
Enterprise-grade Post-Quantum Cryptography Scanner and CBOM Manager.
"""
import os
import json
import threading
import uuid
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
from werkzeug.utils import secure_filename
from flask_cors import CORS

from database import db
from scanners.orchestrator import ScanOrchestrator
from cbom.cyclonedx import CycloneDXExporter

# Initialize database schema
db.init_db()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    template_folder=TEMPLATES_DIR
)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # upload request cap: 10 MB
UPLOAD_ROOT = os.path.join(BASE_DIR, "data", "uploaded_targets")
ALLOWED_UPLOAD_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".conf", ".crt", ".cer", ".pem"}

orchestrator = ScanOrchestrator()

# Background worker
def execute_scan_worker(scan_id: int, target_type: str, target_path: str):
    orchestrator.run_scan(scan_id, target_type, target_path)

# --- Routes ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "2.6.0", "engine": "Explainable-MultiFactor-QScore-v3"})

@app.route("/api/dashboard")
def get_dashboard():
    scan_id_str = request.args.get("scan_id")
    scan_id = int(scan_id_str) if scan_id_str and scan_id_str.isdigit() else None
    summary = db.get_dashboard_summary(scan_id)
    return jsonify(summary)

@app.route("/api/scans")
def list_scans():
    scans = db.list_scans()
    return jsonify({"scans": scans})

@app.route("/api/scans/<int:scan_id>")
def get_scan_details(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = db.get_scan_findings(scan_id)
    return jsonify({"scan": scan, "findings": findings})

@app.route("/api/scans/<int:scan_id>/logs")
def get_scan_logs(scan_id: int):
    logs = db.get_scan_logs(scan_id)
    return jsonify({"logs": logs})

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "Corporate Crypto Audit")
    target_type = data.get("target_type", "local_directory")
    target_path = data.get("target_path", "").strip()

    # Defaults if empty
    if not target_path:
        if target_type in ["local_directory", "combined"]:
            target_path = os.path.join(BASE_DIR, "sample_targets")
        elif target_type == "network_tls":
            target_path = "google.com:443"

    scan_id = db.create_scan(
        name=name,
        target_type=target_type,
        target_path=target_path
    )

    # Launch background thread
    t = threading.Thread(
        target=execute_scan_worker,
        args=(scan_id, target_type, target_path),
        daemon=True
    )
    t.start()

    return jsonify({
        "status": "QUEUED",
        "scan_id": scan_id,
        "name": name,
        "target_path": target_path
    })

@app.route("/api/scans/<int:scan_id>/cbom")
def export_cbom(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = db.get_scan_findings(scan_id)
    cbom_json = CycloneDXExporter.export_cbom(scan, findings)
    
    response = make_response(json.dumps(cbom_json, indent=2))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = f"attachment; filename=cbom-scan-{scan_id}.json"
    return response

@app.route("/api/settings", methods=["GET", "POST"])
def manage_settings():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "crqc_horizon_year" in data:
            db.update_setting("crqc_horizon_year", str(data["crqc_horizon_year"]))
        if "default_migration_time_years" in data:
            db.update_setting("default_migration_time_years", str(data["default_migration_time_years"]))
        if "default_shelf_life_years" in data:
            db.update_setting("default_shelf_life_years", str(data["default_shelf_life_years"]))
        return jsonify({"status": "SUCCESS", "settings": db.get_settings()})
    return jsonify(db.get_settings())

@app.route("/api/upload-target", methods=["POST"])
def upload_target_files():
    """Store a small, temporary, allow-listed set of files for the existing local scanner."""
    files = request.files.getlist("files")
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "Choose at least one file."}), 400
    if len(files) > 10:
        return jsonify({"error": "A maximum of 10 files can be uploaded at once."}), 400

    upload_id = uuid.uuid4().hex
    target_dir = os.path.join(UPLOAD_ROOT, upload_id)
    os.makedirs(target_dir, exist_ok=False)
    accepted, rejected = [], []
    total_bytes = 0
    for uploaded in files:
        original = uploaded.filename or ""
        safe_name = secure_filename(original)
        ext = os.path.splitext(safe_name)[1].lower()
        if not safe_name or ext not in ALLOWED_UPLOAD_EXTENSIONS:
            rejected.append(f"{original or 'unnamed file'}: unsupported file type")
            continue
        if "key" in safe_name.lower() or "private" in safe_name.lower():
            rejected.append(f"{safe_name}: private-key-like filename rejected")
            continue
        content = uploaded.read(2 * 1024 * 1024 + 1)
        if len(content) > 2 * 1024 * 1024:
            rejected.append(f"{safe_name}: exceeds 2 MB")
            continue
        total_bytes += len(content)
        if total_bytes > 8 * 1024 * 1024:
            rejected.append(f"{safe_name}: upload batch exceeds 8 MB")
            break
        # Never accept PEM-encoded private keys, even when disguised with an allowed extension.
        sample = content[:200000].lower()
        if b"-----begin private key-----" in sample or b"-----begin rsa private key-----" in sample or b"-----begin ec private key-----" in sample or b"-----begin openssh private key-----" in sample:
            rejected.append(f"{safe_name}: private-key content rejected")
            continue
        dest = os.path.join(target_dir, safe_name)
        # Avoid overwriting another file with the same sanitized name.
        stem, suffix = os.path.splitext(safe_name)
        counter = 1
        while os.path.exists(dest):
            dest = os.path.join(target_dir, f"{stem}_{counter}{suffix}")
            counter += 1
        with open(dest, "wb") as handle:
            handle.write(content)
        accepted.append(os.path.basename(dest))

    if not accepted:
        try:
            os.rmdir(target_dir)
        except OSError:
            pass
        return jsonify({"error": "No files were accepted.", "rejected": rejected}), 400
    return jsonify({"status": "READY", "path": target_dir, "accepted": accepted, "rejected": rejected,
                    "notice": "Uploaded files are stored locally for scanning. Remove them from data/uploaded_targets when no longer needed."})

@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"error": "Upload request exceeds the 10 MB limit."}), 413

@app.route("/api/sample-path")
def get_sample_path():
    return jsonify({"path": os.path.join(BASE_DIR, "sample_targets")})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
