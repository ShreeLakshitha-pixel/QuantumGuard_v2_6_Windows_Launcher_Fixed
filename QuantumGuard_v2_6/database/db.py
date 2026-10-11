"""
SQLite Database interface for QuantumGuard.
Persistent real storage for scans, assets, vulnerabilities, and migration roadmaps.
"""
import sqlite3
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from database.models import (
    CryptoAsset,
    VulnerabilityRecord,
    MigrationRecommendation,
    ScanRecord,
    RiskTier
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "quantumguard.db")

def get_db_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Create all required SQLite tables and indexes."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            total_assets INTEGER DEFAULT 0,
            hndl_critical_count INTEGER DEFAULT 0,
            avg_q_score REAL DEFAULT 0.0,
            raw_summary_json TEXT DEFAULT '{}'
        );
        """)

        # Crypto Assets table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            location TEXT NOT NULL,
            line_number INTEGER,
            algorithm TEXT NOT NULL,
            key_size INTEGER,
            curve_name TEXT,
            signature_algorithm TEXT,
            purpose TEXT,
            exposure_level TEXT NOT NULL,
            data_shelf_life_years REAL DEFAULT 10.0,
            code_snippet TEXT,
            raw_metadata_json TEXT DEFAULT '{}',
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """)

        # Vulnerabilities table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            q_score REAL NOT NULL,
            severity TEXT NOT NULL,
            shor_vulnerable INTEGER NOT NULL DEFAULT 0,
            grover_vulnerable INTEGER NOT NULL DEFAULT 0,
            mosca_gap_years REAL DEFAULT 0.0,
            time_to_compromise_years REAL DEFAULT 0.0,
            urgency_tier TEXT NOT NULL,
            explanation TEXT,
            risk_factors_json TEXT DEFAULT '{}',
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """)

        # Backward-compatible schema migration for transparent multi-factor risk scoring.
        vuln_columns = {row[1] for row in cursor.execute("PRAGMA table_info(vulnerabilities)").fetchall()}
        if "risk_factors_json" not in vuln_columns:
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN risk_factors_json TEXT DEFAULT '{}' ")

        # Migration Recommendations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS migration_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            scan_id INTEGER NOT NULL,
            current_primitive TEXT NOT NULL,
            nist_standard_replacement TEXT NOT NULL,
            hybrid_replacement TEXT NOT NULL,
            standard_reference TEXT NOT NULL,
            code_diff_title TEXT NOT NULL,
            current_code_snippet TEXT NOT NULL,
            migrated_code_snippet TEXT NOT NULL,
            configuration_recipe TEXT NOT NULL,
            migration_effort TEXT NOT NULL DEFAULT 'MEDIUM',
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """)

        # Scan Logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """)

        # Settings table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT
        );
        """)

        # Default settings
        default_settings = [
            ("crqc_horizon_year", "2033", "Estimated arrival year of Cryptographically Relevant Quantum Computer (Shor's)"),
            ("default_migration_time_years", "3.0", "Estimated enterprise time to complete end-to-end PQC migration"),
            ("default_shelf_life_years", "10.0", "Baseline confidentiality shelf-life for standard corporate data"),
            ("current_year", "2026", "Current baseline evaluation year")
        ]
        for key, val, desc in default_settings:
            cursor.execute("""
            INSERT OR IGNORE INTO settings (key, value, description)
            VALUES (?, ?, ?);
            """, (key, val, desc))

        # Create performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets (scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities (scan_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_asset_id ON vulnerabilities (asset_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_recs_asset_id ON migration_recommendations (asset_id);")

        conn.commit()
    # Existing projects may already contain findings created before factor scoring.
    # Backfill only rows without a factor breakdown; never overwrite new assessments.
    _backfill_legacy_risk_scores()

def _backfill_legacy_risk_scores() -> None:
    """Upgrade older saved findings to the explainable scoring model in place."""
    try:
        from core.mosca_engine import MoscaEngine
        settings = get_settings()
        engine = MoscaEngine(
            crqc_year=int(settings.get("crqc_horizon_year", 2033)),
            current_year=int(settings.get("current_year", 2026)),
            default_migration_years=float(settings.get("default_migration_time_years", 3.0)),
        )
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT a.*, v.id AS vulnerability_id
                FROM assets a JOIN vulnerabilities v ON v.asset_id = a.id
                WHERE v.risk_factors_json IS NULL OR v.risk_factors_json = '' OR v.risk_factors_json = '{}'
            """).fetchall()
            for row in rows:
                data = dict(row)
                try:
                    metadata = json.loads(data.get("raw_metadata_json") or "{}")
                except (TypeError, json.JSONDecodeError):
                    metadata = {}
                asset = CryptoAsset(
                    id=data.get("id"), scan_id=data.get("scan_id"), name=data.get("name") or "",
                    asset_type=data.get("asset_type") or "SOURCE_CODE", location=data.get("location") or "",
                    line_number=data.get("line_number"), algorithm=data.get("algorithm") or "",
                    key_size=data.get("key_size"), curve_name=data.get("curve_name"),
                    signature_algorithm=data.get("signature_algorithm"), purpose=data.get("purpose") or "",
                    exposure_level=data.get("exposure_level") or "INTERNAL_NETWORK",
                    data_shelf_life_years=float(data.get("data_shelf_life_years") or 7.0),
                    code_snippet=data.get("code_snippet"), raw_metadata=metadata
                )
                vuln, explanation = engine.assess_asset(asset)
                conn.execute("""UPDATE vulnerabilities SET q_score=?, severity=?, shor_vulnerable=?,
                    grover_vulnerable=?, mosca_gap_years=?, time_to_compromise_years=?, urgency_tier=?,
                    explanation=?, risk_factors_json=? WHERE id=?""", (
                    vuln.q_score, vuln.severity, int(vuln.shor_vulnerable), int(vuln.grover_vulnerable),
                    vuln.mosca_gap_years, vuln.time_to_compromise_years, vuln.urgency_tier, explanation,
                    json.dumps(vuln.risk_factors), data["vulnerability_id"]
                ))
            if rows:
                conn.execute("""UPDATE scans SET avg_q_score = COALESCE((SELECT ROUND(AVG(v.q_score),1)
                    FROM vulnerabilities v WHERE v.scan_id=scans.id),0),
                    hndl_critical_count = (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id=scans.id
                    AND v.severity='CRITICAL') WHERE id IN (SELECT DISTINCT scan_id FROM vulnerabilities)""")
                conn.commit()
    except Exception as exc:
        # Startup should remain available if a legacy database needs manual repair.
        print(f"QuantumGuard legacy risk-score backfill skipped: {exc}")

# --- Scan CRUD ---

def create_scan(name: str, target_type: str, target_path: str) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
        INSERT INTO scans (name, target_type, target_path, status, started_at)
        VALUES (?, ?, ?, 'RUNNING', ?);
        """, (name, target_type, target_path, now))
        conn.commit()
        return cursor.lastrowid

def update_scan_status(
    scan_id: int,
    status: str,
    total_assets: int,
    hndl_critical: int,
    avg_q: float,
    summary: Dict[str, Any]
):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
        UPDATE scans
        SET status = ?, completed_at = ?, total_assets = ?, hndl_critical_count = ?,
            avg_q_score = ?, raw_summary_json = ?
        WHERE id = ?;
        """, (status, now, total_assets, hndl_critical, avg_q, json.dumps(summary), scan_id))
        conn.commit()

def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        res["raw_summary"] = json.loads(res.get("raw_summary_json") or "{}")
        return res

def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        scans = []
        for r in rows:
            d = dict(r)
            d["raw_summary"] = json.loads(d.get("raw_summary_json") or "{}")
            scans.append(d)
        return scans

# --- Logs ---

def add_scan_log(scan_id: int, level: str, message: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute("""
        INSERT INTO scan_logs (scan_id, timestamp, level, message)
        VALUES (?, ?, ?, ?);
        """, (scan_id, now, level, message))
        conn.commit()

def get_scan_logs(scan_id: int, limit: int = 200) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id ASC LIMIT ?
        """, (scan_id, limit))
        return [dict(r) for r in cursor.fetchall()]

# --- Asset & Finding Storage ---

def save_finding(
    scan_id: int,
    asset: CryptoAsset,
    vuln: VulnerabilityRecord,
    rec: MigrationRecommendation
) -> int:
    """Save asset, vulnerability, and recommendation atomically."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. Insert asset
        cursor.execute("""
        INSERT INTO assets (
            scan_id, name, asset_type, location, line_number,
            algorithm, key_size, curve_name, signature_algorithm,
            purpose, exposure_level, data_shelf_life_years,
            code_snippet, raw_metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            scan_id, asset.name, asset.asset_type, asset.location, asset.line_number,
            asset.algorithm, asset.key_size, asset.curve_name, asset.signature_algorithm,
            asset.purpose, asset.exposure_level, asset.data_shelf_life_years,
            asset.code_snippet, json.dumps(asset.raw_metadata or {})
        ))
        asset_id = cursor.lastrowid
        
        # 2. Insert vulnerability
        cursor.execute("""
        INSERT INTO vulnerabilities (
            asset_id, scan_id, q_score, severity,
            shor_vulnerable, grover_vulnerable, mosca_gap_years,
            time_to_compromise_years, urgency_tier, explanation, risk_factors_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            asset_id, scan_id, vuln.q_score, vuln.severity,
            1 if vuln.shor_vulnerable else 0, 1 if vuln.grover_vulnerable else 0,
            vuln.mosca_gap_years, vuln.time_to_compromise_years,
            vuln.urgency_tier, vuln.explanation, json.dumps(vuln.risk_factors or {})
        ))
        
        # 3. Insert recommendation
        cursor.execute("""
        INSERT INTO migration_recommendations (
            asset_id, scan_id, current_primitive, nist_standard_replacement,
            hybrid_replacement, standard_reference, code_diff_title,
            current_code_snippet, migrated_code_snippet, configuration_recipe,
            migration_effort
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            asset_id, scan_id, rec.current_primitive, rec.nist_standard_replacement,
            rec.hybrid_replacement, rec.standard_reference, rec.code_diff_title,
            rec.current_code_snippet, rec.migrated_code_snippet,
            rec.configuration_recipe, rec.migration_effort
        ))
        
        conn.commit()
        return asset_id

# --- Query Detailed Findings ---

def get_scan_findings(scan_id: int) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT 
            a.id as asset_id,
            a.scan_id,
            a.name as asset_name,
            a.asset_type,
            a.location,
            a.line_number,
            a.algorithm,
            a.key_size,
            a.curve_name,
            a.signature_algorithm,
            a.purpose,
            a.exposure_level,
            a.data_shelf_life_years,
            a.code_snippet,
            a.raw_metadata_json,
            v.id as vuln_id,
            v.q_score,
            v.severity,
            v.shor_vulnerable,
            v.grover_vulnerable,
            v.mosca_gap_years,
            v.time_to_compromise_years,
            v.urgency_tier,
            v.explanation,
            v.risk_factors_json,
            m.id as rec_id,
            m.nist_standard_replacement,
            m.hybrid_replacement,
            m.standard_reference,
            m.code_diff_title,
            m.current_code_snippet,
            m.migrated_code_snippet,
            m.configuration_recipe,
            m.migration_effort
        FROM assets a
        JOIN vulnerabilities v ON a.id = v.asset_id
        JOIN migration_recommendations m ON a.id = m.asset_id
        WHERE a.scan_id = ?
        ORDER BY v.q_score DESC;
        """, (scan_id,))
        
        findings = []
        for r in cursor.fetchall():
            item = dict(r)
            item["raw_metadata"] = json.loads(item.get("raw_metadata_json") or "{}")
            item["risk_factors"] = json.loads(item.get("risk_factors_json") or "{}")
            item["shor_vulnerable"] = bool(item["shor_vulnerable"])
            item["grover_vulnerable"] = bool(item["grover_vulnerable"])
            findings.append(item)
        return findings

def get_dashboard_summary(scan_id: Optional[int] = None) -> Dict[str, Any]:
    """Calculate aggregated stats for dashboard view."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        target_scan_id = scan_id
        if target_scan_id is None:
            cursor.execute("SELECT id FROM scans WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                target_scan_id = row[0]
                
        if target_scan_id is None:
            return {
                "scan_id": None,
                "total_assets": 0,
                "hndl_critical": 0,
                "avg_q_score": 0.0,
                "readiness_pct": 100.0,
                "tier_breakdown": {
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "QUANTUM_SAFE": 0
                },
                "asset_types": {},
                "findings": []
            }
            
        cursor.execute("SELECT * FROM scans WHERE id = ?", (target_scan_id,))
        scan_row = cursor.fetchone()
        
        findings = get_scan_findings(target_scan_id)
        
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "QUANTUM_SAFE": 0}
        asset_types = {}
        for f in findings:
            sev = f["severity"]
            tier_counts[sev] = tier_counts.get(sev, 0) + 1
            atype = f["asset_type"]
            asset_types[atype] = asset_types.get(atype, 0) + 1
            
        total = len(findings)
        critical_count = tier_counts["CRITICAL"]
        avg_q = sum(f["q_score"] for f in findings) / total if total > 0 else 0.0
        
        # Readiness % (100% minus risk-weighted penalty)
        safe_count = tier_counts["QUANTUM_SAFE"]
        readiness_pct = round(max(0.0, min(100.0, 100.0 - avg_q)), 1)
        
        return {
            "scan_id": target_scan_id,
            "scan_meta": dict(scan_row) if scan_row else {},
            "total_assets": total,
            "hndl_critical": critical_count,
            "avg_q_score": round(avg_q, 1),
            "readiness_pct": readiness_pct,
            "tier_breakdown": tier_counts,
            "asset_types": asset_types,
            "findings": findings
        }

# --- Settings ---

def get_settings() -> Dict[str, str]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in cursor.fetchall()}

def update_setting(key: str, value: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
