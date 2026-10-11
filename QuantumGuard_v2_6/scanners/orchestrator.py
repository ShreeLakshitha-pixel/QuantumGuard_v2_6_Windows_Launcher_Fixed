"""
Scan Orchestrator for QuantumGuard.
Coordinates multi-vector discovery across files, certificates, configs, and live TLS sockets,
evaluating findings against Mosca's theorem and persisting results to SQLite.
"""
import os
import time
from typing import Callable, Optional, Dict, Any, List
from database.models import CryptoAsset, ScanRecord, RiskTier
from database import db
from core.mosca_engine import MoscaEngine
from core.migration_gen import MigrationDiffGenerator
from scanners.cert_scanner import CertScanner
from scanners.code_scanner import CodeScanner
from scanners.config_scanner import ConfigScanner
from scanners.tls_scanner import TLSScanner

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv",
    "env", "__pycache__", ".idea", ".vscode", "dist", "build"
}

class ScanOrchestrator:
    def __init__(self):
        self.cert_scanner = CertScanner()
        self.code_scanner = CodeScanner()
        self.config_scanner = ConfigScanner()
        self.tls_scanner = TLSScanner()

    def run_scan(
        self,
        scan_id: int,
        target_type: str,
        target_path: str,
        log_callback: Optional[Callable[[str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes a scan job synchronously or inside an async background worker.
        """
        def log(level: str, msg: str):
            db.add_scan_log(scan_id, level, msg)
            if log_callback:
                try:
                    log_callback(level, msg)
                except Exception:
                    pass

        log("INFO", f"Initiating QuantumGuard scan (Job #{scan_id}) on target: {target_path} (Type: {target_type})")
        
        # Load user settings for Mosca engine
        settings = db.get_settings()
        crqc_year = int(settings.get("crqc_horizon_year", 2033))
        migration_years = float(settings.get("default_migration_time_years", 3.0))
        current_year = int(settings.get("current_year", 2026))

        mosca = MoscaEngine(
            crqc_year=crqc_year,
            current_year=current_year,
            default_migration_years=migration_years
        )

        discovered_assets: List[CryptoAsset] = []

        try:
            # 1. Network / Live TLS Scan
            if target_type in ["network_tls", "combined"]:
                log("INFO", f"Connecting to live network endpoint: {target_path}")
                # Target path can be comma-separated or single host
                endpoints = [e.strip() for e in target_path.split(",") if e.strip()]
                for ep in endpoints:
                    try:
                        log("INFO", f"Probing TLS socket for {ep}...")
                        tls_assets = self.tls_scanner.scan_endpoint(ep)
                        if tls_assets:
                            log("SUCCESS", f"Negotiated TLS with {ep}: Discovered {len(tls_assets)} cryptographic attributes.")
                            discovered_assets.extend(tls_assets)
                        else:
                            log("WARNING", f"No TLS response or non-SSL service on {ep}.")
                    except Exception as e:
                        log("ERROR", f"Failed probing {ep}: {str(e)}")

            # 2. Local Filesystem / Directory Scan
            if target_type in ["local_directory", "combined"]:
                abs_path = os.path.abspath(target_path)
                if not os.path.exists(abs_path):
                    log("ERROR", f"Target path does not exist: {abs_path}")
                    db.update_scan_status(scan_id, "FAILED", 0, 0, 0.0, {"error": "Path not found"})
                    return {"status": "FAILED", "error": "Path not found"}

                log("INFO", f"Crawling directory tree starting at: {abs_path}")
                file_count = 0

                for root, dirs, files in os.walk(abs_path):
                    # Filter out ignored dirs in-place
                    dirs[:] = [d for d in dirs if d.lower() not in IGNORE_DIRS]

                    for file in files:
                        file_count += 1
                        file_path = os.path.join(root, file)

                        # A. Check Certs & Keys
                        try:
                            cert_assets = self.cert_scanner.scan_file(file_path)
                            if cert_assets:
                                log("INFO", f"Found {len(cert_assets)} certificate/key asset(s) in {file}")
                                discovered_assets.extend(cert_assets)
                        except Exception as e:
                            log("DEBUG", f"Cert scanner error on {file}: {e}")

                        # B. Check Source Code
                        try:
                            code_assets = self.code_scanner.scan_file(file_path)
                            if code_assets:
                                log("INFO", f"Found {len(code_assets)} cryptographic call(s) in {file}")
                                discovered_assets.extend(code_assets)
                        except Exception as e:
                            log("DEBUG", f"Code scanner error on {file}: {e}")

                        # C. Check Configurations
                        try:
                            cfg_assets = self.config_scanner.scan_file(file_path)
                            if cfg_assets:
                                log("INFO", f"Found {len(cfg_assets)} TLS config primitive(s) in {file}")
                                discovered_assets.extend(cfg_assets)
                        except Exception as e:
                            log("DEBUG", f"Config scanner error on {file}: {e}")

                log("INFO", f"Completed file crawling. Inspected {file_count} files.")

            log("INFO", f"Total cryptographic assets discovered: {len(discovered_assets)}. Evaluating against Mosca's Theorem...")

            # 3. Evaluate each asset with Mosca's Equation & Generate Migration Roadmap
            hndl_critical_count = 0
            total_q = 0.0

            for asset in discovered_assets:
                asset.scan_id = scan_id
                
                # Assess with Mosca engine
                vuln, expl = mosca.assess_asset(asset)
                vuln.scan_id = scan_id

                # Generate NIST PQC migration recipe
                rec = MigrationDiffGenerator.generate_recommendation(asset, scan_id)
                rec.scan_id = scan_id

                # Persist to SQLite
                db.save_finding(scan_id, asset, vuln, rec)

                if vuln.severity == RiskTier.CRITICAL.value:
                    hndl_critical_count += 1
                total_q += vuln.q_score

            total_assets = len(discovered_assets)
            avg_q = round(total_q / total_assets, 1) if total_assets > 0 else 0.0

            summary = {
                "total_assets": total_assets,
                "hndl_critical": hndl_critical_count,
                "avg_q_score": avg_q,
                "crqc_horizon_year": crqc_year,
                "migration_years": migration_years
            }

            db.update_scan_status(scan_id, "COMPLETED", total_assets, hndl_critical_count, avg_q, summary)
            log("SUCCESS", f"Scan #{scan_id} finished. Discovered: {total_assets} assets | HNDL Critical: {hndl_critical_count} | Avg Q-Score: {avg_q}")

            return {"status": "COMPLETED", "summary": summary}

        except Exception as e:
            log("ERROR", f"Fatal error during scan: {str(e)}")
            db.update_scan_status(scan_id, "FAILED", 0, 0, 0.0, {"error": str(e)})
            return {"status": "FAILED", "error": str(e)}
