"""
DevOps and Web Server Cryptographic Configuration Scanner.
Inspects Nginx, Apache, OpenSSL, Dockerfiles, and Kubernetes YAML configurations.
"""
import os
import re
from typing import List
from database.models import CryptoAsset, AssetType, ExposureLevel

class ConfigScanner:
    SUPPORTED_FILENAMES = {
        "nginx.conf", "httpd.conf", "openssl.cnf", "dockerfile", "docker-compose.yml"
    }
    SUPPORTED_EXTENSIONS = {
        ".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".env"
    }

    def scan_file(self, file_path: str) -> List[CryptoAsset]:
        assets = []
        if not os.path.exists(file_path):
            return assets

        basename = os.path.basename(file_path).lower()
        ext = os.path.splitext(file_path)[1].lower()

        if not (basename in self.SUPPORTED_FILENAMES or ext in self.SUPPORTED_EXTENSIONS or "dockerfile" in basename):
            return assets

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return assets

        if not content.strip():
            return assets

        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if line_str.startswith(("#", "//")):
                continue

            # 1. Nginx / Apache Cipher Suites
            if re.search(r'(?:ssl_ciphers|SSLCipherSuite)\s+["\']?([^;"\']+)', line, re.IGNORECASE):
                match = re.search(r'(?:ssl_ciphers|SSLCipherSuite)\s+["\']?([^;"\']+)', line, re.IGNORECASE)
                ciphers_val = match.group(1).strip()
                
                # Check for legacy or Grover-impacted
                algo = "TLS-CipherSuite"
                if "ECDHE" in ciphers_val or "RSA" in ciphers_val:
                    algo = "ECDHE-RSA-CipherSuite"
                elif "AES128" in ciphers_val or "AES-128" in ciphers_val:
                    algo = "AES-128-TLS"
                elif "3DES" in ciphers_val:
                    algo = "3DES"

                assets.append(CryptoAsset(
                    name=f"Web Server Ciphers: {os.path.basename(file_path)}",
                    asset_type=AssetType.CONFIG_FILE.value,
                    location=file_path,
                    line_number=idx,
                    algorithm=algo,
                    key_size=2048,
                    purpose="Web Server Ingress TLS Cipher Suite",
                    exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                    data_shelf_life_years=5.0,
                    code_snippet=line_str,
                    raw_metadata={"ciphers": ciphers_val}
                ))

            # 2. TLS Protocols
            elif re.search(r'(?:ssl_protocols|SSLProtocol)\s+([^;]+)', line, re.IGNORECASE):
                proto_val = re.search(r'(?:ssl_protocols|SSLProtocol)\s+([^;]+)', line, re.IGNORECASE).group(1).strip()
                if "TLSv1 " in proto_val or "TLSv1.1" in proto_val or "TLSv1.2" in proto_val:
                    assets.append(CryptoAsset(
                        name=f"TLS Protocol Config: {proto_val}",
                        asset_type=AssetType.CONFIG_FILE.value,
                        location=file_path,
                        line_number=idx,
                        algorithm="TLSv1.2-Legacy",
                        key_size=None,
                        purpose="Server Protocol Policy",
                        exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                        data_shelf_life_years=5.0,
                        code_snippet=line_str,
                        raw_metadata={"protocols": proto_val}
                    ))

            # 3. ECDH Curves
            elif re.search(r'ssl_ecdh_curve\s+([^;]+)', line, re.IGNORECASE):
                curve_val = re.search(r'ssl_ecdh_curve\s+([^;]+)', line, re.IGNORECASE).group(1).strip()
                is_pqc = "kyber" in curve_val.lower() or "mlkem" in curve_val.lower()
                algo = "ML-KEM-Hybrid" if is_pqc else "Classical-ECDH-Curve"

                assets.append(CryptoAsset(
                    name=f"TLS Key Exchange Curve: {curve_val}",
                    asset_type=AssetType.CONFIG_FILE.value,
                    location=file_path,
                    line_number=idx,
                    algorithm=algo,
                    key_size=256,
                    curve_name=curve_val,
                    purpose="TLS Handshake Curve Negotiation",
                    exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                    data_shelf_life_years=5.0,
                    code_snippet=line_str,
                    raw_metadata={"curves": curve_val}
                ))

        return assets
