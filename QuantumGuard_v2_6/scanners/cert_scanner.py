"""
Real X.509 Certificate, Public/Private Key, and SSH Key Scanner.
Parses ASN.1 structures and PEM/DER files using cryptography library.
"""
import os
from typing import List, Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key
)
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from database.models import CryptoAsset, AssetType, ExposureLevel

class CertScanner:
    SUPPORTED_EXTENSIONS = {
        ".pem", ".crt", ".cer", ".der", ".key", ".pub", ".cert"
    }

    def scan_file(self, file_path: str) -> List[CryptoAsset]:
        """
        Inspects a single file for X.509 certificates, private keys, or public keys.
        """
        assets = []
        if not os.path.exists(file_path):
            return assets

        # Check extension or known SSH names
        basename = os.path.basename(file_path).lower()
        is_ssh = basename in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts"]
        has_ext = any(basename.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS)
        
        if not (has_ext or is_ssh):
            return assets

        try:
            with open(file_path, "rb") as f:
                content = f.read()
        except Exception:
            return assets

        if not content:
            return assets

        # 1. Try parsing as X.509 PEM certificate
        if b"-----BEGIN CERTIFICATE-----" in content:
            for pem_block in content.split(b"-----BEGIN CERTIFICATE-----")[1:]:
                full_pem = b"-----BEGIN CERTIFICATE-----" + pem_block.split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----"
                try:
                    cert = x509.load_pem_x509_certificate(full_pem)
                    asset = self._parse_x509_cert(cert, file_path)
                    if asset:
                        assets.append(asset)
                except Exception:
                    pass

        # 2. Try parsing as DER certificate
        if not assets and file_path.endswith((".der", ".cer")):
            try:
                cert = x509.load_der_x509_certificate(content)
                asset = self._parse_x509_cert(cert, file_path)
                if asset:
                    assets.append(asset)
            except Exception:
                pass

        # 3. Try parsing as Private Key (RSA / EC)
        if b"PRIVATE KEY-----" in content:
            try:
                # Password-less check
                pkey = load_pem_private_key(content, password=None)
                asset = self._parse_private_key(pkey, file_path)
                if asset:
                    assets.append(asset)
            except Exception:
                pass

        # 4. Try parsing as Public Key
        if b"PUBLIC KEY-----" in content:
            try:
                pubkey = load_pem_public_key(content)
                asset = self._parse_public_key(pubkey, file_path)
                if asset:
                    assets.append(asset)
            except Exception:
                pass

        # 5. Try parsing as SSH Public Key
        if not assets and (is_ssh or file_path.endswith(".pub")):
            try:
                lines = content.splitlines()
                for idx, line in enumerate(lines, start=1):
                    line_str = line.strip()
                    if line_str.startswith((b"ssh-rsa", b"ssh-dss", b"ecdsa-", b"ssh-ed25519")):
                        try:
                            ssh_key = load_ssh_public_key(line_str)
                            asset = self._parse_ssh_key(ssh_key, file_path, line_number=idx)
                            if asset:
                                assets.append(asset)
                        except Exception:
                            pass
            except Exception:
                pass

        return assets

    def _parse_x509_cert(self, cert: x509.Certificate, file_path: str) -> Optional[CryptoAsset]:
        try:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = hex(cert.serial_number)
            
            # Dates
            try:
                not_before = cert.not_valid_before_utc.isoformat()
                not_after = cert.not_valid_after_utc.isoformat()
            except AttributeError:
                not_before = cert.not_valid_before.isoformat()
                not_after = cert.not_valid_after.isoformat()

            sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
            
            # Public key properties
            pubkey = cert.public_key()
            algo_name = "UNKNOWN"
            key_size = None
            curve_name = None

            if isinstance(pubkey, rsa.RSAPublicKey):
                algo_name = "RSA"
                key_size = pubkey.key_size
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                algo_name = "ECDSA"
                key_size = pubkey.key_size
                curve_name = pubkey.curve.name
            elif isinstance(pubkey, ed25519.Ed25519PublicKey):
                algo_name = "Ed25519"
                key_size = 256
            elif isinstance(pubkey, ed448.Ed448PublicKey):
                algo_name = "Ed448"
                key_size = 448
            elif isinstance(pubkey, dsa.DSAPublicKey):
                algo_name = "DSA"
                key_size = pubkey.key_size

            name = subject.split("CN=")[-1].split(",")[0] if "CN=" in subject else os.path.basename(file_path)

            return CryptoAsset(
                name=f"X.509 Cert: {name}",
                asset_type=AssetType.CERTIFICATE.value,
                location=file_path,
                line_number=1,
                algorithm=f"{algo_name}-{key_size}" if key_size else algo_name,
                key_size=key_size,
                curve_name=curve_name,
                signature_algorithm=sig_algo,
                purpose="TLS Server Authentication / Identity",
                exposure_level=ExposureLevel.PUBLIC_INTERNET.value if "cert" in file_path.lower() else ExposureLevel.INTERNAL_NETWORK.value,
                data_shelf_life_years=10.0,
                code_snippet=f"Subject: {subject}\nIssuer: {issuer}\nValid: {not_before} to {not_after}",
                raw_metadata={
                    "subject": subject,
                    "issuer": issuer,
                    "serial": serial,
                    "not_before": not_before,
                    "not_after": not_after,
                    "signature_algorithm": sig_algo
                }
            )
        except Exception:
            return None

    def _parse_private_key(self, pkey: Any, file_path: str) -> Optional[CryptoAsset]:
        try:
            algo_name = "UNKNOWN"
            key_size = None
            curve_name = None

            if isinstance(pkey, rsa.RSAPrivateKey):
                algo_name = "RSA"
                key_size = pkey.key_size
            elif isinstance(pkey, ec.EllipticCurvePrivateKey):
                algo_name = "ECDSA"
                key_size = pkey.key_size
                curve_name = pkey.curve.name
            elif isinstance(pkey, ed25519.Ed25519PrivateKey):
                algo_name = "Ed25519"
                key_size = 256

            return CryptoAsset(
                name=f"Private Key: {os.path.basename(file_path)}",
                asset_type=AssetType.PRIVATE_KEY.value,
                location=file_path,
                line_number=1,
                algorithm=f"{algo_name}-{key_size}" if key_size else algo_name,
                key_size=key_size,
                curve_name=curve_name,
                signature_algorithm=None,
                purpose="Private Key Signing & Decryption",
                exposure_level=ExposureLevel.AT_REST_STORAGE.value,
                data_shelf_life_years=12.0,
                code_snippet=f"Private key file: {os.path.basename(file_path)} ({algo_name})",
                raw_metadata={"key_type": "PEM Private Key", "size": key_size, "curve": curve_name}
            )
        except Exception:
            return None

    def _parse_public_key(self, pubkey: Any, file_path: str) -> Optional[CryptoAsset]:
        try:
            algo_name = "UNKNOWN"
            key_size = None
            curve_name = None

            if isinstance(pubkey, rsa.RSAPublicKey):
                algo_name = "RSA"
                key_size = pubkey.key_size
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                algo_name = "ECDSA"
                key_size = pubkey.key_size
                curve_name = pubkey.curve.name
            elif isinstance(pubkey, ed25519.Ed25519PublicKey):
                algo_name = "Ed25519"
                key_size = 256

            return CryptoAsset(
                name=f"Public Key: {os.path.basename(file_path)}",
                asset_type=AssetType.PUBLIC_KEY.value,
                location=file_path,
                line_number=1,
                algorithm=f"{algo_name}-{key_size}" if key_size else algo_name,
                key_size=key_size,
                curve_name=curve_name,
                signature_algorithm=None,
                purpose="Public Key Verification / Encryption",
                exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                data_shelf_life_years=8.0,
                code_snippet=f"Public key: {algo_name} ({key_size or ''} bits)",
                raw_metadata={"key_type": "PEM Public Key", "size": key_size}
            )
        except Exception:
            return None

    def _parse_ssh_key(self, ssh_key: Any, file_path: str, line_number: int = 1) -> Optional[CryptoAsset]:
        try:
            algo_name = "UNKNOWN"
            key_size = None
            curve_name = None

            if isinstance(ssh_key, rsa.RSAPublicKey):
                algo_name = "SSH-RSA"
                key_size = ssh_key.key_size
            elif isinstance(ssh_key, ec.EllipticCurvePublicKey):
                algo_name = "SSH-ECDSA"
                key_size = ssh_key.key_size
                curve_name = ssh_key.curve.name
            elif isinstance(ssh_key, ed25519.Ed25519PublicKey):
                algo_name = "SSH-ED25519"
                key_size = 256

            return CryptoAsset(
                name=f"SSH Public Key ({algo_name})",
                asset_type=AssetType.PUBLIC_KEY.value,
                location=file_path,
                line_number=line_number,
                algorithm=f"{algo_name}-{key_size}" if key_size else algo_name,
                key_size=key_size,
                curve_name=curve_name,
                purpose="SSH Remote Access Authentication",
                exposure_level=ExposureLevel.INTERNAL_NETWORK.value,
                data_shelf_life_years=5.0,
                code_snippet=f"SSH key at line {line_number}",
                raw_metadata={"protocol": "OpenSSH", "size": key_size}
            )
        except Exception:
            return None
