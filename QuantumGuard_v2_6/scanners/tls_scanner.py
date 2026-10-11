"""
Real Live Network TLS Handshake & Cipher Suite Scanner.
Performs socket-level TLS probing against live hosts to extract negotiated
key exchange primitives, server certificates, and cipher suites.
"""
import socket
import ssl
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from database.models import CryptoAsset, AssetType, ExposureLevel

class TLSScanner:
    def scan_endpoint(self, target: str, port: int = 443, timeout: float = 8.0) -> List[CryptoAsset]:
        """
        Connects via real TLS socket, negotiates handshake, extracts cipher suite and X.509 cert.
        """
        assets = []
        host = target.strip()
        
        # Clean URL if provided
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
            if parsed.port:
                port = parsed.port
        elif ":" in host:
            parts = host.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        try:
            # Create SSL context (permissive verification to inspect certs without crashing on self-signed)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as s_sock:
                    cipher_info = s_sock.cipher() # ('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1.2', 128)
                    tls_version = s_sock.version() # 'TLSv1.3' or 'TLSv1.2'
                    der_cert = s_sock.getpeercert(binary_form=True)

                    cipher_name = cipher_info[0] if cipher_info else "UNKNOWN"
                    symm_bits = cipher_info[2] if cipher_info else 128

                    # 1. Parse Negotiated Key Exchange / Session Asset
                    is_hybrid = any(k in cipher_name.lower() for k in ["kyber", "mlkem", "ml-kem", "pqc"])
                    kx_algo = "TLS-KeyExchange"
                    if "ECDHE" in cipher_name or "ECDH" in cipher_name:
                        kx_algo = "ECDHE (Shor Vulnerable)"
                    elif "DHE" in cipher_name or "DH" in cipher_name:
                        kx_algo = "DHE (Shor Vulnerable)"
                    elif is_hybrid:
                        kx_algo = "X25519+ML-KEM-768 (Quantum Safe Hybrid)"
                    elif "RSA" in cipher_name and tls_version != "TLSv1.3":
                        kx_algo = "RSA-KeyExchange (Shor Vulnerable)"
                    else:
                        kx_algo = f"TLS-KX-{cipher_name}"

                    assets.append(CryptoAsset(
                        name=f"TLS Key Exchange: {host}:{port}",
                        asset_type=AssetType.TLS_ENDPOINT.value,
                        location=f"tls://{host}:{port}",
                        line_number=None,
                        algorithm=kx_algo,
                        key_size=256 if "ECDH" in kx_algo else 2048,
                        purpose=f"Live TLS Session Handshake ({tls_version})",
                        exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                        data_shelf_life_years=5.0,
                        code_snippet=f"Target: {host}:{port}\nProtocol: {tls_version}\nCipher: {cipher_name}\nKey Exchange: {kx_algo}",
                        raw_metadata={
                            "host": host,
                            "port": port,
                            "tls_version": tls_version,
                            "cipher_suite": cipher_name,
                            "symmetric_bits": symm_bits,
                            "is_hybrid_pqc": is_hybrid
                        }
                    ))

                    # 2. Parse Server Certificate from DER bytes
                    if der_cert:
                        try:
                            cert = x509.load_der_x509_certificate(der_cert)
                            subject = cert.subject.rfc4514_string()
                            issuer = cert.issuer.rfc4514_string()
                            
                            try:
                                not_before = cert.not_valid_before_utc.isoformat()
                                not_after = cert.not_valid_after_utc.isoformat()
                            except AttributeError:
                                not_before = cert.not_valid_before.isoformat()
                                not_after = cert.not_valid_after.isoformat()

                            pubkey = cert.public_key()
                            cert_algo = "UNKNOWN"
                            cert_size = None

                            if isinstance(pubkey, rsa.RSAPublicKey):
                                cert_algo = "RSA"
                                cert_size = pubkey.key_size
                            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                                cert_algo = "ECDSA"
                                cert_size = pubkey.key_size
                            elif isinstance(pubkey, ed25519.Ed25519PublicKey):
                                cert_algo = "Ed25519"
                                cert_size = 256

                            sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)

                            assets.append(CryptoAsset(
                                name=f"TLS Peer Cert: {host}",
                                asset_type=AssetType.CERTIFICATE.value,
                                location=f"tls://{host}:{port}/cert",
                                line_number=None,
                                algorithm=f"{cert_algo}-{cert_size}" if cert_size else cert_algo,
                                key_size=cert_size,
                                signature_algorithm=sig_algo,
                                purpose="TLS Server Authentication",
                                exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                                data_shelf_life_years=7.0,
                                code_snippet=f"Subject: {subject}\nIssuer: {issuer}\nKey: {cert_algo} ({cert_size} bits)\nSig: {sig_algo}",
                                raw_metadata={
                                    "subject": subject,
                                    "issuer": issuer,
                                    "not_before": not_before,
                                    "not_after": not_after,
                                    "serial": hex(cert.serial_number)
                                }
                            ))
                        except Exception:
                            pass

                    # 3. Symmetric Transport Cipher
                    if "AES-128" in cipher_name:
                        assets.append(CryptoAsset(
                            name=f"Bulk Cipher: AES-128 ({host})",
                            asset_type=AssetType.TLS_ENDPOINT.value,
                            location=f"tls://{host}:{port}",
                            line_number=None,
                            algorithm="AES-128",
                            key_size=128,
                            purpose="TLS Bulk Symmetric Transport (Grover Affected)",
                            exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                            data_shelf_life_years=5.0,
                            code_snippet=f"Cipher: {cipher_name} (128-bit key length)",
                            raw_metadata={"cipher": cipher_name}
                        ))
                    elif "AES-256" in cipher_name or "CHACHA20" in cipher_name:
                        assets.append(CryptoAsset(
                            name=f"Bulk Cipher: AES-256 / ChaCha20 ({host})",
                            asset_type=AssetType.TLS_ENDPOINT.value,
                            location=f"tls://{host}:{port}",
                            line_number=None,
                            algorithm="AES-256",
                            key_size=256,
                            purpose="Quantum Grover-Resistant Symmetric Transport",
                            exposure_level=ExposureLevel.PUBLIC_INTERNET.value,
                            data_shelf_life_years=5.0,
                            code_snippet=f"Cipher: {cipher_name} (256-bit quantum-safe key)",
                            raw_metadata={"cipher": cipher_name}
                        ))

        except Exception as e:
            # Re-raise or return empty list
            pass

        return assets
