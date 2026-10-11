"""
Migration Recipe and Code Diff Generator.
Produces actionable before-and-after implementation code and server configs.
"""
from typing import Dict, Any
from database.models import CryptoAsset, MigrationRecommendation
from core.pqc_catalog import get_pqc_mapping

class MigrationDiffGenerator:
    @staticmethod
    def generate_recommendation(asset: CryptoAsset, scan_id: int) -> MigrationRecommendation:
        mapping = get_pqc_mapping(asset.algorithm, asset.purpose)
        nist_std = mapping["nist_standard"]
        hybrid = mapping["hybrid"]
        std_ref = mapping["standard_reference"]
        effort = mapping["effort"]
        
        algo = asset.algorithm.upper()
        asset_type = asset.asset_type
        
        # 1. TLS Endpoint Migration Recipe
        if asset_type == "TLS_ENDPOINT" or "TLS" in algo or "CONFIG" in asset_type:
            diff_title = "Modernize TLS Gateway to Quantum-Safe Hybrid Key Exchange"
            curr_code = (
                "# Deprecated / Quantum-Vulnerable TLS Server Configuration\n"
                "ssl_protocols TLSv1.2 TLSv1.3;\n"
                "ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';\n"
                "ssl_ecdh_curve prime256v1:secp384r1;\n"
                "# Vulnerable to Shor's algorithm harvesting today"
            )
            migrated_code = (
                "# NIST FIPS 203 Post-Quantum Hybrid Configuration (Cloudflare/BoringSSL/Nginx)\n"
                "ssl_protocols TLSv1.3;\n"
                "ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256';\n"
                "# Enable X25519 + ML-KEM-768 hybrid key exchange curve:\n"
                "ssl_ecdh_curve X25519Kyber768Draft00:x25519:secp384r1;\n"
                "ssl_prefer_server_ciphers on;\n"
                "# Protects traffic against Harvest Now, Decrypt Later (HNDL)"
            )
            recipe = (
                "1. Upgrade OpenSSL to v3.2+ or enable the Open Quantum Safe (OQS) Provider.\n"
                "2. Configure web ingress / reverse proxy (Nginx, Envoy, Cloudflare, Traefik) to enable X25519Kyber768Draft00.\n"
                "3. Enforce TLS 1.3 only for sensitive communications to eliminate legacy cipher negotiation."
            )

        # 2. X.509 Certificate / Public Key
        elif asset_type in ["CERTIFICATE", "PUBLIC_KEY", "PRIVATE_KEY"]:
            diff_title = f"Transition PKI Certificate from {asset.algorithm} to Composite ML-DSA / ML-KEM"
            curr_code = (
                f"# Generating vulnerable {asset.algorithm} Keypair (OpenSSL CLI)\n"
                f"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server.key\n"
                f"openssl req -new -x509 -key server.key -out server.crt -days 365\n"
                f"# Subject: {asset.name}\n"
                f"# Broken by Shor's algorithm once CRQC arrives"
            )
            migrated_code = (
                f"# Generating NIST FIPS 204 Quantum-Safe Certificate using OpenSSL OQS Provider\n"
                f"openssl req -new -newkey mldsa65 -nodes -keyout pqc_server.key \\\n"
                f"    -out pqc_server.csr -subj '/CN={asset.name}'\n"
                f"openssl x509 -req -in pqc_server.csr -signkey pqc_server.key \\\n"
                f"    -out pqc_server.crt -days 365\n"
                f"# Or Composite Dual-Certificate (Classic ECDSA + ML-DSA-65) for backward compatibility"
            )
            recipe = (
                "1. Establish a dual-root or hybrid PKI hierarchy (Classical CA + PQC Subordinate CA).\n"
                "2. Issue composite certificates containing both traditional ECDSA/RSA keys and ML-DSA-65 public keys.\n"
                "3. Deploy certificates to internal endpoints and mTLS gateways."
            )

        # 3. Python Source Code Migration
        elif "PYTHON" in asset.location.upper() or asset.location.endswith(".py"):
            if "AES" in algo:
                diff_title = "Upgrade Symmetric Encryption from AES-128 to Grover-Resistant AES-256-GCM"
                curr_code = (
                    "# Legacy vulnerable AES-128 CBC mode\n"
                    "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
                    "key = os.urandom(16)  # 128 bits: halved to 64-bit strength under Grover's search\n"
                    "cipher = Cipher(algorithms.AES(key), modes.CBC(iv))\n"
                    "encryptor = cipher.encryptor()"
                )
                migrated_code = (
                    "# Quantum-Resistant AES-256 in Authenticated GCM Mode\n"
                    "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                    "key = AESGCM.generate_key(bit_length=256)  # 256 bits: retains 128-bit quantum security\n"
                    "aesgcm = AESGCM(key)\n"
                    "nonce = os.urandom(12)\n"
                    "ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)"
                )
            else:
                diff_title = f"Refactor Asymmetric Exchange from {asset.algorithm} to NIST FIPS 203 (ML-KEM-768)"
                curr_code = (
                    f"# Legacy {asset.algorithm} Key Generation & Exchange\n"
                    "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
                    "from cryptography.hazmat.primitives import hashes\n\n"
                    "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                    "public_key = private_key.public_key()\n"
                    "# Exposed to Harvest Now, Decrypt Later"
                )
                migrated_code = (
                    "# NIST FIPS 203 ML-KEM-768 (or Hybrid X25519+ML-KEM-768)\n"
                    "from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt\n\n"
                    "# 1. Recipient generates post-quantum KEM keypair\n"
                    "public_key, secret_key = generate_keypair()\n\n"
                    "# 2. Sender encapsulates shared secret\n"
                    "ciphertext, shared_secret_sender = encrypt(public_key)\n\n"
                    "# 3. Recipient decapsulates shared secret\n"
                    "shared_secret_recipient = decrypt(secret_key, ciphertext)\n"
                    "# shared_secret is quantum-secure and used for AES-256 payload encryption"
                )
            recipe = (
                "1. Add 'pqcrypto' or 'oqs' Python library to application dependencies.\n"
                "2. Replace RSA/ECDH key exchange routines with ML-KEM encapsulation (KEM pattern).\n"
                "3. Derive a 256-bit symmetric session key with HKDF-SHA384 and encrypt bulk payloads via AES-256-GCM."
            )

        # 4. JavaScript / TypeScript / Node.js
        elif any(asset.location.endswith(ext) for ext in [".js", ".ts", ".mjs"]):
            diff_title = f"Refactor Node.js Crypto from {asset.algorithm} to Quantum-Safe Hybrid"
            curr_code = (
                "// Legacy Node.js RSA/ECDSA implementation\n"
                "const crypto = require('crypto');\n"
                "const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {\n"
                "  modulusLength: 2048,\n"
                "});\n"
                "// Vulnerable to Shor's algorithm"
            )
            migrated_code = (
                "// Post-Quantum Hybrid via @openquantumsafe or ML-KEM WASM\n"
                "import { mlKem768 } from '@pq-crystals/kyber';\n\n"
                "// Recipient generates PQC keypair\n"
                "const { publicKey, privateKey } = mlKem768.keypair();\n"
                "// Sender encapsulates shared secret\n"
                "const { ciphertext, sharedSecret } = mlKem768.encap(publicKey);\n"
                "// sharedSecret feeds AES-256-GCM symmetric transport"
            )
            recipe = (
                "1. Install post-quantum WebAssembly or native bindings (e.g. @pq-crystals/kyber).\n"
                "2. Abstract cryptography behind an Agility Factory interface.\n"
                "3. Use hybrid encapsulation until all downstream client endpoints support FIPS 203 natively."
            )

        # 5. Generic Fallback
        else:
            diff_title = f"Migrate {asset.algorithm} to {nist_std}"
            curr_code = f"# Current Primitive: {asset.algorithm} (Location: {asset.location})\n# Vulnerable to quantum cryptanalysis"
            migrated_code = f"# Recommended Replacement: {nist_std} ({std_ref})\n# Hybrid alternative: {hybrid}\n# Implements lattice-based post-quantum security"
            recipe = f"Replace {asset.algorithm} invocations with {nist_std} conforming to {std_ref}."

        return MigrationRecommendation(
            asset_id=asset.id,
            scan_id=scan_id,
            current_primitive=asset.algorithm,
            nist_standard_replacement=nist_std,
            hybrid_replacement=hybrid,
            standard_reference=std_ref,
            code_diff_title=diff_title,
            current_code_snippet=curr_code,
            migrated_code_snippet=migrated_code,
            configuration_recipe=recipe,
            migration_effort=effort
        )
