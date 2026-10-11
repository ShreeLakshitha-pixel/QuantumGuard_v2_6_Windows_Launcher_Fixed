"""
NIST Post-Quantum Cryptography Standard Catalog.
Aligns findings directly with finalized standards:
- FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
- FIPS 204: ML-DSA (Module-Lattice Digital Signature Algorithm)
- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
- NIST SP 800-208: LMS / XMSS (Stateful Hash-Based Signatures)
- IETF Drafts: X25519 + ML-KEM-768 Hybrid Key Exchange
"""

PQC_STANDARDS_METADATA = {
    "ML-KEM-768": {
        "standard": "NIST FIPS 203",
        "category": "Key Encapsulation Mechanism (KEM)",
        "security_level": "NIST Level 3 (Equivalent to AES-192 / classical RSA-3072 / P-384)",
        "public_key_bytes": 1184,
        "ciphertext_bytes": 1088,
        "ideal_for": "General TLS session key exchange, API encryption, hybrid communications.",
        "hybrid_counterpart": "X25519 + ML-KEM-768 (draft-ietf-tls-hybrid-design)"
    },
    "ML-KEM-1024": {
        "standard": "NIST FIPS 203",
        "category": "Key Encapsulation Mechanism (KEM)",
        "security_level": "NIST Level 5 (Equivalent to AES-256)",
        "public_key_bytes": 1568,
        "ciphertext_bytes": 1568,
        "ideal_for": "Top-secret data, long-term archival key transport, defense/banking.",
        "hybrid_counterpart": "P-384 + ML-KEM-1024"
    },
    "ML-DSA-65": {
        "standard": "NIST FIPS 204",
        "category": "Digital Signature Algorithm (DSA)",
        "security_level": "NIST Level 3 (Equivalent to AES-192 / ECDSA P-256)",
        "public_key_bytes": 1952,
        "signature_bytes": 3309,
        "ideal_for": "General digital signatures, PKI certificates, document signing, identity tokens.",
        "hybrid_counterpart": "Composite ECDSA P-256 + ML-DSA-65"
    },
    "ML-DSA-87": {
        "standard": "NIST FIPS 204",
        "category": "Digital Signature Algorithm (DSA)",
        "security_level": "NIST Level 5 (Highest security)",
        "public_key_bytes": 2592,
        "signature_bytes": 4627,
        "ideal_for": "Root CA, Master signing certificates, high-assurance authentication.",
        "hybrid_counterpart": "Composite RSA-4096 + ML-DSA-87"
    },
    "SLH-DSA-SHAKE-128s": {
        "standard": "NIST FIPS 205",
        "category": "Stateless Hash-Based Signature",
        "security_level": "NIST Level 1",
        "public_key_bytes": 32,
        "signature_bytes": 7856,
        "ideal_for": "Conservative fallback against lattice cryptanalysis; firmware authentication.",
        "hybrid_counterpart": "Ed25519 + SLH-DSA"
    },
    "LMS / XMSS": {
        "standard": "NIST SP 800-208",
        "category": "Stateful Hash-Based Signature",
        "security_level": "High (Hash-theory backed)",
        "public_key_bytes": 60,
        "signature_bytes": 2500,
        "ideal_for": "IoT bootloaders, hardware firmware signing (infrequent updates).",
        "hybrid_counterpart": "RSA-4096 + LMS"
    },
    "AES-256-GCM": {
        "standard": "NIST SP 800-38D",
        "category": "Authenticated Symmetric Cipher",
        "security_level": "128 bits post-quantum security against Grover's algorithm",
        "public_key_bytes": 0,
        "ciphertext_bytes": 0,
        "ideal_for": "Data at rest, database encryption, high-throughput bulk payload encryption.",
        "hybrid_counterpart": "N/A (Symmetric upgrade from AES-128)"
    }
}

def get_pqc_mapping(algorithm: str, purpose: str = ""):
    """
    Returns recommended NIST standard, hybrid alternative, and specification details.
    """
    algo = algorithm.upper()
    purpose_lower = purpose.lower()
    
    # 1. Key Exchange / Encryption (KEM)
    if any(k in algo for k in ["RSA", "ECDH", "X25519", "DIFFIE-HELLMAN", "DH", "KEY_EXCHANGE"]):
        if "SIGN" in purpose_lower or "SIGNATURE" in algo:
            # It's an RSA signature
            return {
                "nist_standard": "ML-DSA-65 (Module-Lattice DSA)",
                "hybrid": "Composite ECDSA P-256 + ML-DSA-65",
                "standard_reference": "NIST FIPS 204",
                "details": PQC_STANDARDS_METADATA["ML-DSA-65"],
                "effort": "MEDIUM"
            }
        else:
            return {
                "nist_standard": "ML-KEM-768 (Kyber-768)",
                "hybrid": "X25519 + ML-KEM-768 (Hybrid TLS 1.3)",
                "standard_reference": "NIST FIPS 203",
                "details": PQC_STANDARDS_METADATA["ML-KEM-768"],
                "effort": "LOW" if "TLS" in algo or "CONFIG" in algo else "MEDIUM"
            }
            
    # 2. Digital Signatures / Auth / Certificates
    if any(s in algo for s in ["ECDSA", "ED25519", "DSA", "SIGNATURE", "CERTIFICATE"]):
        if any(h in purpose_lower for h in ["firmware", "bootloader", "iot"]):
            return {
                "nist_standard": "LMS (Stateful Hash-Based Signature)",
                "hybrid": "RSA-4096 + LMS Hybrid",
                "standard_reference": "NIST SP 800-208",
                "details": PQC_STANDARDS_METADATA["LMS / XMSS"],
                "effort": "HIGH"
            }
        return {
            "nist_standard": "ML-DSA-65 (Module-Lattice DSA)",
            "hybrid": "Composite ECDSA P-256 + ML-DSA-65",
            "standard_reference": "NIST FIPS 204",
            "details": PQC_STANDARDS_METADATA["ML-DSA-65"],
            "effort": "MEDIUM"
        }

    # 3. Symmetric Ciphers
    if "AES-128" in algo or "3DES" in algo or "DES" in algo or "RC4" in algo:
        return {
            "nist_standard": "AES-256-GCM (256-bit Key Length)",
            "hybrid": "AES-256-GCM + ChaCha20-Poly1305 fallback",
            "standard_reference": "NIST SP 800-38D (Grover Resistant)",
            "details": PQC_STANDARDS_METADATA["AES-256-GCM"],
            "effort": "LOW"
        }

    # 4. Deprecated Hashes
    if any(h in algo for h in ["MD5", "SHA1", "SHA-1"]):
        return {
            "nist_standard": "SHA-384 / SHA3-256",
            "hybrid": "SHA-384 with HMAC",
            "standard_reference": "FIPS 180-4 / FIPS 202",
            "details": {
                "standard": "FIPS 180-4",
                "security_level": "Collision and Grover resistant (192-bit quantum margin)",
                "ideal_for": "Hashing, HMAC, integrity verification"
            },
            "effort": "LOW"
        }

    # Default fallback
    return {
        "nist_standard": "ML-KEM-768 / ML-DSA-65",
        "hybrid": "X25519 + ML-KEM-768",
        "standard_reference": "NIST FIPS 203 / FIPS 204",
        "details": PQC_STANDARDS_METADATA["ML-KEM-768"],
        "effort": "MEDIUM"
    }
