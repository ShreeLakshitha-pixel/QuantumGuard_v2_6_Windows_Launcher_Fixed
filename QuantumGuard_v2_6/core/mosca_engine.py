"""
Mosca's Inequality & Quantum Risk Assessment Engine (Q-Score Algorithm).
Implements mathematical modeling of "Harvest Now, Decrypt Later" (HNDL).
"""
import re
from typing import Tuple, Dict, Any
from database.models import (
    CryptoAsset,
    VulnerabilityRecord,
    RiskTier,
    ExposureLevel
)

class MoscaEngine:
    def __init__(
        self,
        crqc_year: int = 2033,
        current_year: int = 2026,
        default_migration_years: float = 3.0
    ):
        self.crqc_year = crqc_year
        self.current_year = current_year
        self.default_migration_years = default_migration_years
        self.z_horizon = max(1.0, float(self.crqc_year - self.current_year))

    def infer_shelf_life(self, name: str, location: str, purpose: str) -> float:
        """
        Infers data confidentiality shelf-life (X) in years based on context heuristics.
        """
        combined = f"{name} {location} {purpose}".lower()
        
        # Long-term sensitive (20 - 30 years)
        if any(k in combined for k in ["medical", "health", "phi", "patient", "biometric", "genomic", "national_security", "classified"]):
            return 30.0
            
        # Financial / High PII (10 - 20 years)
        if any(k in combined for k in ["banking", "payment", "pci", "credit", "ssn", "identity", "tax", "payroll", "legal"]):
            return 15.0
            
        # Corporate Confidential / Credentials (5 - 10 years)
        if any(k in combined for k in ["auth", "token", "jwt", "session_secret", "master_key", "ca_cert", "root_ca", "api_key", "password"]):
            return 8.0
            
        # Standard web & application traffic (3 - 5 years)
        if any(k in combined for k in ["tls", "https", "ssl", "nginx", "apache", "ingress", "gateway", "service"]):
            return 5.0
            
        # Ephemeral / Dev (0.5 - 2 years)
        if any(k in combined for k in ["test", "demo", "mock", "temp", "scratch", "cache"]):
            return 1.0
            
        return 7.0

    def evaluate_primitive_vulnerability(self, algorithm: str, key_size: int = None) -> Tuple[float, bool, bool, str]:
        """
        Returns (base_vulnerability_score, is_shor_vulnerable, is_grover_vulnerable, description)
        """
        algo = algorithm.upper().strip()
        
        # 1. NIST Post-Quantum Standards (Safe)
        pqc_standards = ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "SLH-DSA", "SPHINCS+", "FALCON", "LMS", "XMSS"]
        if any(pqc in algo for pqc in pqc_standards):
            return 0.0, False, False, "NIST Post-Quantum Cryptography Standard (Quantum-Resistant)"
            
        # 2. Hybrid Post-Quantum (Safe / Compliant)
        if "HYBRID" in algo or ("X25519" in algo and "KYBER" in algo) or "PQC" in algo:
            return 2.0, False, False, "Composite Classical-Quantum Hybrid Primitive"
            
        # 3. Asymmetric Primitives (Shor's Algorithm - Complete Break)
        if "RSA" in algo:
            if key_size and key_size < 2048:
                return 100.0, True, False, f"Legacy RSA-{key_size} (Shor's polynomial time break + classical weakness)"
            elif key_size and key_size >= 4096:
                return 90.0, True, False, f"RSA-{key_size} (Shor's algorithm breaks in polynomial time O(n^3))"
            else:
                return 95.0, True, False, "RSA-2048 (Shor's algorithm breaks in polynomial time O(n^3))"
                
        if any(ec in algo for ec in ["ECDSA", "ECDH", "EC_", "CURVE25519", "X25519", "ED25519", "SECP256", "PRIME256"]):
            return 95.0, True, False, "Elliptic Curve Cryptography (Broken by Shor's discrete logarithm attack)"
            
        if any(dh in algo for dh in ["DIFFIE-HELLMAN", "DH", "DHE", "DSA"]):
            return 98.0, True, False, "Discrete Logarithm / Diffie-Hellman (Broken by Shor's algorithm)"

        # 4. Classical Broken Legacy
        if any(legacy in algo for legacy in ["DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1"]):
            return 100.0, True, True, "Deprecated Legacy Algorithm (Classically broken & quantum vulnerable)"

        # 5. Symmetric Ciphers (Grover's Algorithm quadratic speedup)
        if "AES" in algo or "CHACHA" in algo:
            if key_size == 128 or "128" in algo:
                return 48.0, False, True, "AES-128 (Grover's algorithm reduces effective security from 128 to 64 bits)"
            elif key_size == 192 or "192" in algo:
                return 20.0, False, True, "AES-192 (Grover's algorithm reduces effective security to 96 bits)"
            elif key_size == 256 or "256" in algo:
                return 5.0, False, False, "AES-256 (Grover-resistant: retains 128 bits of post-quantum security)"
            else:
                return 35.0, False, True, "Symmetric cipher with indeterminate key length"

        # 6. Hashes
        if any(h in algo for h in ["SHA256", "SHA-256", "SHA3-256"]):
            return 10.0, False, False, "Collision resistant; minimal quantum threat"
        if any(h in algo for h in ["SHA384", "SHA-384", "SHA512", "SHA-512"]):
            return 2.0, False, False, "Grover-resistant secure hash"

        return 50.0, False, False, "Unclassified cryptographic primitive"

    def assess_asset(self, asset: CryptoAsset) -> Tuple[VulnerabilityRecord, str]:
        """Score an asset using a documented, explainable multi-factor model.

        Q-Score is a prioritization score (0-100), not a probability of compromise.
        Sensitivity and confidentiality lifetime are heuristic defaults and must be
        validated by the asset owner. The cryptographic weakness factor gates the
        score so a recognized PQC primitive is not flagged as quantum-vulnerable
        merely because it is public-facing or handles sensitive data.
        """
        if not asset.data_shelf_life_years or asset.data_shelf_life_years <= 0:
            asset.data_shelf_life_years = self.infer_shelf_life(asset.name, asset.location, asset.purpose)

        X = float(asset.data_shelf_life_years)
        Y = float(self.default_migration_years)
        Z = self.z_horizon
        mosca_gap = round((X + Y) - Z, 2)
        time_to_compromise = round(Z, 1)
        base_v, shor_vuln, grover_vuln, reason = self.evaluate_primitive_vulnerability(asset.algorithm, asset.key_size)

        # Factor scores are normalized to 0-100 and have explicit documented weights.
        exposure_scores = {
            ExposureLevel.PUBLIC_INTERNET.value: 100.0,
            ExposureLevel.INTERNAL_NETWORK.value: 65.0,
            ExposureLevel.AT_REST_STORAGE.value: 55.0,
            ExposureLevel.LOCAL_DEV.value: 20.0,
        }
        exposure_score = exposure_scores.get(asset.exposure_level, 50.0)
        context = f"{asset.name} {asset.location} {asset.purpose} {asset.asset_type}".lower()
        if any(k in context for k in ("medical", "health", "patient", "phi", "biometric", "genomic", "classified", "national_security")):
            sensitivity, sensitivity_label = 100.0, "Very high"
        elif any(k in context for k in ("bank", "payment", "credit", "tax", "payroll", "identity", "ssn", "financial", "legal")):
            sensitivity, sensitivity_label = 85.0, "High"
        elif any(k in context for k in ("password", "secret", "token", "credential", "private_key", "root_ca", "master_key", "api_key", "auth")):
            sensitivity, sensitivity_label = 75.0, "High"
        elif any(k in context for k in ("demo", "mock", "test", "sample", "scratch", "temp")):
            sensitivity, sensitivity_label = 20.0, "Low (sample/test heuristic)"
        else:
            sensitivity, sensitivity_label = 55.0, "Moderate (default assumption)"

        # Long-lived data increases HNDL impact; 30 years is the model's normalization cap.
        lifetime_score = min(100.0, max(0.0, (X / 30.0) * 100.0))
        if mosca_gap > 0:
            mosca_score = min(100.0, 60.0 + (mosca_gap * 4.0))
        else:
            mosca_score = max(0.0, 50.0 + (mosca_gap * 5.0))

        factors = {
            "cryptographic_weakness": {"label": "Cryptographic weakness", "score": round(base_v, 1), "weight_pct": 35, "source": "Algorithm/key-size classification", "observed_or_assumed": "observed"},
            "exposure": {"label": "Exposure", "score": round(exposure_score, 1), "weight_pct": 20, "source": f"Asset exposure: {asset.exposure_level}", "observed_or_assumed": "scanner classification"},
            "data_sensitivity": {"label": "Data sensitivity", "score": round(sensitivity, 1), "weight_pct": 20, "source": sensitivity_label, "observed_or_assumed": "heuristic assumption; validate with owner"},
            "confidentiality_lifetime": {"label": "Confidentiality lifetime", "score": round(lifetime_score, 1), "weight_pct": 10, "source": f"X = {X:g} years", "observed_or_assumed": "configured or inferred; validate with owner"},
            "mosca_planning_gap": {"label": "Mosca planning gap", "score": round(mosca_score, 1), "weight_pct": 15, "source": f"X + Y - Z = {mosca_gap:+g} years (Y={Y:g}, Z={Z:g})", "observed_or_assumed": "scenario calculation"},
        }
        weighted = sum(v["score"] * v["weight_pct"] / 100.0 for v in factors.values())
        q_score = 0.0 if base_v == 0.0 else round(min(100.0, max(0.0, weighted)), 1)
        for factor in factors.values():
            # A recognized PQC/hybrid primitive gates quantum-vulnerability contributions to zero.
            factor["weighted_points"] = 0.0 if base_v == 0.0 else round(factor["score"] * factor["weight_pct"] / 100.0, 1)

        if base_v == 0.0:
            severity = RiskTier.QUANTUM_SAFE.value
            urgency_tier = "Quantum-resistant primitive detected; validate implementation and inventory completeness"
        elif q_score >= 80.0:
            severity, urgency_tier = RiskTier.CRITICAL.value, "Priority 1 — validate immediately and plan migration"
        elif q_score >= 65.0:
            severity, urgency_tier = RiskTier.HIGH.value, "Priority 2 — migration planning should start soon"
        elif q_score >= 40.0:
            severity, urgency_tier = RiskTier.MEDIUM.value, "Priority 3 — assess dependencies and plan remediation"
        else:
            severity, urgency_tier = RiskTier.LOW.value, "Priority 4 — validate context and track in roadmap"

        if mosca_gap > 0:
            mosca_text = f"Planning gap: X + Y > Z by {mosca_gap:g} years; prioritize long-lived data and migration dependencies."
        else:
            mosca_text = f"Planning buffer: X + Y is within Z by {abs(mosca_gap):g} years under the selected scenario."
        explanation = (
            f"{reason}. Q-Score {q_score}/100 is a weighted prioritization score, not a breach probability. "
            f"Weights: cryptographic weakness 35%, exposure 20%, data sensitivity 20%, confidentiality lifetime 10%, "
            f"Mosca planning gap 15%. {mosca_text} Data sensitivity and lifetime may be heuristic assumptions; validate them with the asset owner."
            + (" Recognized PQC/hybrid primitive gate applied: contextual factors alone do not create a quantum-cryptographic risk score." if base_v == 0.0 else "")
        )
        vuln_record = VulnerabilityRecord(
            asset_id=asset.id, scan_id=asset.scan_id, q_score=q_score, severity=severity,
            shor_vulnerable=shor_vuln, grover_vulnerable=grover_vuln,
            mosca_gap_years=mosca_gap, time_to_compromise_years=time_to_compromise,
            urgency_tier=urgency_tier, explanation=explanation, risk_factors=factors
        )
        return vuln_record, explanation
