"""
CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) Exporter.
Produces standard-compliant JSON for enterprise DevSecOps pipelines.
"""
import uuid
import json
from datetime import datetime
from typing import List, Dict, Any

class CycloneDXExporter:
    @staticmethod
    def export_cbom(scan_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Transforms scan findings into official CycloneDX 1.6 CBOM schema format.
        """
        bom_uuid = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        components = []
        vulnerabilities = []

        for f in findings:
            comp_ref = f"urn:quantumguard:asset:{f.get('asset_id')}"
            algo = f.get("algorithm", "UNKNOWN")
            shor = f.get("shor_vulnerable", False)
            grover = f.get("grover_vulnerable", False)

            # Determine primitive category
            primitive_cat = "asymmetric"
            if "AES" in algo or "3DES" in algo or "DES" in algo:
                primitive_cat = "symmetric"
            elif "SHA" in algo or "MD5" in algo:
                primitive_cat = "hash"
            elif "ML-KEM" in algo or "KYBER" in algo:
                primitive_cat = "post-quantum-kem"
            elif "ML-DSA" in algo or "DILITHIUM" in algo:
                primitive_cat = "post-quantum-signature"

            comp = {
                "type": "cryptographic-asset",
                "bom-ref": comp_ref,
                "name": f.get("asset_name"),
                "version": "1.0",
                "description": f"Cryptographic primitive detected at {f.get('location')}",
                "cryptoProperties": {
                    "assetType": "algorithm" if f.get("asset_type") == "SOURCE_CODE" else "certificate",
                    "algorithmProperties": {
                        "name": algo,
                        "keyLength": f.get("key_size"),
                        "curve": f.get("curve_name"),
                        "primitive": primitive_cat,
                        "executionEnvironment": f.get("exposure_level")
                    },
                    "oid": f.get("signature_algorithm")
                },
                "properties": [
                    {"name": "q_score", "value": str(f.get("q_score"))},
                    {"name": "mosca_gap_years", "value": str(f.get("mosca_gap_years"))},
                    {"name": "shor_vulnerable", "value": str(shor)},
                    {"name": "grover_vulnerable", "value": str(grover)},
                    {"name": "nist_pqc_replacement", "value": f.get("nist_standard_replacement")},
                    {"name": "hybrid_replacement", "value": f.get("hybrid_replacement")},
                    {"name": "standard_reference", "value": f.get("standard_reference")}
                ]
            }
            components.append(comp)

            # Add CycloneDX vulnerability if vulnerable
            if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                vuln = {
                    "bom-ref": f"vuln-{f.get('asset_id')}",
                    "id": f"Q-EXPOSURE-{f.get('asset_id')}",
                    "source": {
                        "name": "QuantumGuard Q-Score Engine",
                        "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
                    },
                    "ratings": [
                        {
                            "severity": f.get("severity").lower(),
                            "score": f.get("q_score") / 10.0,
                            "method": "other"
                        }
                    ],
                    "description": f.get("explanation"),
                    "recommendation": f"Migrate to {f.get('nist_standard_replacement')} ({f.get('standard_reference')})",
                    "affects": [
                        {"ref": comp_ref}
                    ]
                }
                vulnerabilities.append(vuln)

        cbom_doc = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{bom_uuid}",
            "version": 1,
            "metadata": {
                "timestamp": now,
                "tools": [
                    {
                        "vendor": "QuantumGuard",
                        "name": "QuantumGuard CBOM & Mosca Scanner",
                        "version": "2.4.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": scan_info.get("name", "Enterprise Security Audit"),
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": vulnerabilities
        }

        return cbom_doc
