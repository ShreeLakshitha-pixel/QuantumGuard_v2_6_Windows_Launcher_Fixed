"""
Data models and dataclasses for QuantumGuard.
"""
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class AssetType(str, Enum):
    CERTIFICATE = "CERTIFICATE"
    PRIVATE_KEY = "PRIVATE_KEY"
    PUBLIC_KEY = "PUBLIC_KEY"
    TLS_ENDPOINT = "TLS_ENDPOINT"
    SOURCE_CODE = "SOURCE_CODE"
    CONFIG_FILE = "CONFIG_FILE"

class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"         # HNDL Zone: Mosca gap > 0, immediate harvest danger
    HIGH = "HIGH"                 # Shor-broken, medium shelf-life
    MEDIUM = "MEDIUM"             # Grover-impacted (e.g. AES-128) or internal asymmetric
    LOW = "LOW"                   # Low exposure or short shelf-life
    QUANTUM_SAFE = "QUANTUM_SAFE" # NIST PQC or Grover-resistant (AES-256)

class ExposureLevel(str, Enum):
    PUBLIC_INTERNET = "PUBLIC_INTERNET"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    AT_REST_STORAGE = "AT_REST_STORAGE"
    LOCAL_DEV = "LOCAL_DEV"

@dataclass
class CryptoAsset:
    id: Optional[int] = None
    scan_id: Optional[int] = None
    name: str = ""
    asset_type: str = AssetType.SOURCE_CODE.value
    location: str = ""
    line_number: Optional[int] = None
    algorithm: str = ""
    key_size: Optional[int] = None
    curve_name: Optional[str] = None
    signature_algorithm: Optional[str] = None
    purpose: str = "Encryption / Authentication"
    exposure_level: str = ExposureLevel.INTERNAL_NETWORK.value
    data_shelf_life_years: float = 10.0
    code_snippet: Optional[str] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VulnerabilityRecord:
    id: Optional[int] = None
    asset_id: Optional[int] = None
    scan_id: Optional[int] = None
    q_score: float = 0.0
    severity: str = RiskTier.MEDIUM.value
    shor_vulnerable: bool = False
    grover_vulnerable: bool = False
    mosca_gap_years: float = 0.0
    time_to_compromise_years: float = 0.0
    urgency_tier: str = "Phase 2"
    explanation: str = ""
    risk_factors: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MigrationRecommendation:
    id: Optional[int] = None
    asset_id: Optional[int] = None
    scan_id: Optional[int] = None
    current_primitive: str = ""
    nist_standard_replacement: str = ""
    hybrid_replacement: str = ""
    standard_reference: str = ""
    code_diff_title: str = ""
    current_code_snippet: str = ""
    migrated_code_snippet: str = ""
    configuration_recipe: str = ""
    migration_effort: str = "MEDIUM"

@dataclass
class ScanRecord:
    id: Optional[int] = None
    name: str = ""
    target_type: str = "local_directory"
    target_path: str = ""
    status: str = "PENDING"
    started_at: str = ""
    completed_at: Optional[str] = None
    total_assets: int = 0
    hndl_critical_count: int = 0
    avg_q_score: float = 0.0
    raw_summary: Dict[str, Any] = field(default_factory=dict)
