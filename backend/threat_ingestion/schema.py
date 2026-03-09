"""
Threat Intelligence Datasets Schema
Local AI-Powered Security Operations Center
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """CVSS severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CVEMetric(BaseModel):
    """CVE vulnerability record."""
    id: str
    cve_id: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    cvss_vector: Optional[str] = None
    published_date: datetime
    last_modified: datetime
    affected_products: List[str] = []
    affected_vendors: List[str] = []
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    exploit_available: bool = False
    exploit_maturity: Optional[str] = None  # EPOC, POC, Functional, High
    patch_available: bool = False
    patch_url: Optional[str] = None
    references: List[str] = []
    mitre_attack_ids: List[str] = []  # TTP IDs
    threat_actors: List[str] = []
    malware_families: List[str] = []
    cwe_ids: List[str] = []  # Common Weakness Enumeration
    epss_score: Optional[float] = None  # Exploit Prediction Scoring System
    keV_listed: bool = False  # CISA Known Exploited Vulnerabilities
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ZeroDayAlert(BaseModel):
    """Zero-day vulnerability alert."""
    id: str
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: SeverityLevel
    risk_score: float  # 0-100
    discovered_date: datetime
    affected_products: List[str] = []
    affected_vendors: List[str] = []
    exploit_available: bool = False
    exploit_type: Optional[str] = None  # RCE, LPE, XSS, etc.
    patch_available: bool = False
    active_exploitation: bool = False
    attack_campaigns: List[str] = []
    threat_actors: List[str] = []
    iocs: List[Dict[str, str]] = []  # Indicators of Compromise
    mitigation: Optional[str] = None
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ThreatActor(BaseModel):
    """Threat actor profile."""
    id: str
    name: str
    aliases: List[str] = []
    type: str  # Nation-state, Cybercriminal, Hacktivist, Insider, APT
    origin_country: Optional[str] = None
    sophistication: str  # Low, Medium, High, Advanced
    motivation: List[str] = []  # Espionage, Financial, Disruption, etc.
    targets_industries: List[str] = []
    targets_countries: List[str] = []
    targets_regions: List[str] = []
    ttps: List[str] = []  # MITRE ATT&CK Technique IDs
    malware_used: List[str] = []
    exploits_used: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: str
    associated_groups: List[str] = []
    recent_campaigns: List[Dict[str, Any]] = []
    iocs: List[Dict[str, str]] = []
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MalwareFamily(BaseModel):
    """Malware family profile."""
    id: str
    name: str
    aliases: List[str] = []
    type: str  # Ransomware, Trojan, Worm, Rootkit, Spyware, etc.
    family: Optional[str] = None
    description: str
    capabilities: List[str] = []  # Encryption, C2, Persistence, etc.
    platforms: List[str] = []  # Windows, Linux, macOS, Android, iOS
    delivery_methods: List[str] = []  # Phishing, Drive-by, USB, etc.
    c2_protocols: List[str] = []  # HTTP, HTTPS, DNS, Tor, etc.
    associated_threat_actors: List[str] = []
    exploits_used: List[str] = []
    hashes: List[Dict[str, str]] = []  # MD5, SHA1, SHA256
    yara_rules: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    prevalence: str  # Low, Medium, High
    impact: str  # Low, Medium, High, Critical
    mitigation: Optional[str] = None
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class IOCRecord(BaseModel):
    """Indicator of Compromise record."""
    id: str
    ioc_type: str  # ip, domain, hash, url, email, file_path, registry_key
    value: str
    ioc_category: str  # Malware, Phishing, C2, Exfiltration, etc.
    severity: SeverityLevel
    confidence: str  # Low, Medium, High
    source: str
    description: str
    associated_malware: List[str] = []
    associated_threat_actors: List[str] = []
    associated_campaigns: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expiration: Optional[datetime] = None  # When IOC becomes stale
    false_positive_rate: float = 0.0  # 0-1
    tags: List[str] = []
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AttackPattern(BaseModel):
    """MITRE ATT&CK attack pattern."""
    id: str
    mitre_id: str  # Txxxx.xxx
    name: str
    description: str
    tactic: str
    technique: Optional[str] = None
    sub_technique: Optional[str] = None
    platforms: List[str] = []
    permissions_required: List[str] = []
    data_sources: List[str] = []
    detection: Optional[str] = None
    mitigation: Optional[str] = None
    procedure_examples: List[str] = []
    associated_threat_actors: List[str] = []
    associated_malware: List[str] = []
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecurityAdvisory(BaseModel):
    """Security advisory record."""
    id: str
    title: str
    source: str  # Vendor, CERT, CISA, etc.
    advisory_id: Optional[str] = None
    published_date: datetime
    severity: SeverityLevel
    description: str
    affected_products: List[str] = []
    affected_vendors: List[str] = []
    cve_ids: List[str] = []
    vulnerability_type: Optional[str] = None
    impact: Optional[str] = None
    recommended_actions: List[str] = []
    workarounds: List[str] = []
    patch_available: bool = False
    patch_url: Optional[str] = None
    exploit_available: bool = False
    references: List[str] = []
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ThreatIntelligenceSummary(BaseModel):
    """Summary of threat intelligence data."""
    total_cves: int
    critical_cves: int
    high_cves: int
    total_zero_days: int
    active_zero_days: int
    total_threat_actors: int
    active_threat_actors: int
    total_malware_families: int
    total_iocs: int
    total_advisories: int
    last_updated: datetime
    top_threat_actors: List[Dict[str, Any]] = []
    recent_critical_cves: List[Dict[str, Any]] = []
    active_campaigns: List[Dict[str, Any]] = []


# Schema version for dataset validation
SCHEMA_VERSION = "1.0.0"
