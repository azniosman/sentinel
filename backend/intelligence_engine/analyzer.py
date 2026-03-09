"""
Intelligence Engine
Local AI-Powered Security Operations Center

Core intelligence capabilities for threat analysis and zero-day detection.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog
import asyncio

from config import settings
from threat_ingestion.schema import (
    CVEMetric,
    ZeroDayAlert,
    ThreatActor,
    MalwareFamily,
    SecurityAdvisory,
    SeverityLevel,
    ThreatIntelligenceSummary,
)

logger = structlog.get_logger()


class IntelligenceEngine:
    """Core intelligence engine for threat analysis."""
    
    def __init__(self):
        self.threat_intel_dir = Path(settings.THREAT_INTEL_DIR)
        self.cve_cache: List[CVEMetric] = []
        self.zero_day_cache: List[ZeroDayAlert] = []
        self.threat_actors_cache: List[ThreatActor] = []
        self.malware_cache: List[MalwareFamily] = []
        self.advisories_cache: List[SecurityAdvisory] = []
        self.mitre_attack_cache: Dict[str, Any] = {}
        
        logger.info("IntelligenceEngine initialized")
    
    async def load_datasets(self):
        """Load all threat intelligence datasets from disk."""
        logger.info("Loading threat intelligence datasets")
        
        try:
            # Load CVE database
            cve_file = self.threat_intel_dir / "cve_database.json"
            if cve_file.exists():
                with open(cve_file, "r") as f:
                    cve_data = json.load(f)
                    self.cve_cache = [
                        CVEMetric(**cve) if isinstance(cve, dict) else cve
                        for cve in cve_data
                    ]
                logger.info(f"Loaded {len(self.cve_cache)} CVEs")
            
            # Load zero-day alerts
            zero_day_file = self.threat_intel_dir / "zero_day_alerts.json"
            if zero_day_file.exists():
                with open(zero_day_file, "r") as f:
                    zero_day_data = json.load(f)
                    self.zero_day_cache = [
                        ZeroDayAlert(**zd) if isinstance(zd, dict) else zd
                        for zd in zero_day_data
                    ]
                logger.info(f"Loaded {len(self.zero_day_cache)} zero-day alerts")
            
            # Load threat actors
            threat_actor_file = self.threat_intel_dir / "threat_actors.json"
            if threat_actor_file.exists():
                with open(threat_actor_file, "r") as f:
                    ta_data = json.load(f)
                    self.threat_actors_cache = [
                        ThreatActor(**ta) if isinstance(ta, dict) else ta
                        for ta in ta_data
                    ]
                logger.info(f"Loaded {len(self.threat_actors_cache)} threat actors")
            
            # Load malware families
            malware_file = self.threat_intel_dir / "malware_families.json"
            if malware_file.exists():
                with open(malware_file, "r") as f:
                    mal_data = json.load(f)
                    self.malware_cache = [
                        MalwareFamily(**mal) if isinstance(mal, dict) else mal
                        for mal in mal_data
                    ]
                logger.info(f"Loaded {len(self.malware_cache)} malware families")
            
            # Load MITRE ATT&CK
            mitre_file = self.threat_intel_dir / "mitre_attack.json"
            if mitre_file.exists():
                with open(mitre_file, "r") as f:
                    self.mitre_attack_cache = json.load(f)
                logger.info("Loaded MITRE ATT&CK dataset")
            
            # Load security advisories
            advisories_file = self.threat_intel_dir / "security_advisories.json"
            if advisories_file.exists():
                with open(advisories_file, "r") as f:
                    adv_data = json.load(f)
                    self.advisories_cache = [
                        SecurityAdvisory(**adv) if isinstance(adv, dict) else adv
                        for adv in adv_data
                    ]
                logger.info(f"Loaded {len(self.advisories_cache)} advisories")
            
        except Exception as e:
            logger.error(f"Failed to load datasets: {str(e)}")
            raise
    
    def calculate_zero_day_risk_score(
        self,
        cvss_score: float,
        exploit_available: bool,
        patch_available: bool,
        active_exploitation: bool,
        epss_score: Optional[float] = None,
    ) -> float:
        """
        Calculate zero-day risk score.
        
        Risk Score = CVSS × Exploit Probability × Attack Activity × (1 - Patch Factor)
        
        Args:
            cvss_score: CVSS base score (0-10)
            exploit_available: Whether exploit is available
            patch_available: Whether patch is available
            active_exploitation: Whether active exploitation is detected
            epss_score: Optional EPSS score (0-1)
            
        Returns:
            Risk score (0-100)
        """
        # Base score from CVSS
        base_score = cvss_score * 10  # Convert to 0-100 scale
        
        # Exploit multiplier
        exploit_multiplier = 1.5 if exploit_available else 1.0
        
        # Patch factor (reduces risk if patch available)
        patch_factor = 0.5 if patch_available else 1.0
        
        # Active exploitation multiplier
        active_multiplier = 2.0 if active_exploitation else 1.0
        
        # EPSS adjustment (if available)
        epss_adjustment = 1.0 + (epss_score or 0.0)
        
        # Calculate final score
        risk_score = (
            base_score *
            exploit_multiplier *
            patch_factor *
            active_multiplier *
            epss_adjustment
        )
        
        # Cap at 100
        return min(100.0, risk_score)
    
    def detect_zero_day_vulnerabilities(self) -> List[ZeroDayAlert]:
        """
        Detect potential zero-day vulnerabilities from CVE database.
        
        Criteria:
        - High CVSS score (>= 7.0)
        - Exploit available
        - No patch available
        - Active exploitation or high EPSS score
        
        Returns:
            List of zero-day alerts
        """
        logger.info("Detecting zero-day vulnerabilities")
        
        zero_days = []
        
        for cve in self.cve_cache:
            # Check zero-day criteria
            is_high_severity = cve.cvss_score >= 7.0
            has_exploit = cve.exploit_available or cve.keV_listed
            no_patch = not cve.patch_available
            high_epss = (cve.epss_score or 0.0) > 0.5
            
            if is_high_severity and has_exploit and no_patch:
                # Calculate risk score
                risk_score = self.calculate_zero_day_risk_score(
                    cvss_score=cve.cvss_score,
                    exploit_available=has_exploit,
                    patch_available=cve.patch_available,
                    active_exploitation=cve.keV_listed,
                    epss_score=cve.epss_score,
                )
                
                # Create zero-day alert
                alert = ZeroDayAlert(
                    id=f"zd_{cve.id}",
                    cve_id=cve.cve_id,
                    title=f"Zero-Day: {cve.cve_id}",
                    description=cve.description,
                    severity=cve.severity,
                    risk_score=risk_score,
                    discovered_date=cve.published_date,
                    affected_products=cve.affected_products,
                    affected_vendors=cve.affected_vendors,
                    exploit_available=has_exploit,
                    exploit_type=cve.attack_vector,
                    patch_available=cve.patch_available,
                    active_exploitation=cve.keV_listed,
                    mitigation=cve.description,  # Would need better extraction
                    references=cve.references,
                )
                
                zero_days.append(alert)
        
        logger.info(f"Detected {len(zero_days)} potential zero-days")
        return zero_days
    
    def map_cve_to_mitre_attack(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Map CVE to MITRE ATT&CK techniques.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of MITRE ATT&CK technique mappings
        """
        # This would ideally use NVD's CPE-to-ATT&CK mapping
        # For now, return placeholder based on attack vector
        
        cve = next((c for c in self.cve_cache if c.cve_id == cve_id), None)
        
        if not cve:
            return []
        
        mappings = []
        
        # Simple heuristic mapping based on attack vector
        attack_vector = cve.attack_vector or ""
        
        if "NETWORK" in attack_vector.upper():
            mappings.append({
                "mitre_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            })
        
        if "LOCAL" in attack_vector.upper():
            mappings.append({
                "mitre_id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
            })
        
        if cve.user_interaction == "REQUIRED":
            mappings.append({
                "mitre_id": "T1203",
                "name": "Exploitation for Client Execution",
                "tactic": "Execution",
            })
        
        return mappings
    
    async def get_threat_summary(self) -> ThreatIntelligenceSummary:
        """
        Get summary of threat intelligence data.
        
        Returns:
            Threat intelligence summary
        """
        # Ensure datasets are loaded
        if not self.cve_cache:
            await self.load_datasets()
        
        # Calculate statistics
        critical_cves = [c for c in self.cve_cache if c.severity == SeverityLevel.CRITICAL]
        high_cves = [c for c in self.cve_cache if c.severity == SeverityLevel.HIGH]
        
        active_zero_days = [zd for zd in self.zero_day_cache if zd.active_exploitation]
        active_actors = [ta for ta in self.threat_actors_cache if ta.last_seen and 
                        (datetime.utcnow() - ta.last_seen).days < 90]
        
        # Get top threat actors
        top_actors = sorted(
            self.threat_actors_cache,
            key=lambda x: len(x.ttps),
            reverse=True,
        )[:10]
        
        # Get recent critical CVEs
        recent_critical = sorted(
            critical_cves,
            key=lambda x: x.published_date,
            reverse=True,
        )[:10]
        
        return ThreatIntelligenceSummary(
            total_cves=len(self.cve_cache),
            critical_cves=len(critical_cves),
            high_cves=len(high_cves),
            total_zero_days=len(self.zero_day_cache),
            active_zero_days=len(active_zero_days),
            total_threat_actors=len(self.threat_actors_cache),
            active_threat_actors=len(active_actors),
            total_malware_families=len(self.malware_cache),
            total_iocs=0,  # Would need IOC database
            total_advisories=len(self.advisories_cache),
            last_updated=datetime.utcnow(),
            top_threat_actors=[
                {"name": ta.name, "ttps": len(ta.ttps)}
                for ta in top_actors
            ],
            recent_critical_cves=[
                {
                    "cve_id": c.cve_id,
                    "cvss_score": c.cvss_score,
                    "description": c.description[:100],
                }
                for c in recent_critical
            ],
            active_campaigns=[],  # Would need campaign data
        )
    
    async def get_cves(
        self,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[CVEMetric]:
        """
        Get CVE database entries with optional filtering.
        
        Args:
            severity: Filter by severity level
            limit: Maximum number of results
            offset: Result offset for pagination
            
        Returns:
            List of CVE records
        """
        if not self.cve_cache:
            await self.load_datasets()
        
        # Filter by severity if specified
        cves = self.cve_cache
        if severity:
            severity_upper = severity.upper()
            cves = [c for c in cves if c.severity.value == severity_upper]
        
        # Apply pagination
        return cves[offset:offset + limit]
    
    async def get_zero_day_alerts(self) -> List[ZeroDayAlert]:
        """
        Get zero-day vulnerability alerts.
        
        Returns:
            List of zero-day alerts
        """
        if not self.zero_day_cache:
            self.zero_day_cache = self.detect_zero_day_vulnerabilities()
        
        return self.zero_day_cache
    
    async def get_threat_actors(self) -> List[ThreatActor]:
        """
        Get threat actor database.
        
        Returns:
            List of threat actors
        """
        if not self.threat_actors_cache:
            await self.load_datasets()
        
        return self.threat_actors_cache
    
    async def get_mitre_attack_data(self) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK framework data.
        
        Returns:
            MITRE ATT&CK data
        """
        if not self.mitre_attack_cache:
            await self.load_datasets()
        
        return self.mitre_attack_cache
    
    def correlate_threat_actor_activity(
        self,
        threat_actor_id: str,
    ) -> Dict[str, Any]:
        """
        Correlate threat actor activity across datasets.
        
        Args:
            threat_actor_id: Threat actor identifier
            
        Returns:
            Correlation data
        """
        actor = next(
            (ta for ta in self.threat_actors_cache if ta.id == threat_actor_id),
            None,
        )
        
        if not actor:
            return {"error": "Threat actor not found"}
        
        # Find associated malware
        associated_malware = [
            mal for mal in self.malware_cache
            if mal.name in actor.malware_used or any(
                alias in actor.malware_used for alias in mal.aliases
            )
        ]
        
        # Find associated CVEs (simplified)
        associated_cves = [
            cve for cve in self.cve_cache
            if any(
                actor.name.lower() in ref.lower()
                for ref in cve.references
            )
        ]
        
        return {
            "threat_actor": actor.dict(),
            "associated_malware": [mal.dict() for mal in associated_malware],
            "associated_cves": [cve.dict() for cve in associated_cves[:10]],
            "ttps": actor.ttps,
            "recent_campaigns": actor.recent_campaigns,
        }
    
    def detect_exploit_trends(self) -> Dict[str, Any]:
        """
        Detect trends in exploit activity.
        
        Returns:
            Exploit trend analysis
        """
        # Analyze CVEs with exploits
        exploitable_cves = [c for c in self.cve_cache if c.exploit_available]
        
        # Group by attack vector
        attack_vectors = {}
        for cve in exploitable_cves:
            vector = cve.attack_vector or "Unknown"
            if vector not in attack_vectors:
                attack_vectors[vector] = 0
            attack_vectors[vector] += 1
        
        # Group by vendor
        vendors = {}
        for cve in exploitable_cves:
            for vendor in cve.affected_vendors:
                if vendor not in vendors:
                    vendors[vendor] = 0
                vendors[vendor] += 1
        
        # Sort by frequency
        top_vectors = sorted(
            attack_vectors.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        
        top_vendors = sorted(
            vendors.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        
        return {
            "total_exploitable_cves": len(exploitable_cves),
            "top_attack_vectors": [
                {"vector": v[0], "count": v[1]}
                for v in top_vectors
            ],
            "most_targeted_vendors": [
                {"vendor": v[0], "count": v[1]}
                for v in top_vendors
            ],
            "kev_listed_count": sum(1 for c in exploitable_cves if c.keV_listed),
        }
