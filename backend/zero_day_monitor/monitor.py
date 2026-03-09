"""
Zero-Day Threat Intelligence Monitor
Local AI-Powered Security Operations Center

Monitors for zero-day vulnerabilities, newly disclosed exploits, and emerging threats.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
from enum import Enum
import structlog

from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class ExploitMaturity(str, Enum):
    """Exploit maturity levels."""
    UNPROVEN = "unproven"
    PROOF_OF_CONCEPT = "proof_of_concept"
    FUNCTIONAL = "functional"
    HIGH = "high"
    ACTIVE_EXPLOITATION = "active_exploitation"


class ZeroDayAlert:
    """Zero-day vulnerability alert."""
    
    def __init__(
        self,
        alert_id: str,
        cve_id: Optional[str],
        title: str,
        description: str,
        severity: str,
        risk_score: float,
        affected_products: List[str],
        exploit_available: bool,
        exploit_maturity: Optional[ExploitMaturity] = None,
        active_exploitation: bool = False,
        patch_available: bool = False,
        threat_actors: Optional[List[str]] = None,
        iocs: Optional[List[Dict[str, str]]] = None,
        mitigation: Optional[str] = None,
        references: Optional[List[str]] = None,
    ):
        self.alert_id = alert_id
        self.cve_id = cve_id
        self.title = title
        self.description = description
        self.severity = severity
        self.risk_score = risk_score
        self.affected_products = affected_products
        self.exploit_available = exploit_available
        self.exploit_maturity = exploit_maturity
        self.active_exploitation = active_exploitation
        self.patch_available = patch_available
        self.threat_actors = threat_actors or []
        self.iocs = iocs or []
        self.mitigation = mitigation
        self.references = references or []
        self.created_at = datetime.utcnow().isoformat() + "Z"
        self.status = "new"  # new, investigating, mitigated, resolved
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "affected_products": self.affected_products,
            "exploit_available": self.exploit_available,
            "exploit_maturity": self.exploit_maturity.value if self.exploit_maturity else None,
            "active_exploitation": self.active_exploitation,
            "patch_available": self.patch_available,
            "threat_actors": self.threat_actors,
            "iocs": self.iocs,
            "mitigation": self.mitigation,
            "references": self.references,
            "created_at": self.created_at,
            "status": self.status,
        }


class ZeroDayMonitor:
    """Monitor for zero-day and emerging threats."""
    
    def __init__(self, data_dir: str = "./data/zero_day"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Active zero-day alerts
        self.alerts: Dict[str, ZeroDayAlert] = {}
        
        # Local software inventory
        self.software_inventory: List[Dict[str, Any]] = []
        
        # Known exploited vulnerabilities (CISA KEV)
        self.known_exploited: Dict[str, Dict[str, Any]] = {}
        
        # Vulnerability database
        self.vuln_database: Dict[str, Dict[str, Any]] = {}
        
        # Load data
        self._load_known_exploited()
        
        logger.info("ZeroDayMonitor initialized")
    
    def _load_known_exploited(self):
        """Load CISA Known Exploited Vulnerabilities."""
        kev_file = self.data_dir.parent / "threat_intel" / "cisa_kev.json"
        
        if kev_file.exists():
            try:
                with open(kev_file, 'r') as f:
                    data = json.load(f)
                    for vuln in data.get('vulnerabilities', []):
                        self.known_exploited[vuln.get('cveID', '')] = vuln
                
                logger.info(f"Loaded {len(self.known_exploited)} CISA KEV entries")
            except Exception as e:
                logger.error(f"Failed to load CISA KEV: {str(e)}")
    
    def calculate_risk_score(
        self,
        cvss_score: float,
        exploit_available: bool,
        active_exploitation: bool,
        patch_available: bool,
        affected_locally: bool,
    ) -> float:
        """
        Calculate zero-day risk score (0-100).
        
        Risk = Base × Exploit × Activity × Patch × Local
        """
        # Base score from CVSS (0-40 points)
        base_score = min(40, cvss_score * 4)
        
        # Exploit multiplier (0-25 points)
        exploit_score = 0
        if exploit_available:
            exploit_score = 25
            if active_exploitation:
                exploit_score = 35
        
        # Patch factor (reduces risk)
        patch_factor = 0.3 if patch_available else 1.0
        
        # Local impact (0-25 points)
        local_score = 25 if affected_locally else 5
        
        # Calculate final score
        risk_score = (base_score + exploit_score + local_score) * patch_factor
        
        return min(100, risk_score)
    
    def create_zero_day_alert(
        self,
        cve_id: Optional[str],
        title: str,
        description: str,
        cvss_score: float,
        affected_products: List[str],
        exploit_available: bool = False,
        exploit_maturity: Optional[ExploitMaturity] = None,
        active_exploitation: bool = False,
        patch_available: bool = False,
        threat_actors: Optional[List[str]] = None,
        iocs: Optional[List[Dict[str, str]]] = None,
        mitigation: Optional[str] = None,
        references: Optional[List[str]] = None,
    ) -> ZeroDayAlert:
        """Create a zero-day alert."""
        # Check if affected locally
        affected_locally = self._check_local_impact(affected_products)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(
            cvss_score=cvss_score,
            exploit_available=exploit_available,
            active_exploitation=active_exploitation,
            patch_available=patch_available,
            affected_locally=affected_locally,
        )
        
        # Determine severity
        if risk_score >= 80:
            severity = "critical"
        elif risk_score >= 60:
            severity = "high"
        elif risk_score >= 40:
            severity = "medium"
        else:
            severity = "low"
        
        # Generate alert ID
        alert_id = f"zd_{hashlib.md5(f'{cve_id}{title}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12]}"
        
        alert = ZeroDayAlert(
            alert_id=alert_id,
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            risk_score=risk_score,
            affected_products=affected_products,
            exploit_available=exploit_available,
            exploit_maturity=exploit_maturity,
            active_exploitation=active_exploitation,
            patch_available=patch_available,
            threat_actors=threat_actors,
            iocs=iocs,
            mitigation=mitigation,
            references=references,
        )
        
        self.alerts[alert_id] = alert
        
        # Log the alert
        log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type="ZERO_DAY_ALERT",
            module="zero_day_monitor",
            message=f"Zero-day alert created: {title}",
            severity=SeverityLevel.CRITICAL if severity == "critical" else SeverityLevel.HIGH,
            metadata={
                "alert_id": alert_id,
                "cve_id": cve_id,
                "risk_score": risk_score,
                "active_exploitation": active_exploitation,
            },
        )
        
        logger.info(f"Created zero-day alert: {alert_id}")
        return alert
    
    def _check_local_impact(self, affected_products: List[str]) -> bool:
        """Check if affected products exist in local inventory."""
        if not self.software_inventory:
            return False
        
        for product in affected_products:
            product_lower = product.lower()
            for inventory_item in self.software_inventory:
                inventory_name = inventory_item.get('name', '').lower()
                inventory_version = inventory_item.get('version', '')
                
                if product_lower in inventory_name:
                    return True
        
        return False
    
    def update_software_inventory(self, inventory: List[Dict[str, Any]]):
        """
        Update local software inventory.
        
        Args:
            inventory: List of software with name, version, vendor
        """
        self.software_inventory = inventory
        logger.info(f"Updated software inventory: {len(inventory)} items")
    
    def process_new_cve(self, cve_data: Dict[str, Any]) -> Optional[ZeroDayAlert]:
        """
        Process a newly disclosed CVE for zero-day potential.
        
        Args:
            cve_data: CVE data with CVSS, description, etc.
            
        Returns:
            ZeroDayAlert if zero-day detected, None otherwise
        """
        cve_id = cve_data.get('cve_id', '')
        cvss_score = cve_data.get('cvss_score', 0)
        description = cve_data.get('description', '')
        affected_products = cve_data.get('affected_products', [])
        
        # Check if already in known exploited
        is_exploited = cve_id in self.known_exploited
        
        # Check for exploit availability indicators
        exploit_indicators = [
            'exploit', 'poc', 'proof of concept', 'weaponized',
            'active exploitation', 'in the wild', 'ransomware'
        ]
        
        exploit_available = any(
            indicator in description.lower() for indicator in exploit_indicators
        ) or is_exploited
        
        # Check for patch availability
        patch_available = cve_data.get('patch_available', False)
        
        # Only create alert for high-severity potential zero-days
        if cvss_score >= 7.0 or (exploit_available and cvss_score >= 5.0):
            alert = self.create_zero_day_alert(
                cve_id=cve_id,
                title=f"CVE-{cve_id} - Potential Zero-Day",
                description=description[:500],
                cvss_score=cvss_score,
                affected_products=affected_products,
                exploit_available=exploit_available,
                exploit_maturity=ExploitMaturity.ACTIVE_EXPLOITATION if is_exploited else None,
                active_exploitation=is_exploited,
                patch_available=patch_available,
                mitigation=cve_data.get('mitigation'),
                references=cve_data.get('references', []),
            )
            return alert
        
        return None
    
    def scan_for_zero_days(self, cve_feed: List[Dict[str, Any]]) -> List[ZeroDayAlert]:
        """
        Scan CVE feed for potential zero-days.
        
        Args:
            cve_feed: List of CVE data
            
        Returns:
            List of zero-day alerts created
        """
        alerts = []
        
        for cve_data in cve_feed:
            alert = self.process_new_cve(cve_data)
            if alert:
                alerts.append(alert)
        
        logger.info(f"Zero-day scan completed: {len(alerts)} alerts created")
        return alerts
    
    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get zero-day alerts."""
        alerts = list(self.alerts.values())
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        # Sort by risk score (highest first)
        alerts.sort(key=lambda x: x.risk_score, reverse=True)
        
        return [a.to_dict() for a in alerts[:limit]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get zero-day monitor statistics."""
        by_severity = {}
        by_status = {}
        
        for alert in self.alerts.values():
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            by_status[alert.status] = by_status.get(alert.status, 0) + 1
        
        active_exploitation = sum(
            1 for a in self.alerts.values() if a.active_exploitation
        )
        
        return {
            "total_alerts": len(self.alerts),
            "by_severity": by_severity,
            "by_status": by_status,
            "active_exploitation_count": active_exploitation,
            "known_exploited_tracked": len(self.known_exploited),
            "software_inventory_size": len(self.software_inventory),
        }
    
    def save_alerts(self):
        """Save alerts to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"zero_day_alerts_{timestamp}.json"
        
        alerts_data = [a.to_dict() for a in self.alerts.values()]
        
        with open(filename, 'w') as f:
            json.dump(alerts_data, f, indent=2)
        
        logger.info(f"Saved {len(alerts_data)} zero-day alerts to {filename}")


# Global zero-day monitor instance
zero_day_monitor = ZeroDayMonitor()
