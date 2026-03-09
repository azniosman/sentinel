"""
Security Risk Scoring Engine
Local AI-Powered Security Operations Center

Calculates dynamic risk scores for hosts, users, and services.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
import structlog

logger = structlog.get_logger()


class RiskScorer:
    """Calculate security risk scores."""
    
    def __init__(self, data_dir: str = "./data/risk_scores"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Risk scores by entity type
        self.host_scores: Dict[str, Dict[str, Any]] = {}
        self.user_scores: Dict[str, Dict[str, Any]] = {}
        self.service_scores: Dict[str, Dict[str, Any]] = {}
        
        # Risk factors
        self.risk_factors = {
            "vulnerability": {
                "critical": 40,
                "high": 25,
                "medium": 10,
                "low": 5,
            },
            "suspicious_activity": {
                "critical": 35,
                "high": 20,
                "medium": 10,
                "low": 5,
            },
            "exposure": {
                "public_facing": 25,
                "internet_accessible": 20,
                "dmz": 15,
                "internal": 5,
            },
            "compliance": {
                "non_compliant": 20,
                "partially_compliant": 10,
                "compliant": 0,
            },
        }
        
        logger.info("RiskScorer initialized")
    
    def calculate_host_risk(
        self,
        hostname: str,
        vulnerabilities: List[Dict[str, Any]],
        suspicious_events: List[Dict[str, Any]],
        exposure_level: str = "internal",
        compliance_status: str = "compliant",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate risk score for a host.
        
        Args:
            hostname: Host identifier
            vulnerabilities: List of vulnerabilities affecting host
            suspicious_events: List of suspicious events on host
            exposure_level: Host exposure (public_facing, internet_accessible, dmz, internal)
            compliance_status: Compliance status
            metadata: Additional metadata
            
        Returns:
            Risk score details
        """
        # Vulnerability risk (0-40 points)
        vuln_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            vuln_score += self.risk_factors["vulnerability"].get(severity, 0)
        vuln_score = min(40, vuln_score)
        
        # Suspicious activity risk (0-35 points)
        activity_score = 0
        for event in suspicious_events:
            severity = event.get('severity', 'low').lower()
            activity_score += self.risk_factors["suspicious_activity"].get(severity, 0)
        activity_score = min(35, activity_score)
        
        # Exposure risk (0-25 points)
        exposure_score = self.risk_factors["exposure"].get(exposure_level, 5)
        
        # Compliance risk (0-20 points)
        compliance_score = self.risk_factors["compliance"].get(compliance_status, 0)
        
        # Total risk score (0-100)
        total_score = vuln_score + activity_score + exposure_score + compliance_score
        total_score = min(100, total_score)
        
        # Determine risk level
        if total_score >= 80:
            risk_level = "critical"
        elif total_score >= 60:
            risk_level = "high"
        elif total_score >= 40:
            risk_level = "medium"
        elif total_score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        # Build risk details
        risk_details = {
            "hostname": hostname,
            "total_score": total_score,
            "risk_level": risk_level,
            "vulnerability_score": vuln_score,
            "activity_score": activity_score,
            "exposure_score": exposure_score,
            "compliance_score": compliance_score,
            "vulnerability_count": len(vulnerabilities),
            "suspicious_event_count": len(suspicious_events),
            "exposure_level": exposure_level,
            "compliance_status": compliance_status,
            "calculated_at": datetime.utcnow().isoformat() + "Z",
            "metadata": metadata or {},
        }
        
        self.host_scores[hostname] = risk_details
        
        return risk_details
    
    def calculate_user_risk(
        self,
        username: str,
        failed_logins: int,
        privilege_escalations: int,
        suspicious_commands: int,
        account_age_days: int,
        is_admin: bool,
    ) -> Dict[str, Any]:
        """
        Calculate risk score for a user.
        
        Args:
            username: User identifier
            failed_logins: Number of failed login attempts
            privilege_escalations: Number of privilege escalation events
            suspicious_commands: Number of suspicious command executions
            account_age_days: Age of account in days
            is_admin: Whether user has admin privileges
            
        Returns:
            Risk score details
        """
        # Base score
        score = 0
        
        # Failed logins (0-25 points)
        if failed_logins > 20:
            score += 25
        elif failed_logins > 10:
            score += 15
        elif failed_logins > 5:
            score += 10
        elif failed_logins > 0:
            score += 5
        
        # Privilege escalations (0-30 points)
        if privilege_escalations > 5:
            score += 30
        elif privilege_escalations > 2:
            score += 20
        elif privilege_escalations > 0:
            score += 10
        
        # Suspicious commands (0-25 points)
        if suspicious_commands > 10:
            score += 25
        elif suspicious_commands > 5:
            score += 15
        elif suspicious_commands > 0:
            score += 10
        
        # Admin privilege modifier
        if is_admin:
            score = min(100, score * 1.2)
        
        # New account modifier
        if account_age_days < 7:
            score = min(100, score * 1.1)
        
        # Determine risk level
        score = min(100, score)
        
        if score >= 80:
            risk_level = "critical"
        elif score >= 60:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        risk_details = {
            "username": username,
            "total_score": score,
            "risk_level": risk_level,
            "failed_logins": failed_logins,
            "privilege_escalations": privilege_escalations,
            "suspicious_commands": suspicious_commands,
            "account_age_days": account_age_days,
            "is_admin": is_admin,
            "calculated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        self.user_scores[username] = risk_details
        
        return risk_details
    
    def calculate_service_risk(
        self,
        service_name: str,
        vulnerabilities: List[Dict[str, Any]],
        is_internet_facing: bool,
        has_known_exploits: bool,
        patch_status: str,
    ) -> Dict[str, Any]:
        """
        Calculate risk score for a service.
        
        Args:
            service_name: Service identifier
            vulnerabilities: List of vulnerabilities
            is_internet_facing: Whether service is internet-facing
            has_known_exploits: Whether exploits are known
            patch_status: Patch status (patched, unpatched, unknown)
            
        Returns:
            Risk score details
        """
        # Base score
        score = 0
        
        # Vulnerability score (0-40 points)
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                score += 15
            elif severity == 'high':
                score += 10
            elif severity == 'medium':
                score += 5
        score = min(40, score)
        
        # Internet facing (0-25 points)
        if is_internet_facing:
            score += 25
        
        # Known exploits (0-20 points)
        if has_known_exploits:
            score += 20
        
        # Patch status (0-15 points)
        if patch_status == 'unpatched':
            score += 15
        elif patch_status == 'unknown':
            score += 10
        
        # Total score
        score = min(100, score)
        
        # Risk level
        if score >= 80:
            risk_level = "critical"
        elif score >= 60:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        risk_details = {
            "service_name": service_name,
            "total_score": score,
            "risk_level": risk_level,
            "vulnerability_count": len(vulnerabilities),
            "is_internet_facing": is_internet_facing,
            "has_known_exploits": has_known_exploits,
            "patch_status": patch_status,
            "calculated_at": datetime.utcnow().isoformat() + "Z",
        }
        
        self.service_scores[service_name] = risk_details
        
        return risk_details
    
    def get_high_risk_hosts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get highest risk hosts."""
        hosts = sorted(
            self.host_scores.values(),
            key=lambda x: x['total_score'],
            reverse=True,
        )
        return hosts[:limit]
    
    def get_high_risk_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get highest risk users."""
        users = sorted(
            self.user_scores.values(),
            key=lambda x: x['total_score'],
            reverse=True,
        )
        return users[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get risk scoring statistics."""
        # Host risk distribution
        host_risk_levels = {}
        for host in self.host_scores.values():
            level = host['risk_level']
            host_risk_levels[level] = host_risk_levels.get(level, 0) + 1
        
        # User risk distribution
        user_risk_levels = {}
        for user in self.user_scores.values():
            level = user['risk_level']
            user_risk_levels[level] = user_risk_levels.get(level, 0) + 1
        
        # Average scores
        avg_host_score = 0
        if self.host_scores:
            avg_host_score = sum(h['total_score'] for h in self.host_scores.values()) / len(self.host_scores)
        
        avg_user_score = 0
        if self.user_scores:
            avg_user_score = sum(u['total_score'] for u in self.user_scores.values()) / len(self.user_scores)
        
        return {
            "hosts_scored": len(self.host_scores),
            "users_scored": len(self.user_scores),
            "services_scored": len(self.service_scores),
            "host_risk_distribution": host_risk_levels,
            "user_risk_distribution": user_risk_levels,
            "average_host_score": round(avg_host_score, 2),
            "average_user_score": round(avg_user_score, 2),
            "high_risk_hosts": len([h for h in self.host_scores.values() if h['risk_level'] in ['critical', 'high']]),
            "high_risk_users": len([u for u in self.user_scores.values() if u['risk_level'] in ['critical', 'high']]),
        }
    
    def save_scores(self):
        """Save risk scores to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"risk_scores_{timestamp}.json"
        
        data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host_scores": self.host_scores,
            "user_scores": self.user_scores,
            "service_scores": self.service_scores,
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved risk scores to {filename}")


# Global risk scorer instance
risk_scorer = RiskScorer()
