"""
IOC Correlation Engine
Local AI-Powered Security Operations Center

Correlates Indicators of Compromise against threat intelligence.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import structlog

from config import settings
from threat_ingestion.schema import IOCRecord, SeverityLevel

logger = structlog.get_logger()


class IOCCorrelator:
    """IOC correlation and matching engine."""
    
    def __init__(self):
        self.threat_intel_dir = Path(settings.THREAT_INTEL_DIR)
        self.ioc_database: List[IOCRecord] = []
        self.ioc_index: Dict[str, List[IOCRecord]] = {
            "ip": [],
            "domain": [],
            "hash": [],
            "url": [],
            "email": [],
            "file_path": [],
            "registry_key": [],
        }
        
        logger.info("IOCCorrelator initialized")
    
    async def load_ioc_database(self):
        """Load IOC database from disk."""
        ioc_file = self.threat_intel_dir / "ioc_database.json"
        
        if ioc_file.exists():
            with open(ioc_file, "r") as f:
                ioc_data = json.load(f)
                
                self.ioc_database = [
                    IOCRecord(**ioc) if isinstance(ioc, dict) else ioc
                    for ioc in ioc_data
                ]
                
                # Build index
                self._build_ioc_index()
                
                logger.info(f"Loaded {len(self.ioc_database)} IOCs")
        else:
            logger.info("No IOC database found, starting empty")
    
    def _build_ioc_index(self):
        """Build index for fast IOC lookup."""
        self.ioc_index = {
            "ip": [],
            "domain": [],
            "hash": [],
            "url": [],
            "email": [],
            "file_path": [],
            "registry_key": [],
        }
        
        for ioc in self.ioc_database:
            ioc_type = ioc.ioc_type.lower()
            if ioc_type in self.ioc_index:
                self.ioc_index[ioc_type].append(ioc)
    
    async def add_ioc(self, ioc: IOCRecord):
        """
        Add an IOC to the database.
        
        Args:
            ioc: IOC record to add
        """
        self.ioc_database.append(ioc)
        self.ioc_index[ioc.ioc_type.lower()].append(ioc)
        
        # Save to disk
        await self._save_ioc_database()
        
        logger.debug(f"Added IOC: {ioc.ioc_type}:{ioc.value}")
    
    async def _save_ioc_database(self):
        """Save IOC database to disk."""
        ioc_file = self.threat_intel_dir / "ioc_database.json"
        
        with open(ioc_file, "w") as f:
            json.dump(
                [ioc.dict() for ioc in self.ioc_database],
                f,
                indent=2,
                default=str,
            )
    
    async def check_ioc(
        self,
        ioc_type: str,
        value: str,
    ) -> Dict[str, Any]:
        """
        Check an IOC against threat intelligence.
        
        Args:
            ioc_type: Type of IOC (ip, domain, hash, url, etc.)
            value: IOC value
            
        Returns:
            Correlation results
        """
        # Ensure database is loaded
        if not self.ioc_database:
            await self.load_ioc_database()
        
        # Normalize value
        value_lower = value.lower().strip()
        
        # Search index
        ioc_type_lower = ioc_type.lower()
        matches = []
        
        if ioc_type_lower in self.ioc_index:
            for ioc in self.ioc_index[ioc_type_lower]:
                if self._ioc_matches(ioc, value_lower):
                    matches.append(ioc)
        
        # If no exact matches, check for partial matches (domains, URLs)
        if not matches and ioc_type_lower in ["domain", "url"]:
            matches = self._check_partial_matches(ioc_type_lower, value_lower)
        
        # Build response
        if matches:
            return {
                "matched": True,
                "ioc_type": ioc_type,
                "value": value,
                "matches": [
                    {
                        "ioc_id": m.id,
                        "severity": m.severity.value,
                        "confidence": m.confidence,
                        "category": m.ioc_category,
                        "description": m.description,
                        "associated_malware": m.associated_malware,
                        "associated_threat_actors": m.associated_threat_actors,
                        "associated_campaigns": m.associated_campaigns,
                        "first_seen": m.first_seen.isoformat() if m.first_seen else None,
                        "last_seen": m.last_seen.isoformat() if m.last_seen else None,
                        "false_positive_rate": m.false_positive_rate,
                        "tags": m.tags,
                    }
                    for m in matches
                ],
                "risk_level": self._calculate_risk_level(matches),
                "recommended_actions": self._get_recommended_actions(matches),
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "matched": False,
                "ioc_type": ioc_type,
                "value": value,
                "matches": [],
                "risk_level": "UNKNOWN",
                "recommended_actions": [
                    "Continue monitoring",
                    "Consider adding to watchlist if suspicious",
                ],
                "timestamp": datetime.utcnow().isoformat(),
            }
    
    def _ioc_matches(self, ioc: IOCRecord, value: str) -> bool:
        """Check if IOC matches value."""
        ioc_value = ioc.value.lower().strip()
        
        # Exact match
        if ioc_value == value:
            return True
        
        # Domain match (subdomains)
        if ioc.ioc_type.lower() == "domain":
            if value.endswith(f".{ioc_value}"):
                return True
        
        # Hash match (any hash type)
        if ioc.ioc_type.lower() == "hash":
            if ioc_value == value:
                return True
        
        return False
    
    def _check_partial_matches(
        self,
        ioc_type: str,
        value: str,
    ) -> List[IOCRecord]:
        """Check for partial matches in domain/URL IOCs."""
        matches = []
        
        for ioc in self.ioc_index.get(ioc_type, []):
            ioc_value = ioc.value.lower().strip()
            
            # Check if value contains IOC (for domains in URLs)
            if ioc_value in value:
                matches.append(ioc)
            
            # Check if IOC domain is parent of value domain
            if ioc_type == "domain" and value.endswith(f".{ioc_value}"):
                matches.append(ioc)
        
        return matches
    
    def _calculate_risk_level(self, matches: List[IOCRecord]) -> str:
        """Calculate overall risk level from matches."""
        if not matches:
            return "UNKNOWN"
        
        # Get highest severity
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1,
        }
        
        max_severity = max(
            matches,
            key=lambda x: severity_order.get(x.severity, 0),
        ).severity
        
        # Check for active threats
        has_active_threat = any(
            m.associated_threat_actors or m.associated_campaigns
            for m in matches
        )
        
        if max_severity == SeverityLevel.CRITICAL or has_active_threat:
            return "CRITICAL"
        elif max_severity == SeverityLevel.HIGH:
            return "HIGH"
        elif max_severity == SeverityLevel.MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_recommended_actions(self, matches: List[IOCRecord]) -> List[str]:
        """Get recommended actions based on matches."""
        actions = []
        
        if not matches:
            return ["No immediate action required"]
        
        risk_level = self._calculate_risk_level(matches)
        
        if risk_level == "CRITICAL":
            actions.extend([
                "IMMEDIATE: Isolate affected systems",
                "Initiate incident response procedure",
                "Block IOC at firewall/proxy",
                "Search for related IOCs in logs",
                "Preserve forensic evidence",
                "Notify security team",
            ])
        elif risk_level == "HIGH":
            actions.extend([
                "Block IOC at firewall/proxy",
                "Investigate associated systems",
                "Review recent logs for related activity",
                "Update detection rules",
            ])
        elif risk_level == "MEDIUM":
            actions.extend([
                "Add IOC to monitoring watchlist",
                "Review logs for historical matches",
                "Update threat intelligence feeds",
            ])
        else:
            actions.extend([
                "Log and monitor",
                "Consider blocking if part of pattern",
            ])
        
        # Add malware-specific actions
        malware_names = set()
        for match in matches:
            malware_names.update(match.associated_malware)
        
        if malware_names:
            actions.append(f"Scan for malware signatures: {', '.join(malware_names)}")
        
        return actions
    
    async def bulk_check(
        self,
        iocs: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Bulk check multiple IOCs.
        
        Args:
            iocs: List of IOC dictionaries with 'ioc_type' and 'value'
            
        Returns:
            Bulk check results
        """
        results = []
        matched_count = 0
        
        for ioc in iocs:
            result = await self.check_ioc(
                ioc_type=ioc.get("ioc_type", "unknown"),
                value=ioc.get("value", ""),
            )
            
            if result["matched"]:
                matched_count += 1
            
            results.append(result)
        
        return {
            "total_checked": len(iocs),
            "matched": matched_count,
            "not_matched": len(iocs) - matched_count,
            "results": results,
            "summary": {
                "critical": sum(1 for r in results if r.get("risk_level") == "CRITICAL"),
                "high": sum(1 for r in results if r.get("risk_level") == "HIGH"),
                "medium": sum(1 for r in results if r.get("risk_level") == "MEDIUM"),
                "low": sum(1 for r in results if r.get("risk_level") == "LOW"),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def match_ip_to_known_threat_actor(self, ip: str) -> Dict[str, Any]:
        """
        Match an IP address to known threat actors.
        
        Args:
            ip: IP address to check
            
        Returns:
            Threat actor correlation
        """
        # This would ideally query a threat intelligence API
        # For now, check our IOC database
        return {
            "ip": ip,
            "threat_actors": [],
            "note": "Full threat actor attribution requires external intelligence",
        }
    
    def detect_malware_hash_matches(self, file_hash: str) -> Dict[str, Any]:
        """
        Check if a file hash matches known malware.
        
        Args:
            file_hash: File hash (MD5, SHA1, SHA256)
            
        Returns:
            Malware match results
        """
        # Check hash IOCs
        hash_matches = [
            ioc for ioc in self.ioc_database
            if ioc.ioc_type.lower() == "hash" and ioc.value.lower() == file_hash.lower()
        ]
        
        if hash_matches:
            return {
                "matched": True,
                "hash": file_hash,
                "malware_families": list(set(
                    m for match in hash_matches
                    for m in match.associated_malware
                )),
                "severity": hash_matches[0].severity.value,
                "recommendation": "Quarantine and analyze file immediately",
            }
        
        return {
            "matched": False,
            "hash": file_hash,
            "malware_families": [],
            "severity": "UNKNOWN",
            "recommendation": "No known malware match found",
        }
    
    def identify_malicious_domains(self, domains: List[str]) -> Dict[str, Any]:
        """
        Check multiple domains for malicious activity.
        
        Args:
            domains: List of domains to check
            
        Returns:
            Domain analysis results
        """
        results = {}
        
        for domain in domains:
            result = next(
                (
                    ioc for ioc in self.ioc_database
                    if ioc.ioc_type.lower() == "domain" and
                    (ioc.value.lower() == domain.lower() or
                     domain.lower().endswith(f".{ioc.value.lower()}"))
                ),
                None,
            )
            
            if result:
                results[domain] = {
                    "malicious": True,
                    "severity": result.severity.value,
                    "category": result.ioc_category,
                    "associated_threat_actors": result.associated_threat_actors,
                }
            else:
                results[domain] = {
                    "malicious": False,
                    "severity": "UNKNOWN",
                }
        
        return {
            "domains_checked": len(domains),
            "malicious_count": sum(1 for r in results.values() if r.get("malicious")),
            "results": results,
        }
    
    def correlate_ioc_patterns(
        self,
        iocs: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Correlate multiple IOCs to identify patterns.
        
        Args:
            iocs: List of IOCs to correlate
            
        Returns:
            Pattern correlation analysis
        """
        # Group IOCs by type
        by_type: Dict[str, List[str]] = {}
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            value = ioc.get("value", "")
            
            if ioc_type not in by_type:
                by_type[ioc_type] = []
            by_type[ioc_type].append(value)
        
        # Check each type
        correlation_results = {}
        
        for ioc_type, values in by_type.items():
            if ioc_type == "ip":
                correlation_results["ip_analysis"] = {
                    "count": len(values),
                    "unique_subnets": self._extract_unique_subnets(values),
                }
            elif ioc_type == "domain":
                correlation_results["domain_analysis"] = {
                    "count": len(values),
                    "unique_tlds": self._extract_unique_tlds(values),
                    "potential_dga": self._detect_dga_domains(values),
                }
            elif ioc_type == "hash":
                correlation_results["hash_analysis"] = {
                    "count": len(values),
                    "hash_types": self._identify_hash_types(values),
                }
        
        return {
            "total_iocs": len(iocs),
            "correlation": correlation_results,
            "potential_campaign": self._assess_campaign_likelihood(correlation_results),
        }
    
    def _extract_unique_subnets(self, ips: List[str]) -> List[str]:
        """Extract unique /24 subnets from IP list."""
        subnets = set()
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3]) + ".0/24"
                subnets.add(subnet)
        return list(subnets)
    
    def _extract_unique_tlds(self, domains: List[str]) -> List[str]:
        """Extract unique TLDs from domain list."""
        tlds = set()
        for domain in domains:
            parts = domain.split(".")
            if parts:
                tlds.add(parts[-1])
        return list(tlds)
    
    def _detect_dga_domains(self, domains: List[str]) -> List[str]:
        """Detect potential DGA (Domain Generation Algorithm) domains."""
        dga_candidates = []
        
        for domain in domains:
            # Simple heuristic: long random-looking domains
            name = domain.split(".")[0] if "." in domain else domain
            
            if len(name) > 12:
                # Check for high entropy (random-looking)
                unique_chars = len(set(name))
                if unique_chars > len(name) * 0.6:
                    dga_candidates.append(domain)
        
        return dga_candidates
    
    def _identify_hash_types(self, hashes: List[str]) -> Dict[str, int]:
        """Identify hash types (MD5, SHA1, SHA256)."""
        types = {"md5": 0, "sha1": 0, "sha256": 0, "unknown": 0}
        
        for h in hashes:
            if len(h) == 32:
                types["md5"] += 1
            elif len(h) == 40:
                types["sha1"] += 1
            elif len(h) == 64:
                types["sha256"] += 1
            else:
                types["unknown"] += 1
        
        return types
    
    def _assess_campaign_likelihood(self, correlation: Dict[str, Any]) -> str:
        """Assess likelihood that IOCs are part of a campaign."""
        # Simple heuristic
        ip_count = correlation.get("ip_analysis", {}).get("count", 0)
        domain_count = correlation.get("domain_analysis", {}).get("count", 0)
        
        if ip_count > 5 or domain_count > 5:
            return "HIGH"
        elif ip_count > 2 or domain_count > 2:
            return "MEDIUM"
        else:
            return "LOW"
