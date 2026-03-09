"""
Threat Feed Ingestion System
Local AI-Powered Security Operations Center

Responsible for downloading and updating threat intelligence feeds.
"""

import asyncio
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import httpx
import structlog
from feedparser import parse as parse_rss
from bs4 import BeautifulSoup

from config import settings
from threat_ingestion.schema import (
    CVEMetric,
    ZeroDayAlert,
    ThreatActor,
    MalwareFamily,
    IOCRecord,
    SecurityAdvisory,
    SeverityLevel,
)

logger = structlog.get_logger()


class ThreatIngestionService:
    """Service for ingesting threat intelligence feeds."""
    
    def __init__(self):
        self.raw_feeds_dir = Path(settings.RAW_FEEDS_DIR)
        self.threat_intel_dir = Path(settings.THREAT_INTEL_DIR)
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            headers={"User-Agent": "AI-SOC Threat Ingestion Service"},
        )
        
        # Ensure directories exist
        self.raw_feeds_dir.mkdir(parents=True, exist_ok=True)
        self.threat_intel_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("ThreatIngestionService initialized")
    
    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
    
    async def download_cve_feed(self) -> List[CVEMetric]:
        """
        Download CVE feed from NVD API.
        
        Returns:
            List of CVE records
        """
        logger.info("Downloading CVE feed from NVD")
        
        try:
            # NVD API requires no authentication for public access
            # Fetch last 7 days of CVEs
            last_modified = (datetime.utcnow() - timedelta(days=7)).isoformat()
            
            params = {
                "lastModStartDate": last_modified,
                "lastModEndDate": datetime.utcnow().isoformat(),
                "resultsPerPage": 2000,
            }
            
            response = await self.http_client.get(
                settings.NVD_API_URL,
                params=params,
            )
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                
                # Parse CVSS metrics
                metrics = cve_data.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}
                
                cvss_data = cvss_v3.get("cvssData", {}) or cvss_v2.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                
                # Determine severity
                if cvss_score >= 9.0:
                    severity = SeverityLevel.CRITICAL
                elif cvss_score >= 7.0:
                    severity = SeverityLevel.HIGH
                elif cvss_score >= 4.0:
                    severity = SeverityLevel.MEDIUM
                else:
                    severity = SeverityLevel.LOW
                
                # Extract affected products
                affected_products = []
                for config in cve_data.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            affected_products.append(cpe.get("criteria", "Unknown"))
                
                cve_record = CVEMetric(
                    id=f"cve_{cve_data.get('id', 'unknown')}",
                    cve_id=cve_data.get("id", "Unknown"),
                    description=cve_data.get("descriptions", [{}])[0].get("value", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_data.get("vectorString"),
                    published_date=datetime.fromisoformat(
                        cve_data.get("published", datetime.utcnow().isoformat()).replace("Z", "+00:00")
                    ),
                    last_modified=datetime.fromisoformat(
                        cve_data.get("lastModified", datetime.utcnow().isoformat()).replace("Z", "+00:00")
                    ),
                    affected_products=affected_products[:10],  # Limit to 10
                    attack_vector=cvss_data.get("attackVector"),
                    attack_complexity=cvss_data.get("attackComplexity"),
                    privileges_required=cvss_data.get("privilegesRequired"),
                    user_interaction=cvss_data.get("userInteraction"),
                    scope=cvss_data.get("scope"),
                    confidentiality_impact=cvss_data.get("confidentialityImpact"),
                    integrity_impact=cvss_data.get("integrityImpact"),
                    availability_impact=cvss_data.get("availabilityImpact"),
                    references=[
                        ref.get("url", "")
                        for ref in cve_data.get("references", [])[:10]
                    ],
                )
                
                cves.append(cve_record)
            
            # Save raw feed
            raw_file = self.raw_feeds_dir / f"cve_feed_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(raw_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Downloaded {len(cves)} CVEs", raw_file=str(raw_file))
            return cves
            
        except Exception as e:
            logger.error(f"Failed to download CVE feed: {str(e)}")
            return []
    
    async def download_mitre_attack_dataset(self) -> Dict[str, Any]:
        """
        Download MITRE ATT&CK dataset.
        
        Returns:
            MITRE ATT&CK data
        """
        logger.info("Downloading MITRE ATT&CK dataset")
        
        try:
            response = await self.http_client.get(settings.MITRE_ATTACK_URL)
            response.raise_for_status()
            
            data = response.json()
            
            # Save raw feed
            raw_file = self.raw_feeds_dir / f"mitre_attack_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(raw_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info("Downloaded MITRE ATT&CK dataset", raw_file=str(raw_file))
            return data
            
        except Exception as e:
            logger.error(f"Failed to download MITRE ATT&CK dataset: {str(e)}")
            return {}
    
    async def download_cisa_known_exploited(self) -> List[str]:
        """
        Download CISA Known Exploited Vulnerabilities catalog.
        
        Returns:
            List of CVE IDs in KEV catalog
        """
        logger.info("Downloading CISA Known Exploited Vulnerabilities")
        
        try:
            response = await self.http_client.get(settings.CISA_KNOWN_EXPLOITED_URL)
            response.raise_for_status()
            
            data = response.json()
            kev_cves = [vuln.get("cveID", "") for vuln in data.get("vulnerabilities", [])]
            
            # Save raw feed
            raw_file = self.raw_feeds_dir / f"cisa_kev_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            with open(raw_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Downloaded {len(kev_cves)} CISA KEV entries", raw_file=str(raw_file))
            return kev_cves
            
        except Exception as e:
            logger.error(f"Failed to download CISA KEV: {str(e)}")
            return []
    
    async def download_security_advisories(self) -> List[SecurityAdvisory]:
        """
        Download security advisories from various sources.
        
        Returns:
            List of security advisories
        """
        logger.info("Downloading security advisories")
        
        advisories = []
        
        # Example: CISA alerts RSS feed
        try:
            response = await self.http_client.get("https://www.cisa.gov/cybersecurity-advisories.xml")
            response.raise_for_status()
            
            feed = parse_rss(response.content)
            
            for entry in feed.get("entries", [])[:50]:  # Last 50 advisories
                advisory = SecurityAdvisory(
                    id=f"cisa_{hashlib.md5(entry.get('title', '').encode()).hexdigest()[:12]}",
                    title=entry.get("title", ""),
                    source="CISA",
                    published_date=datetime.utcnow(),
                    severity=SeverityLevel.HIGH,  # Would need to parse from content
                    description=entry.get("summary", entry.get("description", "")),
                    references=[entry.get("link", "")],
                )
                advisories.append(advisory)
            
            logger.info(f"Downloaded {len(advisories)} CISA advisories")
            
        except Exception as e:
            logger.error(f"Failed to download CISA advisories: {str(e)}")
        
        return advisories
    
    async def process_and_save_datasets(self, datasets: Dict[str, Any]):
        """
        Process and save datasets to threat intelligence directory.
        
        Args:
            datasets: Dictionary of datasets to save
        """
        logger.info("Processing and saving datasets")
        
        for dataset_name, data in datasets.items():
            if not data:
                continue
            
            # Convert to JSON if needed
            if isinstance(data, list):
                data = [
                    item.dict() if hasattr(item, "dict") else item
                    for item in data
                ]
            elif hasattr(data, "dict"):
                data = data.dict()
            
            # Save to file
            output_file = self.threat_intel_dir / f"{dataset_name}.json"
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Saved {dataset_name}", file=str(output_file))
    
    async def run_full_ingestion(self):
        """
        Run full threat intelligence ingestion pipeline.
        
        This method downloads all feeds, processes them, and updates datasets.
        """
        logger.info("Starting full threat intelligence ingestion")
        
        start_time = datetime.utcnow()
        
        try:
            # Download all feeds in parallel
            cve_feed, mitre_data, kev_cves, advisories = await asyncio.gather(
                self.download_cve_feed(),
                self.download_mitre_attack_dataset(),
                self.download_cisa_known_exploited(),
                self.download_security_advisories(),
                return_exceptions=True,
            )
            
            # Handle exceptions
            if isinstance(cve_feed, Exception):
                logger.error(f"CVE feed download failed: {cve_feed}")
                cve_feed = []
            
            if isinstance(mitre_data, Exception):
                logger.error(f"MITRE ATT&CK download failed: {mitre_data}")
                mitre_data = {}
            
            if isinstance(kev_cves, Exception):
                logger.error(f"CISA KEV download failed: {kev_cves}")
                kev_cves = []
            
            if isinstance(advisories, Exception):
                logger.error(f"Security advisories download failed: {advisories}")
                advisories = []
            
            # Mark CVEs in KEV list
            for cve in cve_feed:
                if hasattr(cve, "cve_id") and cve.cve_id in kev_cves:
                    cve.keV_listed = True
                    cve.exploit_available = True
            
            # Save all datasets
            datasets = {
                "cve_database": cve_feed,
                "mitre_attack": mitre_data,
                "cisa_kev_list": kev_cves,
                "security_advisories": advisories,
            }
            
            await self.process_and_save_datasets(datasets)
            
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Full ingestion completed in {elapsed:.2f}s")
            
        except Exception as e:
            logger.error(f"Full ingestion failed: {str(e)}")
            raise
