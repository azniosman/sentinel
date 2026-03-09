"""
Attack Map Simulation Engine
Local AI-Powered Security Operations Center

Generates simulated cyber attack events for demonstration and testing.
"""

import random
import asyncio
import structlog
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import json

logger = structlog.get_logger()


class AttackSimulationEngine:
    """Engine for generating simulated cyber attack events."""
    
    def __init__(self):
        self.is_running = False
        self.simulation_interval = 30  # seconds between simulated attacks
        self.max_active_events = 100
        self.callbacks: List[Callable] = []
        
        # Attack type probabilities
        self.attack_type_weights = {
            "ransomware": 0.25,
            "ddos": 0.20,
            "phishing": 0.20,
            "malware": 0.15,
            "zero_day": 0.10,
            "credential_theft": 0.10,
        }
        
        # Origin countries (attack sources) with weights
        self.origin_countries = {
            "RU": 0.35,  # Russia
            "CN": 0.30,  # China
            "IR": 0.15,  # Iran
            "KP": 0.12,  # North Korea
            "BR": 0.05,  # Brazil
            "NG": 0.03,  # Nigeria
        }
        
        # Target countries with weights
        self.target_countries = {
            "US": 0.25,  # United States
            "GB": 0.12,  # United Kingdom
            "DE": 0.10,  # Germany
            "FR": 0.08,  # France
            "JP": 0.08,  # Japan
            "AU": 0.06,  # Australia
            "IN": 0.06,  # India
            "SG": 0.05,  # Singapore
            "KR": 0.05,  # South Korea
            "UA": 0.05,  # Ukraine
            "CA": 0.04,  # Canada
            "IT": 0.03,  # Italy
            "NL": 0.03,  # Netherlands
        }
        
        # Threat actors by origin
        self.threat_actors = {
            "RU": [
                {"name": "LockBit", "malware": "LockBit 3.0", "sectors": ["Finance", "Healthcare", "Energy"]},
                {"name": "APT28", "malware": "XAgent", "sectors": ["Government", "Defense", "Media"]},
                {"name": "Sandworm", "malware": "Industroyer2", "sectors": ["Energy", "Transportation", "Government"]},
                {"name": "Killnet", "malware": None, "sectors": ["Government", "Transportation", "Media"]},
                {"name": "APT29", "malware": "WellMess", "sectors": ["Government", "Healthcare", "Research"]},
            ],
            "CN": [
                {"name": "APT41", "malware": "PlugX", "sectors": ["Healthcare", "Telecom", "Gaming"]},
                {"name": "Volt Typhoon", "malware": "Living off the Land", "sectors": ["Telecommunications", "Energy", "Transportation"]},
                {"name": "RedEcho", "malware": "Cobalt Strike", "sectors": ["Power Grid", "Finance", "Government"]},
                {"name": "APT10", "malware": "QuasarRAT", "sectors": ["Technology", "Aerospace", "Engineering"]},
            ],
            "IR": [
                {"name": "MuddyWater", "malware": "PowerShell Empire", "sectors": ["Defense", "Government", "Telecom"]},
                {"name": "OilRig", "malware": "Helix Kitten", "sectors": ["Oil & Gas", "Government", "Finance"]},
                {"name": "Charcoal Bank", "malware": "Black Basta", "sectors": ["Healthcare", "Finance", "Technology"]},
                {"name": "APT33", "malware": "TurnedUp", "sectors": ["Aerospace", "Energy", "Petrochemical"]},
            ],
            "KP": [
                {"name": "Lazarus Group", "malware": "AppleJeus", "sectors": ["Cryptocurrency", "Finance", "Media"]},
                {"name": "Kimsuky", "malware": "RokRat", "sectors": ["Government", "Finance", "Research"]},
                {"name": "APT38", "malware": "COPPERHEDGE", "sectors": ["Finance", "Cryptocurrency", "Defense"]},
            ],
            "BR": [
                {"name": "FIN7", "malware": "Carbanak", "sectors": ["Retail", "Finance", "Hospitality"]},
            ],
            "NG": [
                {"name": "SilverTerrier", "malware": "Necurs", "sectors": ["Finance", "Technology", "Legal"]},
            ],
        }
        
        # Severity distribution
        self.severity_weights = {
            "critical": 0.20,
            "high": 0.35,
            "medium": 0.30,
            "low": 0.15,
        }
        
        # Status distribution
        self.status_weights = {
            "active": 0.50,
            "investigating": 0.30,
            "mitigated": 0.20,
        }
        
        # CVE list for simulation
        self.cve_list = [
            "CVE-2024-3400", "CVE-2024-23897", "CVE-2024-1086", "CVE-2024-27198",
            "CVE-2024-4577", "CVE-2024-21410", "CVE-2024-3094", "CVE-2024-9999",
            "CVE-2024-8888", "CVE-2024-5678", "CVE-2024-1234", "CVE-2024-5555",
            "CVE-2024-7777", "CVE-2024-3333", "CVE-2024-6666",
        ]
        
        logger.info("AttackSimulationEngine initialized")
    
    def register_callback(self, callback: Callable):
        """Register a callback to be called when new attack is generated."""
        self.callbacks.append(callback)
        logger.info(f"Registered attack simulation callback: {callback.__name__}")
    
    def _weighted_choice(self, choices: Dict[str, float]) -> str:
        """Make a weighted random choice."""
        items = list(choices.keys())
        weights = list(choices.values())
        return random.choices(items, weights=weights, k=1)[0]
    
    def generate_attack_event(self, simulated: bool = True) -> Dict[str, Any]:
        """Generate a single simulated attack event."""
        origin = self._weighted_choice(self.origin_countries)
        target = self._weighted_choice(self.target_countries)
        attack_type = self._weighted_choice(self.attack_type_weights)
        severity = self._weighted_choice(self.severity_weights)
        status = self._weighted_choice(self.status_weights)
        
        # Get threat actor info
        actor_info = random.choice(self.threat_actors.get(origin, [{"name": "Unknown", "malware": None, "sectors": ["General"]}]))
        
        # Generate CVE (70% chance)
        cve = random.choice(self.cve_list) if random.random() > 0.3 else None
        
        event = {
            "id": f"{'sim' if simulated else 'real'}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
            "origin_country": self._get_country_name(origin),
            "origin_country_code": origin,
            "target_country": self._get_country_name(target),
            "target_country_code": target,
            "attack_type": attack_type,
            "threat_actor": actor_info["name"],
            "malware_family": actor_info["malware"],
            "target_sector": random.choice(actor_info["sectors"]),
            "cve_exploited": cve,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status": status,
            "simulated": simulated,
        }
        
        return event
    
    def _get_country_name(self, code: str) -> str:
        """Get country name from code."""
        country_names = {
            "US": "United States", "CN": "China", "RU": "Russia", "GB": "United Kingdom",
            "DE": "Germany", "FR": "France", "JP": "Japan", "KR": "South Korea",
            "KP": "North Korea", "IR": "Iran", "IL": "Israel", "UA": "Ukraine",
            "AU": "Australia", "IN": "India", "SG": "Singapore", "SA": "Saudi Arabia",
            "BR": "Brazil", "CA": "Canada", "IT": "Italy", "ES": "Spain",
            "NL": "Netherlands", "SE": "Sweden", "NO": "Norway", "PL": "Poland",
            "TR": "Turkey", "ZA": "South Africa", "NG": "Nigeria", "EG": "Egypt",
            "AE": "United Arab Emirates", "MX": "Mexico", "AR": "Argentina",
        }
        return country_names.get(code, code)
    
    async def start_simulation(self):
        """Start the attack simulation loop."""
        if self.is_running:
            logger.warning("Simulation already running")
            return
        
        self.is_running = True
        logger.info("Starting attack simulation loop")
        
        while self.is_running:
            try:
                # Generate simulated attack
                event = self.generate_attack_event()
                
                # Log the attack
                logger.info(
                    "[ATTACK_SIMULATION] Simulated cyber attack detected",
                    origin=event["origin_country"],
                    target=event["target_country"],
                    attack_type=event["attack_type"],
                    severity=event["severity"],
                    threat_actor=event["threat_actor"],
                )
                
                # Call registered callbacks
                for callback in self.callbacks:
                    try:
                        if asyncio.iscoroutinefunction(callback):
                            await callback(event)
                        else:
                            callback(event)
                    except Exception as e:
                        logger.error(f"Callback error: {str(e)}")
                
                # Wait for next simulation
                await asyncio.sleep(self.simulation_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Simulation error: {str(e)}")
                await asyncio.sleep(self.simulation_interval)
    
    def stop_simulation(self):
        """Stop the simulation loop."""
        self.is_running = False
        logger.info("Attack simulation stopped")
    
    def generate_burst_attacks(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate a burst of attack events (for demo purposes)."""
        events = []
        for _ in range(count):
            event = self.generate_attack_event()
            events.append(event)
            logger.info(
                "[ATTACK_BURST] Simulated attack",
                origin=event["origin_country"],
                target=event["target_country"],
                attack_type=event["attack_type"],
            )
        return events
    
    def generate_targeted_campaign(
        self,
        origin: str,
        targets: List[str],
        attack_type: str,
        threat_actor: str,
        malware: str,
    ) -> List[Dict[str, Any]]:
        """Generate a coordinated campaign targeting multiple countries."""
        events = []
        
        for target in targets:
            event = {
                "id": f"campaign_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{target}",
                "origin_country": self._get_country_name(origin),
                "origin_country_code": origin,
                "target_country": self._get_country_name(target),
                "target_country_code": target,
                "attack_type": attack_type,
                "threat_actor": threat_actor,
                "malware_family": malware,
                "target_sector": random.choice(["Government", "Defense", "Energy", "Finance"]),
                "cve_exploited": random.choice(self.cve_list),
                "severity": random.choice(["critical", "high"]),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "status": "active",
                "simulated": True,
                "campaign_id": f"campaign_{origin}_{attack_type}",
            }
            events.append(event)
            
            logger.info(
                "[CAMPAIGN] Coordinated attack",
                origin=origin,
                target=target,
                actor=threat_actor,
            )
        
        return events


# Global simulation engine instance
simulation_engine = AttackSimulationEngine()
