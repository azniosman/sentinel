"""
Attack Map API
Local AI-Powered Security Operations Center

Provides endpoints for cyber attack visualization and intelligence.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
import json
import random
import structlog

from config import settings

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["attack_map"])

# Data paths
DATA_DIR = Path(settings.DATA_DIR)
THREAT_INTEL_DIR = Path(settings.THREAT_INTEL_DIR)

# Attack type configurations
ATTACK_TYPE_CONFIG = {
    "ransomware": {
        "color": "#ef4444",
        "arc_color": "#ef4444",
        "arc_width": 2.0,
        "pulse_color": "#fca5a5",
        "label": "Ransomware"
    },
    "ddos": {
        "color": "#f97316",
        "arc_color": "#f97316",
        "arc_width": 1.5,
        "pulse_color": "#fdba74",
        "label": "DDoS"
    },
    "phishing": {
        "color": "#eab308",
        "arc_color": "#eab308",
        "arc_width": 1.0,
        "pulse_color": "#fef08a",
        "label": "Phishing"
    },
    "malware": {
        "color": "#8b5cf6",
        "arc_color": "#8b5cf6",
        "arc_width": 1.8,
        "pulse_color": "#c4b5fd",
        "label": "Malware"
    },
    "zero_day": {
        "color": "#dc2626",
        "arc_color": "#dc2626",
        "arc_width": 2.5,
        "pulse_color": "#f87171",
        "label": "Zero-Day"
    },
    "credential_theft": {
        "color": "#06b6d4",
        "arc_color": "#06b6d4",
        "arc_width": 1.2,
        "pulse_color": "#67e8f9",
        "label": "Credential Theft"
    }
}

# Severity configurations
SEVERITY_CONFIG = {
    "critical": {"color": "#dc2626", "weight": 1.0},
    "high": {"color": "#ea580c", "weight": 0.8},
    "medium": {"color": "#ca8a04", "weight": 0.6},
    "low": {"color": "#16a34a", "weight": 0.4}
}


def load_attack_events() -> List[Dict[str, Any]]:
    """Load attack events from dataset."""
    events_file = THREAT_INTEL_DIR / "attack_events.json"
    
    if not events_file.exists():
        return []
    
    with open(events_file, "r") as f:
        data = json.load(f)
        return data.get("attack_events", [])


def load_country_coordinates() -> Dict[str, Any]:
    """Load country coordinates for map visualization."""
    coords_file = THREAT_INTEL_DIR / "country_coordinates.json"
    
    if not coords_file.exists():
        return {}
    
    with open(coords_file, "r") as f:
        data = json.load(f)
        return data.get("countries", {})


def generate_simulated_attack() -> Dict[str, Any]:
    """Generate a simulated attack event for demonstration."""
    origins = ["RU", "CN", "IR", "KP"]
    targets = ["US", "GB", "DE", "FR", "JP", "AU", "IN", "SG", "KR", "UA"]
    attack_types = ["ransomware", "ddos", "phishing", "malware", "zero_day", "credential_theft"]
    threat_actors = {
        "RU": ["LockBit", "APT28", "Sandworm", "Killnet"],
        "CN": ["APT41", "Volt Typhoon", "RedEcho"],
        "IR": ["MuddyWater", "OilRig", "Charcoal Bank"],
        "KP": ["Lazarus Group", "Kimsuky"]
    }
    sectors = ["Finance", "Government", "Defense", "Healthcare", "Energy", "Telecommunications", "Transportation"]
    severities = ["critical", "high", "medium"]
    
    origin = random.choice(origins)
    target = random.choice(targets)
    attack_type = random.choice(attack_types)
    
    return {
        "id": f"sim_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        "origin_country_code": origin,
        "target_country_code": target,
        "attack_type": attack_type,
        "threat_actor": random.choice(threat_actors.get(origin, ["Unknown"])),
        "malware_family": f"Malware-{random.randint(1000, 9999)}",
        "target_sector": random.choice(sectors),
        "cve_exploited": f"CVE-2024-{random.randint(1000, 9999)}" if random.random() > 0.3 else None,
        "severity": random.choice(severities),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "active",
        "simulated": True
    }


@router.get("/attack_events")
async def get_attack_events(
    limit: int = Query(default=50, ge=1, le=200),
    attack_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    origin: Optional[str] = Query(default=None),
    target: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    include_simulated: bool = Query(default=True),
):
    """
    Get attack events for map visualization.
    
    - **limit**: Maximum number of events to return
    - **attack_type**: Filter by attack type (ransomware, ddos, phishing, etc.)
    - **severity**: Filter by severity (critical, high, medium, low)
    - **origin**: Filter by origin country code
    - **target**: Filter by target country code
    - **status**: Filter by status (active, mitigated, investigating)
    - **include_simulated**: Include simulated events
    """
    try:
        events = load_attack_events()
        
        # Apply filters
        if attack_type:
            events = [e for e in events if e.get("attack_type") == attack_type]
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        if origin:
            events = [e for e in events if e.get("origin_country_code") == origin]
        if target:
            events = [e for e in events if e.get("target_country_code") == target]
        if status:
            events = [e for e in events if e.get("status") == status]
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Limit results
        events = events[:limit]
        
        # Enrich with coordinates and visual config
        coordinates = load_country_coordinates()
        enriched_events = []
        
        for event in events:
            origin_code = event.get("origin_country_code", "")
            target_code = event.get("target_country_code", "")
            attack_type = event.get("attack_type", "unknown")
            severity = event.get("severity", "medium")
            
            # Get coordinates
            origin_coords = coordinates.get(origin_code, {"lat": 0, "lng": 0})
            target_coords = coordinates.get(target_code, {"lat": 0, "lng": 0})
            
            # Get visual config
            type_config = ATTACK_TYPE_CONFIG.get(attack_type, ATTACK_TYPE_CONFIG["malware"])
            severity_config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["medium"])
            
            enriched_event = {
                **event,
                "origin_lat": origin_coords.get("lat", 0),
                "origin_lng": origin_coords.get("lng", 0),
                "target_lat": target_coords.get("lat", 0),
                "target_lng": target_coords.get("lng", 0),
                "arc_color": type_config["arc_color"],
                "arc_width": type_config["arc_width"] * severity_config["weight"],
                "pulse_color": type_config["pulse_color"],
                "color": type_config["color"],
            }
            enriched_events.append(enriched_event)
        
        return {
            "status": "success",
            "events": enriched_events,
            "total": len(enriched_events),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    except Exception as e:
        logger.error(f"Failed to get attack events: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack_events/stats")
async def get_attack_statistics():
    """Get attack statistics for dashboard."""
    try:
        events = load_attack_events()
        
        if not events:
            return {
                "status": "success",
                "data": {
                    "total_attacks": 0,
                    "active_attacks": 0,
                    "by_type": {},
                    "by_severity": {},
                    "top_origins": [],
                    "top_targets": [],
                    "top_actors": [],
                    "top_sectors": []
                }
            }
        
        # Calculate statistics
        by_type = {}
        by_severity = {}
        origin_counts = {}
        target_counts = {}
        actor_counts = {}
        sector_counts = {}
        active_count = 0
        
        for event in events:
            # Count by type
            attack_type = event.get("attack_type", "unknown")
            by_type[attack_type] = by_type.get(attack_type, 0) + 1
            
            # Count by severity
            severity = event.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count origins
            origin = event.get("origin_country_code", "Unknown")
            origin_counts[origin] = origin_counts.get(origin, 0) + 1
            
            # Count targets
            target = event.get("target_country_code", "Unknown")
            target_counts[target] = target_counts.get(target, 0) + 1
            
            # Count actors
            actor = event.get("threat_actor", "Unknown")
            actor_counts[actor] = actor_counts.get(actor, 0) + 1
            
            # Count sectors
            sector = event.get("target_sector", "Unknown")
            sector_counts[sector] = sector_counts.get(sector, 0) + 1
            
            # Count active
            if event.get("status") == "active":
                active_count += 1
        
        # Get top items
        top_origins = sorted(origin_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_actors = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "status": "success",
            "data": {
                "total_attacks": len(events),
                "active_attacks": active_count,
                "by_type": by_type,
                "by_severity": by_severity,
                "top_origins": [{"code": k, "count": v} for k, v in top_origins],
                "top_targets": [{"code": k, "count": v} for k, v in top_targets],
                "top_actors": [{"name": k, "count": v} for k, v in top_actors],
                "top_sectors": [{"name": k, "count": v} for k, v in top_sectors],
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    except Exception as e:
        logger.error(f"Failed to get attack statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack_events/simulate")
async def simulate_attack_event():
    """Generate and add a simulated attack event."""
    try:
        simulated_event = generate_simulated_attack()
        
        # Log the simulated attack
        logger.info(
            "[ATTACK_SIMULATION] Simulated attack detected",
            origin=simulated_event["origin_country_code"],
            target=simulated_event["target_country_code"],
            attack_type=simulated_event["attack_type"],
            severity=simulated_event["severity"],
        )
        
        return {
            "status": "success",
            "event": simulated_event,
            "message": "Simulated attack event generated"
        }
        
    except Exception as e:
        logger.error(f"Failed to simulate attack: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack_events/{event_id}")
async def get_attack_event(event_id: str):
    """Get details of a specific attack event."""
    try:
        events = load_attack_events()
        
        event = next((e for e in events if e.get("id") == event_id), None)
        
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")
        
        # Enrich with coordinates
        coordinates = load_country_coordinates()
        origin_coords = coordinates.get(event.get("origin_country_code", ""), {"lat": 0, "lng": 0})
        target_coords = coordinates.get(event.get("target_country_code", ""), {"lat": 0, "lng": 0})
        
        enriched_event = {
            **event,
            "origin_lat": origin_coords.get("lat", 0),
            "origin_lng": origin_coords.get("lng", 0),
            "target_lat": target_coords.get("lat", 0),
            "target_lng": target_coords.get("lng", 0),
        }
        
        return {
            "status": "success",
            "event": enriched_event
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get attack event: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack_events/types")
async def get_attack_types():
    """Get available attack types with visual configuration."""
    return {
        "status": "success",
        "types": ATTACK_TYPE_CONFIG,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@router.get("/attack_events/heatmap")
async def get_attack_heatmap(
    grid_size: int = Query(default=50, ge=10, le=100),
):
    """Get attack density heatmap data."""
    try:
        events = load_attack_events()
        coordinates = load_country_coordinates()
        
        # Create grid-based heatmap
        heatmap_points = []
        
        for event in events:
            target_code = event.get("target_country_code", "")
            target_coords = coordinates.get(target_code, {"lat": 0, "lng": 0})
            severity = event.get("severity", "medium")
            
            # Weight by severity
            intensity = SEVERITY_CONFIG.get(severity, {}).get("weight", 0.5)
            
            heatmap_points.append({
                "lat": target_coords.get("lat", 0),
                "lng": target_coords.get("lng", 0),
                "intensity": intensity,
            })
        
        return {
            "status": "success",
            "heatmap": heatmap_points,
            "grid_size": grid_size,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    except Exception as e:
        logger.error(f"Failed to get heatmap: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
