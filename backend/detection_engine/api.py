"""
Detection Engine API
Local AI-Powered Security Operations Center

Provides endpoints for detection rules, alerts, and IOC management.
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from detection_engine.engine import detection_engine, DetectionRule

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["detection"])


@router.get("/detections/rules")
async def get_detection_rules(
    enabled_only: bool = Query(default=False),
):
    """Get all detection rules."""
    rules = detection_engine.rules
    
    if enabled_only:
        rules = {k: v for k, v in rules.items() if v.enabled}
    
    return {
        "status": "success",
        "rules": [r.to_dict() for r in rules.values()],
        "total": len(rules),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/detections/rules")
async def create_detection_rule(
    rule_id: str = Body(...),
    name: str = Body(...),
    description: str = Body(...),
    severity: str = Body(default="medium"),
    mitre_attack: List[str] = Body(default=[]),
):
    """Create a new detection rule (simplified - full implementation needs condition function)."""
    # Note: Full rule creation requires defining condition function
    # This is a placeholder for rule metadata registration
    
    return {
        "status": "success",
        "message": "Rule creation requires condition function definition",
        "rule_id": rule_id,
    }


@router.get("/detections/alerts")
async def get_alerts(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get security alerts with filtering."""
    alerts = detection_engine.get_alerts(
        status=status,
        severity=severity,
        limit=limit,
    )
    
    return {
        "status": "success",
        "alerts": alerts,
        "total": len(alerts),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/detections/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    resolution: str = Body(default="resolved"),
):
    """Resolve a security alert."""
    if resolution not in ["resolved", "false_positive", "investigating"]:
        raise HTTPException(status_code=400, detail="Invalid resolution status")
    
    detection_engine.resolve_alert(alert_id, resolution)
    
    return {
        "status": "success",
        "alert_id": alert_id,
        "resolution": resolution,
    }


@router.post("/detections/scan")
async def run_detection_scan(
    events: List[Dict[str, Any]] = Body(...),
):
    """Run detection engine on provided events."""
    alerts = detection_engine.process_batch(events)
    
    return {
        "status": "success",
        "events_processed": len(events),
        "alerts_triggered": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/detections/iocs")
async def get_iocs(
    ioc_type: Optional[str] = Query(default=None),
):
    """Get IOC database."""
    if ioc_type:
        iocs = detection_engine.ioc_database.get(ioc_type, [])
    else:
        iocs = detection_engine.ioc_database
    
    return {
        "status": "success",
        "iocs": iocs,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/detections/iocs/add")
async def add_ioc(
    ioc_type: str = Body(...),
    value: str = Body(...),
):
    """Add an IOC to the database."""
    valid_types = ["malicious_ip", "malicious_domain", "malicious_hash"]
    
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type. Must be one of: {valid_types}")
    
    detection_engine.add_ioc(ioc_type, value)
    
    return {
        "status": "success",
        "ioc_type": ioc_type,
        "value": value,
    }


@router.get("/detections/stats")
async def get_detection_statistics():
    """Get detection engine statistics."""
    stats = detection_engine.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/detections/process")
async def process_telemetry(
    events: List[Dict[str, Any]] = Body(...),
    source_type: str = Body(default="normalized"),
):
    """Process telemetry through detection engine."""
    from log_normalization.normalizer import log_normalizer
    
    # Normalize if needed
    if source_type != "normalized":
        events = log_normalizer.normalize_batch(events, source_type)
    
    # Run detection
    alerts = detection_engine.process_batch(events)
    
    # Save alerts
    detection_engine.save_alerts()
    
    return {
        "status": "success",
        "events_processed": len(events),
        "alerts_triggered": len(alerts),
        "alert_ids": [a.alert_id for a in alerts],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
