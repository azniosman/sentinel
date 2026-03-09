"""
Extended AI-SOC APIs
Zero-Day Monitor, Endpoint Monitor, Risk Scoring
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from zero_day_monitor.monitor import zero_day_monitor, ExploitMaturity
from endpoint_monitor.monitor import endpoint_monitor
from risk_scoring.scorer import risk_scorer

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["extended"])


# ============== Zero-Day Monitor Endpoints ==============

@router.get("/zero_day/alerts")
async def get_zero_day_alerts(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
):
    """Get zero-day alerts."""
    alerts = zero_day_monitor.get_alerts(status, severity, limit)
    
    return {
        "status": "success",
        "alerts": alerts,
        "total": len(alerts),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/zero_day/stats")
async def get_zero_day_statistics():
    """Get zero-day monitor statistics."""
    stats = zero_day_monitor.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/zero_day/scan")
async def scan_for_zero_days(
    cve_feed: List[Dict[str, Any]] = Body(default=[]),
):
    """Scan CVE feed for zero-days."""
    if not cve_feed:
        # Use sample data
        cve_feed = [
            {
                "cve_id": "2024-9999",
                "cvss_score": 9.8,
                "description": "Critical RCE vulnerability with active exploitation",
                "affected_products": ["Apache", "Nginx"],
                "patch_available": False,
            }
        ]
    
    alerts = zero_day_monitor.scan_for_zero_days(cve_feed)
    
    return {
        "status": "success",
        "alerts_created": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ============== Endpoint Monitor Endpoints ==============

@router.get("/endpoint/events")
async def get_endpoint_events(
    hostname: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
):
    """Get endpoint events."""
    events = endpoint_monitor.get_events(hostname, event_type, severity, limit)
    
    return {
        "status": "success",
        "events": events,
        "total": len(events),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/endpoint/hosts/{hostname}")
async def get_host_summary(hostname: str):
    """Get endpoint summary for a host."""
    summary = endpoint_monitor.get_host_summary(hostname)
    
    return {
        "status": "success",
        "data": summary,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/endpoint/stats")
async def get_endpoint_statistics():
    """Get endpoint monitoring statistics."""
    stats = endpoint_monitor.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/endpoint/events/ingest")
async def ingest_endpoint_events(
    events: List[Dict[str, Any]] = Body(...),
):
    """Ingest endpoint events."""
    processed = []
    
    for event_data in events:
        event = endpoint_monitor.process_event(event_data)
        if event:
            processed.append(event.to_dict())
    
    return {
        "status": "success",
        "events_processed": len(processed),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ============== Risk Scoring Endpoints ==============

@router.get("/risk/hosts")
async def get_host_risk_scores(
    limit: int = Query(default=10),
):
    """Get host risk scores."""
    hosts = risk_scorer.get_high_risk_hosts(limit)
    
    return {
        "status": "success",
        "hosts": hosts,
        "total": len(hosts),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/risk/users")
async def get_user_risk_scores(
    limit: int = Query(default=10),
):
    """Get user risk scores."""
    users = risk_scorer.get_high_risk_users(limit)
    
    return {
        "status": "success",
        "users": users,
        "total": len(users),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/risk/hosts/calculate")
async def calculate_host_risk(
    hostname: str = Body(...),
    vulnerabilities: List[Dict[str, Any]] = Body(default=[]),
    suspicious_events: List[Dict[str, Any]] = Body(default=[]),
    exposure_level: str = Body(default="internal"),
    compliance_status: str = Body(default="compliant"),
):
    """Calculate risk score for a host."""
    risk = risk_scorer.calculate_host_risk(
        hostname=hostname,
        vulnerabilities=vulnerabilities,
        suspicious_events=suspicious_events,
        exposure_level=exposure_level,
        compliance_status=compliance_status,
    )
    
    return {
        "status": "success",
        "risk": risk,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/risk/users/calculate")
async def calculate_user_risk(
    username: str = Body(...),
    failed_logins: int = Body(default=0),
    privilege_escalations: int = Body(default=0),
    suspicious_commands: int = Body(default=0),
    account_age_days: int = Body(default=365),
    is_admin: bool = Body(default=False),
):
    """Calculate risk score for a user."""
    risk = risk_scorer.calculate_user_risk(
        username=username,
        failed_logins=failed_logins,
        privilege_escalations=privilege_escalations,
        suspicious_commands=suspicious_commands,
        account_age_days=account_age_days,
        is_admin=is_admin,
    )
    
    return {
        "status": "success",
        "risk": risk,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/risk/stats")
async def get_risk_statistics():
    """Get risk scoring statistics."""
    stats = risk_scorer.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
