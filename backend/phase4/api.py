"""
Phase 4 Advanced APIs
Anomaly Detection, User Behavior Analytics
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from anomaly_detection.detector import anomaly_detector
from user_behavior_analytics.engine import uba_engine

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["phase4"])


# ============== Anomaly Detection Endpoints ==============

@router.get("/anomaly/detect")
async def detect_anomaly(
    event: Dict[str, Any] = Body(...),
):
    """Detect if an event is anomalous."""
    # Add event to buffer
    anomaly_detector.add_event(event)
    
    # Check for anomaly
    anomaly = anomaly_detector.detect_anomaly(event)
    
    return {
        "status": "success",
        "anomaly_detected": anomaly is not None,
        "anomaly": anomaly,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/anomaly/alerts")
async def get_anomaly_alerts(
    limit: int = Query(default=100),
    severity: Optional[str] = Query(default=None),
):
    """Get anomaly alerts."""
    alerts = anomaly_detector.get_anomalies(limit, severity)
    
    return {
        "status": "success",
        "alerts": alerts,
        "total": len(alerts),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/anomaly/stats")
async def get_anomaly_statistics():
    """Get anomaly detection statistics."""
    stats = anomaly_detector.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/anomaly/behavioral")
async def detect_behavioral_anomaly(
    entity: str = Body(...),
    entity_type: str = Body(default="ip"),
    metrics: Dict[str, Any] = Body(default={}),
):
    """Detect behavioral anomaly for an entity."""
    anomaly = anomaly_detector.detect_behavioral_anomaly(entity, entity_type, metrics)
    
    return {
        "status": "success",
        "anomaly_detected": anomaly is not None,
        "anomaly": anomaly,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ============== User Behavior Analytics Endpoints ==============

@router.post("/uba/process")
async def process_uba_event(
    event: Dict[str, Any] = Body(...),
):
    """Process event for UBA analysis."""
    alert = uba_engine.process_event(event)
    
    return {
        "status": "success",
        "alert_generated": alert is not None,
        "alert": alert,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/uba/users/{username}")
async def get_user_profile(username: str):
    """Get user behavior profile."""
    profile = uba_engine.get_user_profile(username)
    
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    
    return {
        "status": "success",
        "profile": profile,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/uba/users/high-risk")
async def get_high_risk_users(
    limit: int = Query(default=10),
):
    """Get high risk users."""
    users = uba_engine.get_high_risk_users(limit)
    
    return {
        "status": "success",
        "users": users,
        "total": len(users),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/uba/alerts")
async def get_uba_alerts(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
):
    """Get UBA alerts."""
    alerts = uba_engine.get_alerts(status, limit)
    
    return {
        "status": "success",
        "alerts": alerts,
        "total": len(alerts),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/uba/stats")
async def get_uba_statistics():
    """Get UBA statistics."""
    stats = uba_engine.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
