"""
Threat Hunting and SOAR API
Local AI-Powered Security Operations Center
"""

from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from threat_hunting.engine import threat_hunting_engine
from response_engine.engine import soar_engine, ResponseActionType

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["threat_hunting", "soar"])


# ============== Threat Hunting Endpoints ==============

@router.get("/threat_hunting/queries")
async def get_hunt_queries():
    """Get all threat hunting queries."""
    queries = [q.to_dict() for q in threat_hunting_engine.queries.values()]
    
    return {
        "status": "success",
        "queries": queries,
        "total": len(queries),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/threat_hunting/run")
async def run_hunt_query(
    query_id: str = Body(...),
    events: List[Dict[str, Any]] = Body(default=[]),
):
    """Run a threat hunting query."""
    if not events:
        # Use sample data if no events provided
        events = [{"source_type": "endpoint", "process": "powershell.exe", "command": "test"}]
    
    findings = threat_hunting_engine.run_hunt(query_id, events)
    
    return {
        "status": "success",
        "query_id": query_id,
        "findings": findings,
        "findings_count": len(findings),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/threat_hunting/run_all")
async def run_all_hunts(
    events: List[Dict[str, Any]] = Body(default=[]),
):
    """Run all threat hunting queries."""
    if not events:
        events = [{"source_type": "endpoint", "process": "test"}]
    
    all_findings = threat_hunting_engine.run_all_hunts(events)
    
    total_findings = sum(len(f) for f in all_findings.values())
    
    return {
        "status": "success",
        "findings_by_query": {k: len(v) for k, v in all_findings.items()},
        "total_findings": total_findings,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/threat_hunting/findings")
async def get_hunt_findings(
    query_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
):
    """Get threat hunting findings."""
    findings = threat_hunting_engine.get_findings(query_id, limit)
    
    return {
        "status": "success",
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/threat_hunting/stats")
async def get_hunt_statistics():
    """Get threat hunting statistics."""
    stats = threat_hunting_engine.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ============== SOAR Endpoints ==============

@router.get("/soar/playbooks")
async def get_playbooks(
    enabled_only: bool = Query(default=False),
):
    """Get SOAR playbooks."""
    playbooks = soar_engine.get_playbooks(enabled_only)
    
    return {
        "status": "success",
        "playbooks": playbooks,
        "total": len(playbooks),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/soar/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: str,
    context: Dict[str, Any] = Body(default={}),
):
    """Run a SOAR playbook."""
    import asyncio
    
    # Add sample alert context if none provided
    if not context:
        context = {
            "alert": {
                "rule_id": "BRUTE_FORCE_001",
                "severity": "high",
                "rule_name": "SSH Brute Force Detection",
                "event": {
                    "source_ip": "10.0.0.50",
                    "host": "server01",
                    "destination_ip": "192.168.1.100",
                }
            }
        }
    
    result = asyncio.run(soar_engine.run_playbook(playbook_id, context))
    
    return {
        "status": "success",
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/soar/actions")
async def get_response_actions(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100),
):
    """Get response actions."""
    actions = soar_engine.get_actions(status, limit)
    
    return {
        "status": "success",
        "actions": actions,
        "total": len(actions),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/soar/actions/create")
async def create_response_action(
    action_type: str = Body(...),
    target: str = Body(...),
    parameters: Dict[str, Any] = Body(default={}),
    requires_approval: bool = Body(default=True),
):
    """Create a response action."""
    try:
        action_type_enum = ResponseActionType(action_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action type: {action_type}")
    
    action = soar_engine.create_action(
        action_type=action_type_enum,
        target=target,
        parameters=parameters,
        requires_approval=requires_approval,
    )
    
    return {
        "status": "success",
        "action": action.to_dict(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/soar/actions/{action_id}/execute")
async def execute_action(
    action_id: str,
    executed_by: str = Body(default="system"),
):
    """Execute a response action."""
    import asyncio
    
    result = asyncio.run(soar_engine.execute_action(action_id, executed_by))
    
    return {
        "status": "success",
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.post("/soar/actions/{action_id}/approve")
async def approve_action(
    action_id: str,
    approved_by: str = Body(...),
):
    """Approve a pending response action."""
    import asyncio
    
    result = asyncio.run(soar_engine.approve_action(action_id, approved_by))
    
    return {
        "status": "success",
        "result": result,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/soar/stats")
async def get_soar_statistics():
    """Get SOAR statistics."""
    stats = soar_engine.get_statistics()
    
    return {
        "status": "success",
        "data": stats,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
