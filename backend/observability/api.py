"""
Activity Log API
Local AI-Powered Security Operations Center

Provides endpoints and WebSocket for real-time activity streaming.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.responses import JSONResponse, Response
from typing import Optional, List, Dict, Any
from datetime import datetime
import json
import structlog

from observability.activity_logger import (
    activity_logger,
    ActivityEvent,
    EventCategory,
    SeverityLevel,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/api", tags=["activity_log"])

# Store WebSocket connections
websocket_connections: Dict[str, WebSocket] = {}


def broadcast_event(event_data: Dict[str, Any]):
    """Broadcast event to all connected WebSocket clients."""
    disconnected = []
    
    for client_id, websocket in websocket_connections.items():
        try:
            asyncio_run = False
            try:
                # Check if we're in an async context
                import asyncio
                asyncio.get_running_loop()
                asyncio_run = True
            except RuntimeError:
                pass
            
            if asyncio_run:
                import asyncio
                asyncio.create_task(websocket.send_json(event_data))
            else:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(websocket.send_json(event_data))
                loop.close()
        except Exception:
            disconnected.append(client_id)
    
    # Clean up disconnected clients
    for client_id in disconnected:
        websocket_connections.pop(client_id, None)


# Register broadcast callback
activity_logger.register_callback(broadcast_event)


@router.get("/activity_stream")
async def get_activity_events(
    limit: int = Query(default=100, ge=1, le=1000),
    category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    module: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None, description="Search in message and metadata"),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
):
    """
    Get activity log events with filtering.
    
    - **limit**: Maximum events to return (1-1000)
    - **category**: Filter by category (SYSTEM, RAG_PIPELINE, AI_AGENT, etc.)
    - **severity**: Filter by severity (debug, info, warning, error, critical)
    - **module**: Filter by module name
    - **event_type**: Filter by event type
    - **search**: Search query in message and metadata
    - **start_time**: Filter events after this ISO timestamp
    - **end_time**: Filter events before this ISO timestamp
    """
    try:
        events = activity_logger.get_events(
            limit=limit,
            category=category,
            severity=severity,
            module=module,
            event_type=event_type,
            search_query=search,
            start_time=start_time,
            end_time=end_time,
        )
        
        return {
            "status": "success",
            "events": events,
            "total": len(events),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Failed to get activity events: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/activity_stats")
async def get_activity_statistics():
    """Get activity log statistics."""
    try:
        stats = activity_logger.get_statistics()
        return {
            "status": "success",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Failed to get activity stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/activity_categories")
async def get_activity_categories():
    """Get available event categories with colors."""
    categories = []
    for category in EventCategory:
        categories.append({
            "name": category.value,
            "color": activity_logger.__class__.__dict__.get('CATEGORY_COLORS', {}).get(
                category, "#9ca3af"
            ),
        })
    
    # Add colors from module
    from observability.activity_logger import CATEGORY_COLORS
    categories = []
    for category in EventCategory:
        categories.append({
            "name": category.value,
            "color": CATEGORY_COLORS.get(category, "#9ca3af"),
        })
    
    return {
        "status": "success",
        "categories": categories,
        "severities": [s.value for s in SeverityLevel],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.websocket("/ws/activity")
async def websocket_activity(websocket: WebSocket):
    """
    WebSocket endpoint for real-time activity streaming.
    
    Clients connect to receive live event updates.
    """
    await websocket.accept()
    
    client_id = f"client_{id(websocket)}"
    websocket_connections[client_id] = websocket
    
    logger.info(f"WebSocket client connected: {client_id}")
    
    # Send welcome message with recent events
    recent_events = activity_logger.get_events(limit=50)
    await websocket.send_json({
        "type": "connection_established",
        "message": "Connected to activity stream",
        "recent_events": recent_events,
    })
    
    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            
            # Handle client commands
            try:
                command = json.loads(data)
                
                if command.get("action") == "subscribe":
                    # Subscribe to specific categories
                    categories = command.get("categories", [])
                    logger.info(f"Client {client_id} subscribed to: {categories}")
                    
                elif command.get("action") == "unsubscribe":
                    # Unsubscribe from categories
                    logger.info(f"Client {client_id} unsubscribed")
                    
            except json.JSONDecodeError:
                pass
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected: {client_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        websocket_connections.pop(client_id, None)


@router.get("/activity_export")
async def export_activity_logs(
    format: str = Query(default="json", regex="^(json|csv)$"),
    start_time: Optional[str] = Query(default=None),
    end_time: Optional[str] = Query(default=None),
):
    """
    Export activity logs.
    
    - **format**: Export format (json or csv)
    - **start_time**: Filter events after this ISO timestamp
    - **end_time**: Filter events before this ISO timestamp
    """
    try:
        exported_data = activity_logger.export_events(
            format=format,
            start_time=start_time,
            end_time=end_time,
        )
        
        media_type = "application/json" if format.lower() == "json" else "text/csv"
        filename = f"activity_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format.lower()}"
        
        return Response(
            content=exported_data,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
            },
        )
    except Exception as e:
        logger.error(f"Failed to export logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/activity_log")
async def create_activity_log(
    category: str,
    event_type: str,
    module: str,
    message: str,
    severity: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
):
    """
    Create a new activity log entry.
    
    This endpoint allows external systems to log events.
    """
    try:
        event_category = EventCategory(category.upper())
        event_severity = SeverityLevel(severity.lower())
        
        event = activity_logger.log_event(
            category=event_category,
            event_type=event_type,
            module=module,
            message=message,
            severity=event_severity,
            metadata=metadata,
        )
        
        return {
            "status": "success",
            "event_id": event.id,
            "timestamp": event.timestamp,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create activity log: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/activity_security_alerts")
async def get_security_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None),
):
    """Get security alerts specifically."""
    try:
        events = activity_logger.get_events(
            limit=limit,
            category=EventCategory.SECURITY_ALERT.value,
            severity=severity,
        )
        
        return {
            "status": "success",
            "alerts": events,
            "total": len(events),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Failed to get security alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/activity_log/cleanup")
async def cleanup_old_logs():
    """Clean up logs older than retention period."""
    try:
        activity_logger.cleanup_old_events()
        return {
            "status": "success",
            "message": f"Cleaned up events older than {activity_logger.retention_days} days",
        }
    except Exception as e:
        logger.error(f"Failed to cleanup logs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
