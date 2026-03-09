"""
Activity Logger
Local AI-Powered Security Operations Center

Centralized logging system for SOC event tracking and observability.
"""

import json
import uuid
import asyncio
import structlog
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Set
from collections import deque
from enum import Enum
import threading

from config import settings

logger = structlog.get_logger()


class EventCategory(str, Enum):
    """Event categories for activity logging."""
    SYSTEM = "SYSTEM"
    RAG_PIPELINE = "RAG_PIPELINE"
    AI_AGENT = "AI_AGENT"
    NETWORK_ANALYSIS = "NETWORK_ANALYSIS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    VULNERABILITY_DETECTION = "VULNERABILITY_DETECTION"
    ATTACK_MAP = "ATTACK_MAP"
    DATASET_UPDATE = "DATASET_UPDATE"
    USER_QUERY = "USER_QUERY"
    SECURITY_ALERT = "SECURITY_ALERT"
    SCHEDULER = "SCHEDULER"
    IOC_CORRELATION = "IOC_CORRELATION"
    ATTACK_SIMULATION = "ATTACK_SIMULATION"


class SeverityLevel(str, Enum):
    """Severity levels for events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# Category color mapping for UI
CATEGORY_COLORS = {
    EventCategory.SYSTEM: "#3b82f6",  # blue
    EventCategory.RAG_PIPELINE: "#06b6d4",  # cyan
    EventCategory.AI_AGENT: "#8b5cf6",  # purple
    EventCategory.NETWORK_ANALYSIS: "#10b981",  # green
    EventCategory.THREAT_INTELLIGENCE: "#eab308",  # yellow
    EventCategory.VULNERABILITY_DETECTION: "#f97316",  # orange
    EventCategory.ATTACK_MAP: "#ef4444",  # red
    EventCategory.DATASET_UPDATE: "#14b8a6",  # teal
    EventCategory.USER_QUERY: "#a855f7",  # purple
    EventCategory.SECURITY_ALERT: "#dc2626",  # red
    EventCategory.SCHEDULER: "#6b7280",  # gray
    EventCategory.IOC_CORRELATION: "#ec4899",  # pink
    EventCategory.ATTACK_SIMULATION: "#f43f5e",  # rose
}


class ActivityEvent:
    """Represents a single activity log event."""
    
    def __init__(
        self,
        category: EventCategory,
        event_type: str,
        module: str,
        message: str,
        severity: SeverityLevel = SeverityLevel.INFO,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.category = category.value
        self.event_type = event_type
        self.module = module
        self.message = message
        self.severity = severity.value
        self.metadata = metadata or {}
        self.color = CATEGORY_COLORS.get(category, "#9ca3af")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "category": self.category,
            "event_type": self.event_type,
            "module": self.module,
            "message": self.message,
            "severity": self.severity,
            "metadata": self.metadata,
            "color": self.color,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActivityEvent":
        """Create event from dictionary."""
        event = cls(
            category=EventCategory(data["category"]),
            event_type=data["event_type"],
            module=data["module"],
            message=data["message"],
            severity=SeverityLevel(data["severity"]),
            metadata=data.get("metadata", {}),
        )
        event.id = data["id"]
        event.timestamp = data["timestamp"]
        event.color = data.get("color", "#9ca3af")
        return event


class ActivityLogger:
    """Centralized activity logger for SOC observability."""
    
    def __init__(
        self,
        log_dir: str = "./data/logs",
        max_memory_events: int = 1000,
        retention_days: int = 30,
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.max_memory_events = max_memory_events
        self.retention_days = retention_days
        
        # In-memory event buffer (circular buffer)
        self.events: deque = deque(maxlen=max_memory_events)
        
        # WebSocket callbacks for real-time streaming
        self.callbacks: Set[Callable] = set()
        self.callbacks_lock = threading.Lock()
        
        # Event filters for subscribers
        self.subscriber_filters: Dict[str, Dict[str, Any]] = {}
        
        # File paths
        self.activity_log_file = self.log_dir / "activity_log.json"
        self.security_alerts_file = self.log_dir / "security_alerts.json"
        
        # Load existing events
        self._load_events()
        
        logger.info("ActivityLogger initialized", log_dir=str(self.log_dir))
    
    def _load_events(self):
        """Load recent events from disk."""
        if self.activity_log_file.exists():
            try:
                with open(self.activity_log_file, "r") as f:
                    events_data = json.load(f)
                    for event_data in events_data[-self.max_memory_events:]:
                        self.events.append(ActivityEvent.from_dict(event_data))
                logger.info(f"Loaded {len(self.events)} events from disk")
            except Exception as e:
                logger.error(f"Failed to load events: {str(e)}")
    
    def _save_event(self, event: ActivityEvent):
        """Append event to log file."""
        try:
            # Append to activity log
            with open(self.activity_log_file, "a") as f:
                json.dump(event.to_dict(), f)
                f.write("\n")
            
            # Also save security alerts separately
            if event.category == EventCategory.SECURITY_ALERT:
                with open(self.security_alerts_file, "a") as f:
                    json.dump(event.to_dict(), f)
                    f.write("\n")
                    
        except Exception as e:
            logger.error(f"Failed to save event: {str(e)}")
    
    def log_event(
        self,
        category: EventCategory,
        event_type: str,
        module: str,
        message: str,
        severity: SeverityLevel = SeverityLevel.INFO,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ActivityEvent:
        """
        Log a new activity event.
        
        Args:
            category: Event category
            event_type: Type of event
            module: Module that generated the event
            message: Human-readable message
            severity: Event severity level
            metadata: Additional event metadata
            
        Returns:
            The created ActivityEvent
        """
        event = ActivityEvent(
            category=category,
            event_type=event_type,
            module=module,
            message=message,
            severity=severity,
            metadata=metadata,
        )
        
        # Add to memory buffer
        self.events.append(event)
        
        # Save to disk
        self._save_event(event)
        
        # Notify WebSocket subscribers
        self._notify_subscribers(event)
        
        # Log to structlog as well
        log_method = getattr(logger, severity.value, logger.info)
        log_method(
            f"[{category.value}] {event_type}",
            module=module,
            message=message,
            metadata=metadata,
        )
        
        return event
    
    def log_error(
        self,
        module: str,
        error_message: str,
        exception: Optional[Exception] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ActivityEvent:
        """Log an error event."""
        meta = metadata or {}
        if exception:
            meta["exception_type"] = type(exception).__name__
            meta["exception_message"] = str(exception)
        
        return self.log_event(
            category=EventCategory.SYSTEM,
            event_type="ERROR",
            module=module,
            message=error_message,
            severity=SeverityLevel.ERROR,
            metadata=meta,
        )
    
    def log_security_alert(
        self,
        alert_type: str,
        severity: SeverityLevel,
        details: Dict[str, Any],
    ) -> ActivityEvent:
        """Log a security alert."""
        return self.log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type=alert_type,
            module="security_monitor",
            message=f"Security alert: {alert_type}",
            severity=severity,
            metadata=details,
        )
    
    def _notify_subscribers(self, event: ActivityEvent):
        """Notify all WebSocket subscribers of new event."""
        with self.callbacks_lock:
            for callback in self.callbacks:
                try:
                    callback(event.to_dict())
                except Exception as e:
                    logger.error(f"Callback error: {str(e)}")
    
    def register_callback(self, callback: Callable):
        """Register a callback for real-time events."""
        with self.callbacks_lock:
            self.callbacks.add(callback)
    
    def unregister_callback(self, callback: Callable):
        """Unregister a callback."""
        with self.callbacks_lock:
            self.callbacks.discard(callback)
    
    def get_events(
        self,
        limit: int = 100,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        module: Optional[str] = None,
        event_type: Optional[str] = None,
        search_query: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get events with optional filtering.
        
        Args:
            limit: Maximum events to return
            category: Filter by category
            severity: Filter by severity
            module: Filter by module
            event_type: Filter by event type
            search_query: Search in message and metadata
            start_time: Filter events after this time
            end_time: Filter events before this time
            
        Returns:
            List of event dictionaries
        """
        filtered_events = list(self.events)
        
        # Apply filters
        if category:
            filtered_events = [e for e in filtered_events if e.category == category]
        
        if severity:
            filtered_events = [e for e in filtered_events if e.severity == severity]
        
        if module:
            filtered_events = [e for e in filtered_events if e.module == module]
        
        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        
        if search_query:
            query_lower = search_query.lower()
            filtered_events = [
                e for e in filtered_events
                if query_lower in e.message.lower() or
                   query_lower in json.dumps(e.metadata).lower()
            ]
        
        if start_time:
            filtered_events = [
                e for e in filtered_events if e.timestamp >= start_time
            ]
        
        if end_time:
            filtered_events = [
                e for e in filtered_events if e.timestamp <= end_time
            ]
        
        # Sort by timestamp (newest first) and limit
        filtered_events.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [e.to_dict() for e in filtered_events[:limit]]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get event statistics."""
        events = list(self.events)
        
        # Count by category
        by_category = {}
        for event in events:
            by_category[event.category] = by_category.get(event.category, 0) + 1
        
        # Count by severity
        by_severity = {}
        for event in events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
        
        # Count by module
        by_module = {}
        for event in events:
            by_module[event.module] = by_module.get(event.module, 0) + 1
        
        # Security alerts count
        security_alerts = [e for e in events if e.category == EventCategory.SECURITY_ALERT]
        
        # Recent activity (last hour)
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        recent_events = [e for e in events if e.timestamp >= one_hour_ago]
        
        return {
            "total_events": len(events),
            "by_category": by_category,
            "by_severity": by_severity,
            "by_module": by_module,
            "security_alerts": len(security_alerts),
            "recent_activity_1h": len(recent_events),
            "memory_buffer_size": self.max_memory_events,
        }
    
    def export_events(
        self,
        format: str = "json",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> str:
        """
        Export events to JSON or CSV format.
        
        Args:
            format: Export format (json or csv)
            start_time: Filter events after this time
            end_time: Filter events before this time
            
        Returns:
            Exported data as string
        """
        events = self.get_events(
            limit=10000,
            start_time=start_time,
            end_time=end_time,
        )
        
        if format.lower() == "csv":
            # CSV export
            import csv
            import io
            
            output = io.StringIO()
            fieldnames = ["id", "timestamp", "category", "event_type", "module", "message", "severity", "metadata"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            
            for event in events:
                writer.writerow(event)
            
            return output.getvalue()
        else:
            # JSON export
            return json.dumps(events, indent=2)
    
    def cleanup_old_events(self):
        """Remove events older than retention period."""
        cutoff = (datetime.utcnow() - timedelta(days=self.retention_days)).isoformat()
        
        # Filter out old events from memory
        self.events = deque(
            [e for e in self.events if e.timestamp >= cutoff],
            maxlen=self.max_memory_events,
        )
        
        # Cleanup log files (rewrite without old events)
        if self.activity_log_file.exists():
            events = [e.to_dict() for e in self.events]
            with open(self.activity_log_file, "w") as f:
                for event in events:
                    json.dump(event, f)
                    f.write("\n")
        
        logger.info(f"Cleaned up events older than {self.retention_days} days")


# Global activity logger instance
activity_logger = ActivityLogger()


# Convenience functions for direct logging
def log_event(
    category: EventCategory,
    event_type: str,
    module: str,
    message: str,
    severity: SeverityLevel = SeverityLevel.INFO,
    metadata: Optional[Dict[str, Any]] = None,
) -> ActivityEvent:
    """Log an event using the global logger."""
    return activity_logger.log_event(category, event_type, module, message, severity, metadata)


def log_error(
    module: str,
    error_message: str,
    exception: Optional[Exception] = None,
) -> ActivityEvent:
    """Log an error using the global logger."""
    return activity_logger.log_error(module, error_message, exception)


def log_security_alert(
    alert_type: str,
    severity: SeverityLevel,
    details: Dict[str, Any],
) -> ActivityEvent:
    """Log a security alert using the global logger."""
    return activity_logger.log_security_alert(alert_type, severity, details)
