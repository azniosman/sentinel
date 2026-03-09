"""
Endpoint Monitoring Module (EDR-lite)
Local AI-Powered Security Operations Center

Monitors endpoint activity for suspicious behavior.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from collections import defaultdict
import structlog

from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class EndpointEvent:
    """Endpoint security event."""
    
    def __init__(
        self,
        event_id: str,
        timestamp: str,
        hostname: str,
        event_type: str,
        username: Optional[str],
        process_name: Optional[str],
        process_id: Optional[int],
        parent_process: Optional[str],
        command_line: Optional[str],
        file_path: Optional[str],
        network_connection: Optional[Dict[str, Any]],
        severity: str = "info",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.hostname = hostname
        self.event_type = event_type
        self.username = username
        self.process_name = process_name
        self.process_id = process_id
        self.parent_process = parent_process
        self.command_line = command_line
        self.file_path = file_path
        self.network_connection = network_connection
        self.severity = severity
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "username": self.username,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process": self.parent_process,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "network_connection": self.network_connection,
            "severity": self.severity,
            "metadata": self.metadata,
        }


class EndpointMonitor:
    """Monitor endpoint activity for threats."""
    
    def __init__(self, data_dir: str = "./data/endpoint"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Endpoint events buffer
        self.events: List[EndpointEvent] = []
        self.max_events = 10000
        
        # Process baseline
        self.known_processes: Set[str] = set()
        self.process_counts: Dict[str, int] = defaultdict(int)
        
        # Suspicious indicators
        self.suspicious_processes = {
            'mimikatz', 'pwdump', 'procdump', 'lazagne', 'bloodhound',
            'empire', 'cobalt', 'metasploit', 'meterpreter', 'psexec',
            'wmic', 'vssadmin', 'bcdedit', 'wevtutil', 'nltest',
        }
        
        self.suspicious_commands = [
            'invoke-mimikatz', 'sekurlsa', 'lsadump',
            'bypass -executionpolicy', 'frombase64', 'downloadstring',
            'invoke-expression', 'iex ', 'add-mppreference',
            'set-mppreference -disablerealtimemonitoring',
            'netsh advfirewall', 'reg add', 'schtasks /create',
        ]
        
        # File monitoring
        self.suspicious_paths = [
            '/temp/', '/tmp/', 'appdata', 'programdata',
            'startup', 'schedule', 'services',
        ]
        
        logger.info("EndpointMonitor initialized")
    
    def process_event(self, event_data: Dict[str, Any]) -> Optional[EndpointEvent]:
        """
        Process an endpoint event.
        
        Args:
            event_data: Raw endpoint event data
            
        Returns:
            EndpointEvent if processed, None otherwise
        """
        # Generate event ID
        event_id = f"ep_{hashlib.md5(f'{event_data}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12]}"
        
        event = EndpointEvent(
            event_id=event_id,
            timestamp=event_data.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            hostname=event_data.get('hostname', 'unknown'),
            event_type=event_data.get('event_type', 'UNKNOWN'),
            username=event_data.get('username'),
            process_name=event_data.get('process_name'),
            process_id=event_data.get('process_id'),
            parent_process=event_data.get('parent_process'),
            command_line=event_data.get('command_line'),
            file_path=event_data.get('file_path'),
            network_connection=event_data.get('network_connection'),
            metadata=event_data.get('metadata', {}),
        )
        
        # Analyze event for threats
        threat_indicators = self._analyze_event(event)
        
        if threat_indicators:
            event.severity = threat_indicators.get('severity', 'warning')
            event.metadata['threat_indicators'] = threat_indicators
            
            # Log the detection
            log_event(
                category=EventCategory.SECURITY_ALERT,
                event_type="ENDPOINT_THREAT_DETECTED",
                module="endpoint_monitor",
                message=f"Endpoint threat detected on {event.hostname}",
                severity=SeverityLevel(event.severity),
                metadata={
                    "hostname": event.hostname,
                    "process": event.process_name,
                    "indicators": threat_indicators,
                },
            )
        
        # Store event
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)
        
        # Update baseline
        if event.process_name:
            self.known_processes.add(event.process_name.lower())
            self.process_counts[event.process_name.lower()] += 1
        
        return event
    
    def _analyze_event(self, event: EndpointEvent) -> Optional[Dict[str, Any]]:
        """
        Analyze endpoint event for threats.
        
        Returns:
            Threat indicators if detected, None otherwise
        """
        indicators = {
            'suspicious_process': False,
            'suspicious_command': False,
            'suspicious_path': False,
            'rare_process': False,
            'persistence_mechanism': False,
            'credential_access': False,
            'defense_evasion': False,
        }
        
        severity = 'info'
        
        # Check process name
        if event.process_name:
            process_lower = event.process_name.lower()
            
            # Known malicious tools
            if any(sus in process_lower for sus in self.suspicious_processes):
                indicators['suspicious_process'] = True
                severity = 'critical'
            
            # Rare process
            if self.process_counts.get(process_lower, 0) <= 2:
                indicators['rare_process'] = True
                if severity == 'info':
                    severity = 'low'
        
        # Check command line
        if event.command_line:
            command_lower = event.command_line.lower()
            
            # Suspicious commands
            if any(sus in command_lower for sus in self.suspicious_commands):
                indicators['suspicious_command'] = True
                severity = 'high'
            
            # Encoded commands
            if '-enc' in command_lower or 'frombase64' in command_lower:
                indicators['defense_evasion'] = True
                severity = 'high'
            
            # Credential access
            if any(cred in command_lower for cred in ['lsass', 'sam', 'ntds', 'credential', 'password']):
                indicators['credential_access'] = True
                severity = 'critical'
        
        # Check file path
        if event.file_path:
            path_lower = event.file_path.lower()
            
            if any(sus in path_lower for sus in self.suspicious_paths):
                indicators['suspicious_path'] = True
                if severity == 'info':
                    severity = 'low'
        
        # Check for persistence mechanisms
        if event.event_type in ['SCHEDULED_TASK_CREATED', 'SERVICE_CREATED', 'REGISTRY_MODIFIED']:
            indicators['persistence_mechanism'] = True
            if severity == 'info':
                severity = 'medium'
        
        # Check for defense evasion
        if event.event_type in ['LOG_CLEARED', 'SERVICE_STOPPED', 'PROCESS_TERMINATED']:
            indicators['defense_evasion'] = True
            if severity == 'info':
                severity = 'medium'
        
        # Return indicators if any detected
        if any(v for k, v in indicators.items() if k != 'rare_process'):
            indicators['severity'] = severity
            return indicators
        
        return None
    
    def get_events(
        self,
        hostname: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get endpoint events."""
        events = self.events
        
        if hostname:
            events = [e for e in events if e.hostname == hostname]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if severity:
            events = [e for e in events if e.severity == severity]
        
        # Sort by timestamp (newest first)
        events.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [e.to_dict() for e in events[:limit]]
    
    def get_host_summary(self, hostname: str) -> Dict[str, Any]:
        """Get summary for a specific host."""
        host_events = [e for e in self.events if e.hostname == hostname]
        
        if not host_events:
            return {"error": "No events for host"}
        
        # Count by severity
        by_severity = {}
        for event in host_events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
        
        # Top processes
        process_counts = defaultdict(int)
        for event in host_events:
            if event.process_name:
                process_counts[event.process_name] += 1
        
        top_processes = sorted(
            process_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        
        # Users
        users = set(e.username for e in host_events if e.username)
        
        return {
            "hostname": hostname,
            "total_events": len(host_events),
            "by_severity": by_severity,
            "top_processes": top_processes,
            "users": list(users),
            "first_event": host_events[-1].timestamp if host_events else None,
            "last_event": host_events[0].timestamp if host_events else None,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get endpoint monitoring statistics."""
        by_severity = {}
        by_type = {}
        hosts = set()
        
        for event in self.events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
            hosts.add(event.hostname)
        
        threat_events = [
            e for e in self.events
            if e.metadata.get('threat_indicators')
        ]
        
        return {
            "total_events": len(self.events),
            "by_severity": by_severity,
            "by_type": by_type,
            "hosts_monitored": len(hosts),
            "threat_events": len(threat_events),
            "known_processes": len(self.known_processes),
        }
    
    def save_events(self):
        """Save events to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"endpoint_events_{timestamp}.json"
        
        events_data = [e.to_dict() for e in self.events[-1000:]]
        
        with open(filename, 'w') as f:
            json.dump(events_data, f, indent=2)
        
        logger.info(f"Saved {len(events_data)} endpoint events to {filename}")


# Global endpoint monitor instance
endpoint_monitor = EndpointMonitor()
