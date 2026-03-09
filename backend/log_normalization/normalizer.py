"""
Log Normalization Engine
Local AI-Powered Security Operations Center

Converts raw logs from multiple sources into standardized Common Event Format (CEF).
"""

import re
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path
import structlog

logger = structlog.get_logger()


class NormalizedEvent:
    """Standardized security event format."""
    
    def __init__(self):
        self.event_id: str = ""
        self.timestamp: str = ""
        self.source_type: str = ""  # syslog, firewall, ids, dns, endpoint
        self.severity: str = "info"  # debug, info, warning, error, critical
        self.host: str = ""
        self.source_ip: Optional[str] = None
        self.destination_ip: Optional[str] = None
        self.source_port: Optional[int] = None
        self.destination_port: Optional[int] = None
        self.protocol: Optional[str] = None
        self.username: Optional[str] = None
        self.process: Optional[str] = None
        self.command: Optional[str] = None
        self.action: Optional[str] = None  # ALLOW, BLOCK, DROP, etc.
        self.event_type: Optional[str] = None
        self.signature: Optional[str] = None
        self.message: str = ""
        self.raw_log: str = ""
        self.metadata: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "severity": self.severity,
            "host": self.host,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "process": self.process,
            "command": self.command,
            "action": self.action,
            "event_type": self.event_type,
            "signature": self.signature,
            "message": self.message,
            "raw_log": self.raw_log,
            "metadata": self.metadata,
        }
    
    def generate_id(self):
        """Generate unique event ID."""
        content = f"{self.timestamp}{self.raw_log}"
        self.event_id = f"evt_{hashlib.md5(content.encode()).hexdigest()[:12]}"
        return self.event_id


class LogNormalizer:
    """Normalizes logs from various sources into CEF format."""
    
    def __init__(self):
        # Regex patterns for parsing
        self.syslog_pattern = re.compile(
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
        )
        
        self.ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        self.port_pattern = re.compile(r'(?:DPT|SPT|port)[=:]?(\d+)')
        self.proto_pattern = re.compile(r'(?:PROTO|protocol)[=:]?(\w+)')
        
        logger.info("LogNormalizer initialized")
    
    def normalize_syslog(self, raw_log: str) -> Optional[NormalizedEvent]:
        """Normalize syslog entry."""
        event = NormalizedEvent()
        event.source_type = "syslog"
        event.raw_log = raw_log
        event.timestamp = datetime.utcnow().isoformat() + "Z"
        
        match = self.syslog_pattern.match(raw_log)
        if match:
            event.host = match.group('host')
            event.process = match.group('process')
            event.message = match.group('message')
            
            # Detect severity from message content
            event.severity = self._detect_syslog_severity(event.message)
            
            # Extract IPs if present
            ips = self.ip_pattern.findall(raw_log)
            if ips:
                event.source_ip = ips[0]
                if len(ips) > 1:
                    event.destination_ip = ips[1]
            
            # Detect event type
            event.event_type = self._detect_syslog_event_type(event.message)
        else:
            event.message = raw_log
        
        event.generate_id()
        return event
    
    def _detect_syslog_severity(self, message: str) -> str:
        """Detect severity from syslog message."""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['failed', 'failure', 'error', 'denied']):
            return 'warning'
        elif any(word in message_lower for word in ['critical', 'emergency', 'alert']):
            return 'critical'
        elif any(word in message_lower for word in ['warning', 'warn']):
            return 'warning'
        
        return 'info'
    
    def _detect_syslog_event_type(self, message: str) -> Optional[str]:
        """Detect event type from syslog message."""
        message_lower = message.lower()
        
        if 'sshd' in message_lower and 'accepted' in message_lower:
            return 'LOGIN_SUCCESS'
        elif 'sshd' in message_lower and 'failed' in message_lower:
            return 'LOGIN_FAILURE'
        elif 'sudo' in message_lower:
            return 'PRIVILEGE_ESCALATION'
        elif 'ufw' in message_lower or 'block' in message_lower:
            return 'FIREWALL_BLOCK'
        elif 'cron' in message_lower:
            return 'SCHEDULED_TASK'
        
        return None
    
    def normalize_firewall(self, raw_log: str) -> Optional[NormalizedEvent]:
        """Normalize firewall log entry."""
        event = NormalizedEvent()
        event.source_type = "firewall"
        event.raw_log = raw_log
        event.timestamp = datetime.utcnow().isoformat() + "Z"
        event.action = "ALLOW"  # Default
        
        # Detect action
        if any(word in raw_log.upper() for word in ['BLOCK', 'DROP', 'REJECT', 'DENY']):
            event.action = "BLOCK"
            event.severity = "warning"
        
        # Extract IPs
        ips = self.ip_pattern.findall(raw_log)
        if ips:
            event.source_ip = ips[0]
            if len(ips) > 1:
                event.destination_ip = ips[1]
        
        # Extract ports
        ports = self.port_pattern.findall(raw_log)
        if ports:
            event.destination_port = int(ports[0])
        
        # Extract protocol
        proto_match = self.proto_pattern.search(raw_log)
        if proto_match:
            event.protocol = proto_match.group(1)
        
        event.message = raw_log
        event.event_type = "FIREWALL_EVENT"
        event.generate_id()
        
        return event
    
    def normalize_ids_alert(self, raw_log: str) -> Optional[NormalizedEvent]:
        """Normalize IDS/IPS alert."""
        event = NormalizedEvent()
        event.source_type = "ids"
        event.raw_log = raw_log
        event.timestamp = datetime.utcnow().isoformat() + "Z"
        event.severity = "warning"
        event.event_type = "IDS_ALERT"
        
        # Extract signature if present
        sig_patterns = [
            r'\[.*?\]\s+(.*?)(?:\[|\||$)',
            r'signature:\s*(.*?)(?:\n|$)',
            r'alert:\s*(.*?)(?:\n|$)',
        ]
        
        for pattern in sig_patterns:
            match = re.search(pattern, raw_log, re.IGNORECASE)
            if match:
                event.signature = match.group(1).strip()
                break
        
        # Extract IPs
        ips = self.ip_pattern.findall(raw_log)
        if ips:
            event.source_ip = ips[0]
            if len(ips) > 1:
                event.destination_ip = ips[1]
        
        # Detect severity from content
        if any(word in raw_log.lower() for word in ['critical', 'emergency', 'high']):
            event.severity = "critical"
        elif 'medium' in raw_log.lower():
            event.severity = "warning"
        
        event.message = event.signature or raw_log
        event.generate_id()
        
        return event
    
    def normalize_dns(self, raw_log: str) -> Optional[NormalizedEvent]:
        """Normalize DNS query log."""
        event = NormalizedEvent()
        event.source_type = "dns"
        event.raw_log = raw_log
        event.timestamp = datetime.utcnow().isoformat() + "Z"
        event.severity = "info"
        event.event_type = "DNS_QUERY"
        
        # Extract client IP
        ip_match = re.search(r'client(?:[@\s]+)(\d+\.\d+\.\d+\.\d+)', raw_log, re.IGNORECASE)
        if ip_match:
            event.source_ip = ip_match.group(1)
        
        # Extract query domain
        domain_match = re.search(r'query:?\s*([^\s]+)', raw_log, re.IGNORECASE)
        if domain_match:
            event.message = f"DNS query for {domain_match.group(1)}"
            event.metadata['query_domain'] = domain_match.group(1)
            
            # Check for suspicious domains
            domain = domain_match.group(1).lower()
            if self._is_suspicious_domain(domain):
                event.severity = "warning"
                event.metadata['suspicious'] = True
        
        # Extract query type
        type_match = re.search(r'\b(A|AAAA|MX|TXT|CNAME|NS|PTR|SOA)\b', raw_log)
        if type_match:
            event.metadata['query_type'] = type_match.group(1)
        
        event.generate_id()
        return event
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious."""
        # Check for known suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.gq', '.ml', '.cf', '.tk', '.ga']
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Check for very long domain (possible DGA)
        if len(domain) > 50:
            return True
        
        # Check for high entropy (random-looking)
        name_part = domain.split('.')[0]
        if len(name_part) > 15 and len(set(name_part)) / len(name_part) > 0.7:
            return True
        
        return False
    
    def normalize_endpoint(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        """Normalize endpoint security event."""
        event = NormalizedEvent()
        event.source_type = "endpoint"
        event.raw_log = json.dumps(raw_event)
        event.timestamp = raw_event.get('timestamp', datetime.utcnow().isoformat() + "Z")
        event.severity = "info"
        
        # Map fields
        event.host = raw_event.get('hostname', '')
        event.username = raw_event.get('username')
        event.process = raw_event.get('process_name')
        event.command = raw_event.get('command_line')
        event.event_type = raw_event.get('event_type', 'ENDPOINT_EVENT').upper()
        
        # Extract IPs if network event
        if 'dst_ip' in raw_event:
            event.destination_ip = raw_event['dst_ip']
            event.destination_port = raw_event.get('dst_port')
            event.protocol = raw_event.get('protocol')
        
        # Detect severity based on event type
        if event.event_type in ['PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS']:
            event.severity = "warning"
        elif event.event_type in ['MALWARE_DETECTED', 'RANSOMWARE_DETECTED']:
            event.severity = "critical"
        
        event.message = raw_event.get('raw', f"Endpoint event: {event.event_type}")
        event.metadata = {k: v for k, v in raw_event.items() 
                         if k not in ['timestamp', 'hostname', 'username', 'raw']}
        event.generate_id()
        
        return event
    
    def normalize_batch(self, events: List[Dict[str, Any]], source_type: str) -> List[Dict[str, Any]]:
        """
        Normalize a batch of events.
        
        Args:
            events: List of raw events
            source_type: Type of log source
            
        Returns:
            List of normalized events
        """
        normalized = []
        
        for event in events:
            try:
                if source_type == "syslog":
                    norm_event = self.normalize_syslog(event.get('raw', str(event)))
                elif source_type == "firewall":
                    norm_event = self.normalize_firewall(event.get('raw', str(event)))
                elif source_type == "ids":
                    norm_event = self.normalize_ids_alert(event.get('raw', str(event)))
                elif source_type == "dns":
                    norm_event = self.normalize_dns(event.get('raw', str(event)))
                elif source_type == "endpoint":
                    norm_event = self.normalize_endpoint(event)
                else:
                    norm_event = None
                
                if norm_event:
                    normalized.append(norm_event.to_dict())
                    
            except Exception as e:
                logger.error(f"Failed to normalize event: {str(e)}")
        
        logger.info(f"Normalized {len(normalized)} {source_type} events")
        return normalized


# Global normalizer instance
log_normalizer = LogNormalizer()
