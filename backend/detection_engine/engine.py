"""
Detection Engine
Local AI-Powered Security Operations Center

Rule-based threat detection, IOC matching, and anomaly detection.
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from collections import defaultdict
import structlog

from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class DetectionRule:
    """Security detection rule."""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: str = "medium",
        mitre_attack: Optional[List[str]] = None,
        response_actions: Optional[List[str]] = None,
        enabled: bool = True,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.condition = condition
        self.severity = severity
        self.mitre_attack = mitre_attack or []
        self.response_actions = response_actions or []
        self.enabled = enabled
        self.trigger_count = 0
        self.last_triggered: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack,
            "response_actions": self.response_actions,
            "enabled": self.enabled,
            "trigger_count": self.trigger_count,
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None,
        }


class SecurityAlert:
    """Generated security alert."""
    
    def __init__(
        self,
        rule: DetectionRule,
        event: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ):
        self.alert_id = f"alert_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.rule_id = rule.rule_id
        self.rule_name = rule.name
        self.severity = rule.severity
        self.event = event
        self.context = context or {}
        self.status = "new"  # new, investigating, resolved, false_positive
        self.assigned_to: Optional[str] = None
        self.mitre_attack = rule.mitre_attack
        self.response_actions = rule.response_actions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "event": self.event,
            "context": self.context,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "mitre_attack": self.mitre_attack,
            "response_actions": self.response_actions,
        }


class DetectionEngine:
    """Main detection engine for security threats."""
    
    def __init__(self, data_dir: str = "./data/detections"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Detection rules registry
        self.rules: Dict[str, DetectionRule] = {}
        
        # Active alerts
        self.alerts: Dict[str, SecurityAlert] = {}
        
        # Event window for correlation (last 5 minutes)
        self.event_window: List[Dict[str, Any]] = []
        self.window_duration = timedelta(minutes=5)
        
        # IOC database
        self.ioc_database: Dict[str, List[str]] = {
            "malicious_ip": [],
            "malicious_domain": [],
            "malicious_hash": [],
        }
        
        # Load built-in rules
        self._load_builtin_rules()
        
        logger.info("DetectionEngine initialized")
    
    def _load_builtin_rules(self):
        """Load built-in detection rules."""
        
        # Rule: Brute Force Detection
        self.register_rule(DetectionRule(
            rule_id="BRUTE_FORCE_001",
            name="SSH Brute Force Detection",
            description="Detect SSH brute force attempts (>20 failed logins in 60 seconds)",
            condition=self._check_brute_force,
            severity="high",
            mitre_attack=["T1110.001"],
            response_actions=["block_ip", "notify_soc"],
        ))
        
        # Rule: Port Scan Detection
        self.register_rule(DetectionRule(
            rule_id="PORT_SCAN_001",
            name="Port Scan Detection",
            description="Detect port scanning activity (>50 connections to different ports)",
            condition=self._check_port_scan,
            severity="medium",
            mitre_attack=["T1046"],
            response_actions=["alert", "log"],
        ))
        
        # Rule: Suspicious PowerShell
        self.register_rule(DetectionRule(
            rule_id="POWERSHELL_001",
            name="Suspicious PowerShell Execution",
            description="Detect suspicious PowerShell commands",
            condition=self._check_suspicious_powershell,
            severity="high",
            mitre_attack=["T1059.001"],
            response_actions=["isolate_host", "notify_soc"],
        ))
        
        # Rule: Malicious IP Connection
        self.register_rule(DetectionRule(
            rule_id="MALICIOUS_IP_001",
            name="Malicious IP Connection",
            description="Detect connection to known malicious IP",
            condition=self._check_malicious_ip,
            severity="critical",
            mitre_attack=["T1071"],
            response_actions=["block_ip", "isolate_host"],
        ))
        
        # Rule: Data Exfiltration Pattern
        self.register_rule(DetectionRule(
            rule_id="EXFIL_001",
            name="Potential Data Exfiltration",
            description="Detect large outbound data transfer",
            condition=self._check_data_exfiltration,
            severity="critical",
            mitre_attack=["T1041"],
            response_actions=["block_connection", "notify_soc"],
        ))
        
        # Rule: Privilege Escalation
        self.register_rule(DetectionRule(
            rule_id="PRIVESC_001",
            name="Privilege Escalation Attempt",
            description="Detect privilege escalation attempts",
            condition=self._check_privilege_escalation,
            severity="high",
            mitre_attack=["T1068"],
            response_actions=["alert", "log"],
        ))
        
        # Rule: IDS Alert
        self.register_rule(DetectionRule(
            rule_id="IDS_ALERT_001",
            name="IDS/IPS Alert",
            description="Process IDS/IPS alerts",
            condition=self._check_ids_alert,
            severity="high",
            mitre_attack=[],
            response_actions=["alert", "log"],
        ))
        
        logger.info(f"Loaded {len(self.rules)} built-in detection rules")
    
    def register_rule(self, rule: DetectionRule):
        """Register a detection rule."""
        self.rules[rule.rule_id] = rule
        logger.info(f"Registered detection rule: {rule.rule_id}")
    
    def process_event(self, event: Dict[str, Any]) -> List[SecurityAlert]:
        """
        Process a single event through all detection rules.
        
        Args:
            event: Normalized security event
            
        Returns:
            List of triggered alerts
        """
        triggered_alerts = []
        
        # Add to event window
        self.event_window.append(event)
        self._cleanup_event_window()
        
        # Check each rule
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            try:
                if rule.condition(event, self.event_window):
                    alert = self._create_alert(rule, event)
                    triggered_alerts.append(alert)
                    self.alerts[alert.alert_id] = alert
                    
                    # Log the detection
                    log_event(
                        category=EventCategory.SECURITY_ALERT,
                        event_type="DETECTION_TRIGGERED",
                        module="detection_engine",
                        message=f"Alert triggered: {rule.name}",
                        severity=SeverityLevel(rule.severity),
                        metadata={
                            "rule_id": rule.rule_id,
                            "alert_id": alert.alert_id,
                            "source_ip": event.get('source_ip'),
                        },
                    )
                    
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} failed: {str(e)}")
        
        return triggered_alerts
    
    def process_batch(self, events: List[Dict[str, Any]]) -> List[SecurityAlert]:
        """
        Process a batch of events.
        
        Args:
            events: List of normalized events
            
        Returns:
            List of all triggered alerts
        """
        all_alerts = []
        
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
        
        logger.info(f"Processed {len(events)} events, triggered {len(all_alerts)} alerts")
        return all_alerts
    
    def _check_brute_force(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for brute force attack pattern."""
        if event.get('event_type') != 'LOGIN_FAILURE':
            return False
        
        source_ip = event.get('source_ip')
        if not source_ip:
            return False
        
        # Count failed logins from same IP in window
        cutoff = datetime.utcnow() - timedelta(seconds=60)
        failed_count = sum(
            1 for e in window
            if e.get('source_ip') == source_ip and
               e.get('event_type') == 'LOGIN_FAILURE' and
               datetime.fromisoformat(e.get('timestamp', '').replace('Z', '+00:00').replace('+00:00', '')) > cutoff
        )
        
        return failed_count >= 20
    
    def _check_port_scan(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for port scanning activity."""
        source_ip = event.get('source_ip')
        if not source_ip:
            return False
        
        # Count unique destination ports from same source
        dest_ports = set()
        for e in window:
            if e.get('source_ip') == source_ip and e.get('destination_port'):
                dest_ports.add(e.get('destination_port'))
        
        return len(dest_ports) >= 50
    
    def _check_suspicious_powershell(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for suspicious PowerShell execution."""
        command = event.get('command', '').lower()
        process = event.get('process', '').lower()
        
        if 'powershell' not in process and 'powershell' not in command:
            return False
        
        # Suspicious patterns
        suspicious_patterns = [
            r'encodedcommand',
            r'-enc\s+',
            r'bypass',
            r'hidden',
            r'windowstyle\s+hidden',
            r'downloadstring',
            r'invoke-expression',
            r'iex\s+',
            r'frombase64',
            r'mimikatz',
            r'credential',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        
        return False
    
    def _check_malicious_ip(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for connection to malicious IP."""
        dest_ip = event.get('destination_ip') or event.get('source_ip')
        if not dest_ip:
            return False
        
        return dest_ip in self.ioc_database.get('malicious_ip', [])
    
    def _check_data_exfiltration(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for potential data exfiltration."""
        # Check for large outbound transfers
        bytes_sent = event.get('bytes_out', 0)
        if bytes_sent > 100 * 1024 * 1024:  # 100MB
            return True
        
        # Check for unusual destinations
        dest_ip = event.get('destination_ip')
        if dest_ip:
            # Check if destination is external (not private IP)
            if not dest_ip.startswith(('10.', '192.168.', '172.')):
                # Check for large transfer to external IP
                total_bytes = sum(
                    e.get('bytes_out', 0) for e in window
                    if e.get('destination_ip') == dest_ip
                )
                if total_bytes > 500 * 1024 * 1024:  # 500MB
                    return True
        
        return False
    
    def _check_privilege_escalation(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for privilege escalation attempts."""
        event_type = event.get('event_type', '').upper()
        
        if event_type in ['PRIVILEGE_ESCALATION', 'SUDO', 'SU']:
            return True
        
        command = event.get('command', '').lower()
        if any(word in command for word in ['sudo', 'su ', 'chmod 777', 'chown root']):
            return True
        
        return False
    
    def _check_ids_alert(self, event: Dict[str, Any], window: List[Dict[str, Any]]) -> bool:
        """Check for IDS/IPS alerts."""
        return event.get('source_type') == 'ids' or event.get('event_type') == 'IDS_ALERT'
    
    def _create_alert(self, rule: DetectionRule, event: Dict[str, Any]) -> SecurityAlert:
        """Create a security alert from triggered rule."""
        rule.trigger_count += 1
        rule.last_triggered = datetime.utcnow()
        
        # Gather context from event window
        context = self._gather_context(event)
        
        return SecurityAlert(
            rule=rule,
            event=event,
            context=context,
        )
    
    def _gather_context(self, trigger_event: Dict[str, Any]) -> Dict[str, Any]:
        """Gather related events for context."""
        source_ip = trigger_event.get('source_ip')
        host = trigger_event.get('host')
        
        context = {
            "related_events": [],
            "source_ip_events": 0,
            "host_events": 0,
        }
        
        for event in self.event_window[-100:]:  # Last 100 events
            if event.get('source_ip') == source_ip:
                context["source_ip_events"] += 1
                if len(context["related_events"]) < 10:
                    context["related_events"].append({
                        "timestamp": event.get('timestamp'),
                        "event_type": event.get('event_type'),
                        "message": event.get('message', '')[:100],
                    })
            
            if event.get('host') == host:
                context["host_events"] += 1
        
        return context
    
    def _cleanup_event_window(self):
        """Remove old events from window."""
        cutoff = datetime.utcnow() - self.window_duration
        
        self.event_window = [
            e for e in self.event_window
            if datetime.fromisoformat(e.get('timestamp', '').replace('Z', '+00:00').replace('+00:00', '')) > cutoff
        ]
    
    def load_ioc_database(self, ioc_file: str):
        """
        Load IOC database from file.
        
        Args:
            ioc_file: Path to IOC JSON file
        """
        try:
            with open(ioc_file, 'r') as f:
                data = json.load(f)
                
            self.ioc_database.update(data)
            
            logger.info(
                "Loaded IOC database",
                malicious_ips=len(self.ioc_database.get('malicious_ip', [])),
                malicious_domains=len(self.ioc_database.get('malicious_domain', [])),
            )
        except Exception as e:
            logger.error(f"Failed to load IOC database: {str(e)}")
    
    def add_ioc(self, ioc_type: str, value: str):
        """
        Add an IOC to the database.
        
        Args:
            ioc_type: Type of IOC (malicious_ip, malicious_domain, malicious_hash)
            value: IOC value
        """
        if ioc_type in self.ioc_database:
            if value not in self.ioc_database[ioc_type]:
                self.ioc_database[ioc_type].append(value)
                logger.info(f"Added IOC: {ioc_type}={value}")
    
    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Get alerts with optional filtering.
        
        Args:
            status: Filter by status
            severity: Filter by severity
            limit: Maximum alerts to return
            
        Returns:
            List of alert dictionaries
        """
        alerts = list(self.alerts.values())
        
        if status:
            alerts = [a for a in alerts if a.status == status]
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [a.to_dict() for a in alerts[:limit]]
    
    def resolve_alert(self, alert_id: str, resolution: str = "resolved"):
        """
        Resolve an alert.
        
        Args:
            alert_id: Alert ID to resolve
            resolution: Resolution status (resolved, false_positive)
        """
        if alert_id in self.alerts:
            self.alerts[alert_id].status = resolution
            logger.info(f"Resolved alert {alert_id} as {resolution}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics."""
        alerts_by_severity = defaultdict(int)
        alerts_by_status = defaultdict(int)
        
        for alert in self.alerts.values():
            alerts_by_severity[alert.severity] += 1
            alerts_by_status[alert.status] += 1
        
        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "total_alerts": len(self.alerts),
            "alerts_by_severity": dict(alerts_by_severity),
            "alerts_by_status": dict(alerts_by_status),
            "event_window_size": len(self.event_window),
            "ioc_count": sum(len(v) for v in self.ioc_database.values()),
        }
    
    def save_alerts(self):
        """Save alerts to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"alerts_{timestamp}.json"
        
        alerts_data = [a.to_dict() for a in self.alerts.values()]
        
        with open(filename, 'w') as f:
            json.dump(alerts_data, f, indent=2)
        
        logger.info(f"Saved {len(alerts_data)} alerts to {filename}")


# Global detection engine instance
detection_engine = DetectionEngine()
