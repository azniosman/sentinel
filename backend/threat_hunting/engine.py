"""
Threat Hunting Engine
Local AI-Powered Security Operations Center

Proactive threat hunting queries and anomaly detection.
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


class HuntQuery:
    """Threat hunting query definition."""
    
    def __init__(
        self,
        query_id: str,
        name: str,
        description: str,
        query: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]],
        severity: str = "medium",
        mitre_attack: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ):
        self.query_id = query_id
        self.name = name
        self.description = description
        self.query = query
        self.severity = severity
        self.mitre_attack = mitre_attack or []
        self.tags = tags or []
        self.run_count = 0
        self.last_run: Optional[datetime] = None
        self.findings_count = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "query_id": self.query_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
            "run_count": self.run_count,
            "findings_count": self.findings_count,
            "last_run": self.last_run.isoformat() if self.last_run else None,
        }


class ThreatHuntingEngine:
    """Engine for proactive threat hunting."""
    
    def __init__(self, data_dir: str = "./data/threat_hunting"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Hunt queries registry
        self.queries: Dict[str, HuntQuery] = {}
        
        # Hunt findings
        self.findings: Dict[str, List[Dict[str, Any]]] = {}
        
        # Load built-in hunt queries
        self._load_builtin_queries()
        
        logger.info("ThreatHuntingEngine initialized")
    
    def _load_builtin_queries(self):
        """Load built-in threat hunting queries."""
        
        # Query: Unusual Outbound Traffic
        self.register_query(HuntQuery(
            query_id="HUNT_001",
            name="Unusual Outbound Traffic",
            description="Detect hosts with unusual outbound data transfer patterns",
            query=self._hunt_unusual_outbound,
            severity="high",
            mitre_attack=["T1041", "T1048"],
            tags=["exfiltration", "network", "data-theft"],
        ))
        
        # Query: Rare Process Execution
        self.register_query(HuntQuery(
            query_id="HUNT_002",
            name="Rare Process Execution",
            description="Detect execution of rare or unusual processes",
            query=self._hunt_rare_processes,
            severity="medium",
            mitre_attack=["T1059"],
            tags=["execution", "endpoint", "anomaly"],
        ))
        
        # Query: Encoded PowerShell Commands
        self.register_query(HuntQuery(
            query_id="HUNT_003",
            name="Encoded PowerShell Commands",
            description="Detect base64 encoded PowerShell execution",
            query=self._hunt_encoded_powershell,
            severity="high",
            mitre_attack=["T1059.001", "T1140"],
            tags=["powershell", "execution", "obfuscation"],
        ))
        
        # Query: Lateral Movement Patterns
        self.register_query(HuntQuery(
            query_id="HUNT_004",
            name="Lateral Movement Patterns",
            description="Detect potential lateral movement activity",
            query=self._hunt_lateral_movement,
            severity="critical",
            mitre_attack=["T1021", "T1570"],
            tags=["lateral-movement", "network", "credentials"],
        ))
        
        # Query: Credential Access Attempts
        self.register_query(HuntQuery(
            query_id="HUNT_005",
            name="Credential Access Attempts",
            description="Detect credential dumping and access attempts",
            query=self._hunt_credential_access,
            severity="critical",
            mitre_attack=["T1003", "T1555"],
            tags=["credentials", "lsass", "dumping"],
        ))
        
        # Query: Persistence Mechanisms
        self.register_query(HuntQuery(
            query_id="HUNT_006",
            name="Persistence Mechanisms",
            description="Detect persistence mechanism installation",
            query=self._hunt_persistence,
            severity="high",
            mitre_attack=["T1053", "T1543", "T1547"],
            tags=["persistence", "scheduled-task", "registry"],
        ))
        
        # Query: Defense Evasion Techniques
        self.register_query(HuntQuery(
            query_id="HUNT_007",
            name="Defense Evasion Techniques",
            description="Detect defense evasion attempts",
            query=self._hunt_defense_evasion,
            severity="high",
            mitre_attack=["T1070", "T1562"],
            tags=["evasion", "logging", "defense"],
        ))
        
        # Query: Command & Control Communication
        self.register_query(HuntQuery(
            query_id="HUNT_008",
            name="C2 Communication Patterns",
            description="Detect potential command and control communication",
            query=self._hunt_c2_communication,
            severity="critical",
            mitre_attack=["T1071", "T1573"],
            tags=["c2", "network", "beacon"],
        ))
        
        logger.info(f"Loaded {len(self.queries)} hunt queries")
    
    def register_query(self, query: HuntQuery):
        """Register a hunt query."""
        self.queries[query.query_id] = query
        logger.info(f"Registered hunt query: {query.query_id}")
    
    def run_hunt(self, query_id: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run a specific hunt query against events.
        
        Args:
            query_id: ID of hunt query to run
            events: List of normalized events to analyze
            
        Returns:
            List of findings
        """
        if query_id not in self.queries:
            logger.error(f"Hunt query not found: {query_id}")
            return []
        
        query = self.queries[query_id]
        
        try:
            # Execute hunt query
            findings = query.query(events)
            
            # Update query stats
            query.run_count += 1
            query.last_run = datetime.utcnow()
            query.findings_count += len(findings)
            
            # Store findings
            if query_id not in self.findings:
                self.findings[query_id] = []
            self.findings[query_id].extend(findings)
            
            # Log findings
            if findings:
                log_event(
                    category=EventCategory.SECURITY_ALERT,
                    event_type="THREAT_HUNT_FINDING",
                    module="threat_hunting",
                    message=f"Hunt '{query.name}' found {len(findings)} findings",
                    severity=SeverityLevel(query.severity),
                    metadata={
                        "query_id": query_id,
                        "findings_count": len(findings),
                    },
                )
            
            logger.info(f"Hunt {query_id} completed: {len(findings)} findings")
            return findings
            
        except Exception as e:
            logger.error(f"Hunt query {query_id} failed: {str(e)}")
            return []
    
    def run_all_hunts(self, events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run all hunt queries against events.
        
        Args:
            events: List of normalized events
            
        Returns:
            Dictionary of query_id -> findings
        """
        all_findings = {}
        
        for query_id in self.queries:
            findings = self.run_hunt(query_id, events)
            if findings:
                all_findings[query_id] = findings
        
        return all_findings
    
    # ============== Hunt Query Implementations ==============
    
    def _hunt_unusual_outbound(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual outbound traffic patterns."""
        findings = []
        
        # Group outbound traffic by destination IP
        outbound_by_dest = defaultdict(list)
        
        for event in events:
            if event.get('source_type') in ['firewall', 'network']:
                dest_ip = event.get('destination_ip')
                if dest_ip and not dest_ip.startswith(('10.', '192.168.', '172.')):
                    outbound_by_dest[dest_ip].append(event)
        
        # Find destinations with high traffic volume
        for dest_ip, dest_events in outbound_by_dest.items():
            total_bytes = sum(e.get('bytes_out', 0) for e in dest_events)
            
            if total_bytes > 100 * 1024 * 1024:  # 100MB threshold
                findings.append({
                    "finding_type": "unusual_outbound",
                    "severity": "high",
                    "destination_ip": dest_ip,
                    "event_count": len(dest_events),
                    "total_bytes": total_bytes,
                    "first_seen": dest_events[0].get('timestamp'),
                    "last_seen": dest_events[-1].get('timestamp'),
                    "description": f"Large outbound transfer ({total_bytes / 1024 / 1024:.1f}MB) to {dest_ip}",
                })
        
        return findings
    
    def _hunt_rare_processes(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect rare or unusual process execution."""
        findings = []
        
        # Count process execution frequency
        process_counts = defaultdict(int)
        process_events = defaultdict(list)
        
        for event in events:
            if event.get('source_type') == 'endpoint' or event.get('event_type') == 'PROCESS_START':
                process = event.get('process') or event.get('process_name', '')
                if process:
                    process_counts[process] += 1
                    process_events[process].append(event)
        
        # Find rare processes (executed only once or twice)
        suspicious_processes = [
            'mimikatz', 'pwdump', 'procdump', 'lazagne', 'bloodhound',
            'empire', 'cobalt', 'metasploit', 'meterpreter',
        ]
        
        for process, count in process_counts.items():
            process_lower = process.lower()
            
            # Check for suspicious process names
            if any(sus in process_lower for sus in suspicious_processes):
                findings.append({
                    "finding_type": "suspicious_process",
                    "severity": "critical",
                    "process": process,
                    "execution_count": count,
                    "events": [e.get('timestamp') for e in process_events[process][:5]],
                    "description": f"Suspicious process detected: {process}",
                })
            # Check for rare execution
            elif count <= 2:
                findings.append({
                    "finding_type": "rare_process",
                    "severity": "low",
                    "process": process,
                    "execution_count": count,
                    "description": f"Rare process execution: {process} ({count} times)",
                })
        
        return findings
    
    def _hunt_encoded_powershell(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect encoded PowerShell commands."""
        findings = []
        
        encoded_patterns = [
            r'powershell.*-enc',
            r'powershell.*-encodedcommand',
            r'powershell.*frombase64',
            r'invoke-expression.*base64',
            r'iex.*\[convert\]::frombase64',
            r'powershell.*-windowstyle\s+hidden',
        ]
        
        for event in events:
            command = event.get('command', '') or event.get('command_line', '') or event.get('message', '')
            command_lower = command.lower()
            
            if 'powershell' in command_lower:
                for pattern in encoded_patterns:
                    if re.search(pattern, command_lower, re.IGNORECASE):
                        findings.append({
                            "finding_type": "encoded_powershell",
                            "severity": "high",
                            "host": event.get('host'),
                            "user": event.get('username'),
                            "command": command[:200],
                            "timestamp": event.get('timestamp'),
                            "description": "Encoded or obfuscated PowerShell execution detected",
                        })
                        break
        
        return findings
    
    def _hunt_lateral_movement(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns."""
        findings = []
        
        # Look for SMB, WMI, PsExec patterns
        lateral_indicators = [
            ('smb', 'port 445'),
            ('wmi', 'wmic'),
            ('psexec', 'psexec'),
            ('rpc', 'port 135'),
            ('rdp', 'port 3389'),
        ]
        
        # Group by source IP
        source_activity = defaultdict(list)
        
        for event in events:
            source_ip = event.get('source_ip')
            if source_ip:
                source_activity[source_ip].append(event)
        
        # Find hosts connecting to many internal hosts
        for source_ip, src_events in source_activity.items():
            dest_hosts = set()
            lateral_events = []
            
            for event in src_events:
                dest_ip = event.get('destination_ip', '')
                if dest_ip.startswith(('10.', '192.168.', '172.')):
                    dest_hosts.add(dest_ip)
                    
                    # Check for lateral movement indicators
                    message = (event.get('message', '') + event.get('command', '')).lower()
                    for indicator, desc in lateral_indicators:
                        if indicator in message or desc in message:
                            lateral_events.append({
                                "timestamp": event.get('timestamp'),
                                "destination": dest_ip,
                                "indicator": desc,
                            })
            
            if len(dest_hosts) >= 5 or lateral_events:
                findings.append({
                    "finding_type": "lateral_movement",
                    "severity": "critical",
                    "source_ip": source_ip,
                    "unique_destinations": len(dest_hosts),
                    "lateral_events": lateral_events[:10],
                    "description": f"Potential lateral movement from {source_ip} to {len(dest_hosts)} hosts",
                })
        
        return findings
    
    def _hunt_credential_access(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect credential access attempts."""
        findings = []
        
        credential_indicators = [
            'lsass', 'ntds', 'sam', 'security hive',
            'mimikatz', 'sekurlsa', 'wdigest',
            'credential', 'password', 'logonpassword',
        ]
        
        for event in events:
            message = (event.get('message', '') + event.get('command', '')).lower()
            process = event.get('process', '').lower()
            
            # Check for credential access indicators
            for indicator in credential_indicators:
                if indicator in message or indicator in process:
                    findings.append({
                        "finding_type": "credential_access",
                        "severity": "critical",
                        "host": event.get('host'),
                        "process": event.get('process'),
                        "user": event.get('username'),
                        "indicator": indicator,
                        "timestamp": event.get('timestamp'),
                        "description": f"Credential access attempt detected: {indicator}",
                    })
                    break
        
        return findings
    
    def _hunt_persistence(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect persistence mechanism installation."""
        findings = []
        
        persistence_indicators = [
            ('scheduled task', 'schtasks'),
            ('cron', 'crontab'),
            ('registry', 'run key'),
            ('startup', 'startup folder'),
            ('service', 'sc create'),
            ('launchd', 'plist'),
        ]
        
        for event in events:
            message = (event.get('message', '') + event.get('command', '')).lower()
            
            for indicator, command in persistence_indicators:
                if indicator in message or command in message:
                    findings.append({
                        "finding_type": "persistence",
                        "severity": "high",
                        "host": event.get('host'),
                        "mechanism": indicator,
                        "command": command,
                        "timestamp": event.get('timestamp'),
                        "description": f"Potential persistence mechanism: {indicator}",
                    })
        
        return findings
    
    def _hunt_defense_evasion(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect defense evasion attempts."""
        findings = []
        
        evasion_indicators = [
            'disable antivirus',
            'stop service.*defender',
            'set-mppreference.*disablerealtimemonitoring',
            'clear eventlog',
            'wevtutil cl',
            'delete logs',
            'timestomp',
            'mask filename',
        ]
        
        for event in events:
            message = (event.get('message', '') + event.get('command', '')).lower()
            
            for indicator in evasion_indicators:
                if re.search(indicator, message, re.IGNORECASE):
                    findings.append({
                        "finding_type": "defense_evasion",
                        "severity": "high",
                        "host": event.get('host'),
                        "technique": indicator,
                        "timestamp": event.get('timestamp'),
                        "description": f"Defense evasion attempt: {indicator}",
                    })
        
        return findings
    
    def _hunt_c2_communication(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect command and control communication patterns."""
        findings = []
        
        # Look for beaconing patterns (regular interval connections)
        dest_connections = defaultdict(list)
        
        for event in events:
            if event.get('source_type') in ['firewall', 'network', 'dns']:
                dest = event.get('destination_ip') or event.get('query_domain')
                if dest:
                    dest_connections[dest].append({
                        'timestamp': event.get('timestamp'),
                        'event': event,
                    })
        
        # Analyze for beaconing patterns
        for dest, connections in dest_connections.items():
            if len(connections) >= 5:
                # Check for regular intervals (simplified check)
                findings.append({
                    "finding_type": "potential_c2",
                    "severity": "critical",
                    "destination": dest,
                    "connection_count": len(connections),
                    "timestamps": [c['timestamp'] for c in connections[:10]],
                    "description": f"Potential C2 beaconing to {dest} ({len(connections)} connections)",
                })
        
        return findings
    
    def get_findings(
        self,
        query_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get hunt findings."""
        if query_id:
            return {query_id: self.findings.get(query_id, [])[-limit:]}
        return {k: v[-limit:] for k, v in self.findings.items()}
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat hunting statistics."""
        total_findings = sum(len(f) for f in self.findings.values())
        
        return {
            "total_queries": len(self.queries),
            "total_findings": total_findings,
            "findings_by_query": {
                qid: len(findings) for qid, findings in self.findings.items()
            },
            "queries": [q.to_dict() for q in self.queries.values()],
        }
    
    def save_findings(self):
        """Save findings to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"findings_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "findings": self.findings,
            }, f, indent=2, default=str)
        
        logger.info(f"Saved threat hunting findings to {filename}")


# Global threat hunting engine instance
threat_hunting_engine = ThreatHuntingEngine()
