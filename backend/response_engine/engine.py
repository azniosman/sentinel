"""
SOAR Response Engine
Local AI-Powered Security Operations Center

Automated security response actions and playbook execution.
"""

import json
import subprocess
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from enum import Enum
import structlog

from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class ResponseActionType(str, Enum):
    """Types of response actions."""
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    ISOLATE_HOST = "isolate_host"
    TERMINATE_PROCESS = "terminate_process"
    DISABLE_ACCOUNT = "disable_account"
    QUARANTINE_FILE = "quarantine_file"
    UPDATE_FIREWALL = "update_firewall"
    CREATE_TICKET = "create_ticket"
    SEND_ALERT = "send_alert"
    RUN_SCRIPT = "run_script"
    COLLECT_EVIDENCE = "collect_evidence"


class ResponseStatus(str, Enum):
    """Response action status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REQUIRES_APPROVAL = "requires_approval"


class ResponseAction:
    """Represents a single response action."""
    
    def __init__(
        self,
        action_id: str,
        action_type: ResponseActionType,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        requires_approval: bool = True,
    ):
        self.action_id = action_id
        self.action_type = action_type
        self.target = target
        self.parameters = parameters or {}
        self.requires_approval = requires_approval
        self.status = ResponseStatus.PENDING
        self.created_at = datetime.utcnow().isoformat() + "Z"
        self.executed_at: Optional[str] = None
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.executed_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "parameters": self.parameters,
            "requires_approval": self.requires_approval,
            "status": self.status.value,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
            "result": self.result,
            "error": self.error,
            "executed_by": self.executed_by,
        }


class Playbook:
    """Security response playbook."""
    
    def __init__(
        self,
        playbook_id: str,
        name: str,
        description: str,
        trigger_condition: str,
        steps: List[Dict[str, Any]],
        enabled: bool = True,
    ):
        self.playbook_id = playbook_id
        self.name = name
        self.description = description
        self.trigger_condition = trigger_condition
        self.steps = steps
        self.enabled = enabled
        self.run_count = 0
        self.last_run: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "trigger_condition": self.trigger_condition,
            "steps": self.steps,
            "enabled": self.enabled,
            "run_count": self.run_count,
            "last_run": self.last_run.isoformat() if self.last_run else None,
        }


class SOAREngine:
    """Security Orchestration, Automation and Response engine."""
    
    def __init__(self, data_dir: str = "./data/response"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Response actions queue
        self.actions: Dict[str, ResponseAction] = {}
        
        # Playbooks registry
        self.playbooks: Dict[str, Playbook] = {}
        
        # Action handlers
        self.action_handlers: Dict[ResponseActionType, Callable] = {
            ResponseActionType.BLOCK_IP: self._block_ip,
            ResponseActionType.UNBLOCK_IP: self._unblock_ip,
            ResponseActionType.ISOLATE_HOST: self._isolate_host,
            ResponseActionType.TERMINATE_PROCESS: self._terminate_process,
            ResponseActionType.DISABLE_ACCOUNT: self._disable_account,
            ResponseActionType.CREATE_TICKET: self._create_ticket,
            ResponseActionType.SEND_ALERT: self._send_alert,
        }
        
        # Load built-in playbooks
        self._load_builtin_playbooks()
        
        logger.info("SOAREngine initialized")
    
    def _load_builtin_playbooks(self):
        """Load built-in security playbooks."""
        
        # Playbook: Brute Force Response
        self.register_playbook(Playbook(
            playbook_id="PB_BRUTE_FORCE",
            name="Brute Force Attack Response",
            description="Automated response to brute force attacks",
            trigger_condition="alert.rule_id == 'BRUTE_FORCE_001'",
            steps=[
                {
                    "step": 1,
                    "action": "block_ip",
                    "target": "${alert.event.source_ip}",
                    "parameters": {"duration": "24h"},
                    "requires_approval": False,
                },
                {
                    "step": 2,
                    "action": "send_alert",
                    "target": "soc_team",
                    "parameters": {
                        "channel": "slack",
                        "message": "Brute force attack detected and blocked",
                    },
                    "requires_approval": False,
                },
                {
                    "step": 3,
                    "action": "create_ticket",
                    "target": "security_incidents",
                    "parameters": {
                        "priority": "high",
                        "category": "intrusion_attempt",
                    },
                    "requires_approval": False,
                },
            ],
        ))
        
        # Playbook: Malware Detection Response
        self.register_playbook(Playbook(
            playbook_id="PB_MALWARE",
            name="Malware Detection Response",
            description="Automated response to malware detection",
            trigger_condition="alert.severity == 'critical' and 'malware' in alert.rule_name.lower()",
            steps=[
                {
                    "step": 1,
                    "action": "isolate_host",
                    "target": "${alert.event.host}",
                    "parameters": {"isolation_level": "network"},
                    "requires_approval": True,
                },
                {
                    "step": 2,
                    "action": "collect_evidence",
                    "target": "${alert.event.host}",
                    "parameters": {
                        "collect_memory": True,
                        "collect_processes": True,
                        "collect_network": True,
                    },
                    "requires_approval": False,
                },
                {
                    "step": 3,
                    "action": "send_alert",
                    "target": "soc_team",
                    "parameters": {
                        "channel": "pagerduty",
                        "severity": "critical",
                        "message": "Malware detected - host isolated",
                    },
                    "requires_approval": False,
                },
            ],
        ))
        
        # Playbook: Port Scan Response
        self.register_playbook(Playbook(
            playbook_id="PB_PORT_SCAN",
            name="Port Scan Response",
            description="Automated response to port scanning",
            trigger_condition="alert.rule_id == 'PORT_SCAN_001'",
            steps=[
                {
                    "step": 1,
                    "action": "block_ip",
                    "target": "${alert.event.source_ip}",
                    "parameters": {"duration": "1h"},
                    "requires_approval": False,
                },
                {
                    "step": 2,
                    "action": "send_alert",
                    "target": "soc_team",
                    "parameters": {
                        "channel": "slack",
                        "message": "Port scan detected and blocked",
                    },
                    "requires_approval": False,
                },
            ],
        ))
        
        # Playbook: Data Exfiltration Response
        self.register_playbook(Playbook(
            playbook_id="PB_EXFIL",
            name="Data Exfiltration Response",
            description="Emergency response to data exfiltration",
            trigger_condition="alert.rule_id == 'EXFIL_001'",
            steps=[
                {
                    "step": 1,
                    "action": "block_ip",
                    "target": "${alert.event.destination_ip}",
                    "parameters": {"duration": "permanent"},
                    "requires_approval": False,
                },
                {
                    "step": 2,
                    "action": "isolate_host",
                    "target": "${alert.event.host}",
                    "parameters": {"isolation_level": "full"},
                    "requires_approval": True,
                },
                {
                    "step": 3,
                    "action": "collect_evidence",
                    "target": "${alert.event.host}",
                    "parameters": {
                        "collect_memory": True,
                        "collect_disk": True,
                        "collect_network": True,
                    },
                    "requires_approval": False,
                },
                {
                    "step": 4,
                    "action": "send_alert",
                    "target": "incident_response",
                    "parameters": {
                        "channel": "pagerduty",
                        "severity": "critical",
                        "message": "DATA EXFILTRATION DETECTED - Emergency response initiated",
                    },
                    "requires_approval": False,
                },
            ],
        ))
        
        logger.info(f"Loaded {len(self.playbooks)} playbooks")
    
    def register_playbook(self, playbook: Playbook):
        """Register a playbook."""
        self.playbooks[playbook.playbook_id] = playbook
        logger.info(f"Registered playbook: {playbook.playbook_id}")
    
    def create_action(
        self,
        action_type: ResponseActionType,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
        requires_approval: bool = True,
    ) -> ResponseAction:
        """Create a response action."""
        action_id = f"action_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
        
        action = ResponseAction(
            action_id=action_id,
            action_type=action_type,
            target=target,
            parameters=parameters,
            requires_approval=requires_approval,
        )
        
        self.actions[action_id] = action
        
        log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type="RESPONSE_ACTION_CREATED",
            module="soar_engine",
            message=f"Response action created: {action_type.value}",
            severity=SeverityLevel.INFO,
            metadata={
                "action_id": action_id,
                "target": target,
                "requires_approval": requires_approval,
            },
        )
        
        return action
    
    async def execute_action(self, action_id: str, executed_by: str = "system") -> Dict[str, Any]:
        """Execute a response action."""
        if action_id not in self.actions:
            return {"error": "Action not found"}
        
        action = self.actions[action_id]
        
        # Check approval requirement
        if action.requires_approval and action.status != ResponseStatus.COMPLETED:
            action.status = ResponseStatus.REQUIRES_APPROVAL
            return {"status": "requires_approval", "action_id": action_id}
        
        # Execute action
        action.status = ResponseStatus.RUNNING
        action.executed_by = executed_by
        
        handler = self.action_handlers.get(action.action_type)
        
        if not handler:
            action.status = ResponseStatus.FAILED
            action.error = f"No handler for action type: {action.action_type}"
            return {"error": action.error}
        
        try:
            result = await handler(action.target, action.parameters)
            
            action.status = ResponseStatus.COMPLETED
            action.executed_at = datetime.utcnow().isoformat() + "Z"
            action.result = result
            
            log_event(
                category=EventCategory.SECURITY_ALERT,
                event_type="RESPONSE_ACTION_EXECUTED",
                module="soar_engine",
                message=f"Response action completed: {action.action_type.value}",
                severity=SeverityLevel.INFO,
                metadata={
                    "action_id": action_id,
                    "target": action.target,
                    "result": result,
                },
            )
            
            return {"status": "completed", "result": result}
            
        except Exception as e:
            action.status = ResponseStatus.FAILED
            action.error = str(e)
            
            log_event(
                category=EventCategory.SECURITY_ALERT,
                event_type="RESPONSE_ACTION_FAILED",
                module="soar_engine",
                message=f"Response action failed: {action.action_type.value}",
                severity=SeverityLevel.ERROR,
                metadata={
                    "action_id": action_id,
                    "error": str(e),
                },
            )
            
            return {"error": str(e)}
    
    async def approve_action(self, action_id: str, approved_by: str) -> Dict[str, Any]:
        """Approve a pending action."""
        if action_id not in self.actions:
            return {"error": "Action not found"}
        
        action = self.actions[action_id]
        action.requires_approval = False
        
        return await self.execute_action(action_id, approved_by)
    
    async def run_playbook(self, playbook_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a playbook with given context.
        
        Args:
            playbook_id: ID of playbook to run
            context: Context data for playbook execution (e.g., alert data)
            
        Returns:
            Execution results
        """
        if playbook_id not in self.playbooks:
            return {"error": "Playbook not found"}
        
        playbook = self.playbooks[playbook_id]
        
        if not playbook.enabled:
            return {"error": "Playbook is disabled"}
        
        playbook.run_count += 1
        playbook.last_run = datetime.utcnow()
        
        results = []
        
        log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type="PLAYBOOK_STARTED",
            module="soar_engine",
            message=f"Playbook started: {playbook.name}",
            severity=SeverityLevel.INFO,
            metadata={
                "playbook_id": playbook_id,
                "context": context,
            },
        )
        
        for step in playbook.steps:
            try:
                # Resolve target from context
                target = self._resolve_template(step["target"], context)
                
                # Create action
                action = self.create_action(
                    action_type=ResponseActionType(step["action"]),
                    target=target,
                    parameters=step.get("parameters", {}),
                    requires_approval=step.get("requires_approval", True),
                )
                
                # Execute action
                result = await self.execute_action(action.action_id)
                results.append({
                    "step": step["step"],
                    "action_id": action.action_id,
                    "result": result,
                })
                
                # Stop on failure
                if result.get("error") and step.get("stop_on_error", True):
                    break
                    
            except Exception as e:
                logger.error(f"Playbook step failed: {str(e)}")
                results.append({
                    "step": step["step"],
                    "error": str(e),
                })
                break
        
        log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type="PLAYBOOK_COMPLETED",
            module="soar_engine",
            message=f"Playbook completed: {playbook.name}",
            severity=SeverityLevel.INFO,
            metadata={
                "playbook_id": playbook_id,
                "steps_completed": len(results),
            },
        )
        
        return {
            "playbook_id": playbook_id,
            "playbook_name": playbook.name,
            "steps_executed": len(results),
            "results": results,
        }
    
    def _resolve_template(self, template: str, context: Dict[str, Any]) -> str:
        """Resolve template variables from context."""
        # Simple template resolution: ${alert.event.source_ip}
        import re
        
        def replace_var(match):
            path = match.group(1).split('.')
            value = context
            for key in path:
                if isinstance(value, dict):
                    value = value.get(key, '')
                else:
                    return ''
            return str(value)
        
        return re.sub(r'\$\{([^}]+)\}', replace_var, template)
    
    # ============== Action Handlers ==============
    
    async def _block_ip(self, target: str, parameters: Dict[str, Any]) -> str:
        """Block an IP address."""
        duration = parameters.get('duration', '24h')
        
        # Log the action (in production, would execute firewall command)
        result = f"Blocked IP {target} for {duration}"
        
        logger.info(f"ACTION: Block IP - {result}")
        
        # Example iptables command (commented for safety)
        # cmd = f"iptables -A INPUT -s {target} -j DROP"
        # subprocess.run(cmd.split(), capture_output=True)
        
        return result
    
    async def _unblock_ip(self, target: str, parameters: Dict[str, Any]) -> str:
        """Unblock an IP address."""
        result = f"Unblocked IP {target}"
        logger.info(f"ACTION: Unblock IP - {result}")
        return result
    
    async def _isolate_host(self, target: str, parameters: Dict[str, Any]) -> str:
        """Isolate a host from the network."""
        isolation_level = parameters.get('isolation_level', 'network')
        result = f"Isolated host {target} (level: {isolation_level})"
        logger.info(f"ACTION: Isolate Host - {result}")
        return result
    
    async def _terminate_process(self, target: str, parameters: Dict[str, Any]) -> str:
        """Terminate a process."""
        process_id = parameters.get('pid', target)
        result = f"Terminated process {process_id}"
        logger.info(f"ACTION: Terminate Process - {result}")
        return result
    
    async def _disable_account(self, target: str, parameters: Dict[str, Any]) -> str:
        """Disable a user account."""
        result = f"Disabled account {target}"
        logger.info(f"ACTION: Disable Account - {result}")
        return result
    
    async def _create_ticket(self, target: str, parameters: Dict[str, Any]) -> str:
        """Create a ticket in ticketing system."""
        priority = parameters.get('priority', 'medium')
        category = parameters.get('category', 'security')
        ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        result = f"Created ticket {ticket_id} (priority: {priority})"
        logger.info(f"ACTION: Create Ticket - {result}")
        return result
    
    async def _send_alert(self, target: str, parameters: Dict[str, Any]) -> str:
        """Send an alert notification."""
        channel = parameters.get('channel', 'slack')
        message = parameters.get('message', 'Security alert')
        severity = parameters.get('severity', 'medium')
        result = f"Sent {severity} alert to {target} via {channel}: {message}"
        logger.info(f"ACTION: Send Alert - {result}")
        return result
    
    async def _collect_evidence(self, target: str, parameters: Dict[str, Any]) -> str:
        """Collect forensic evidence from a host."""
        collect_memory = parameters.get('collect_memory', False)
        collect_disk = parameters.get('collect_disk', False)
        collect_network = parameters.get('collect_network', False)
        
        evidence_id = f"EVD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        result = f"Collected evidence {evidence_id} from {target}"
        
        if collect_memory:
            result += " [memory]"
        if collect_disk:
            result += " [disk]"
        if collect_network:
            result += " [network]"
        
        logger.info(f"ACTION: Collect Evidence - {result}")
        return result
    
    def get_actions(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get response actions."""
        actions = list(self.actions.values())
        
        if status:
            actions = [a for a in actions if a.status.value == status]
        
        actions.sort(key=lambda x: x.created_at, reverse=True)
        
        return [a.to_dict() for a in actions[:limit]]
    
    def get_playbooks(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """Get playbooks."""
        playbooks = list(self.playbooks.values())
        
        if enabled_only:
            playbooks = [p for p in playbooks if p.enabled]
        
        return [p.to_dict() for p in playbooks]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SOAR statistics."""
        actions_by_status = {}
        for action in self.actions.values():
            status = action.status.value
            actions_by_status[status] = actions_by_status.get(status, 0) + 1
        
        return {
            "total_playbooks": len(self.playbooks),
            "enabled_playbooks": sum(1 for p in self.playbooks.values() if p.enabled),
            "total_actions": len(self.actions),
            "actions_by_status": actions_by_status,
            "playbooks": [p.to_dict() for p in self.playbooks.values()],
        }


# Global SOAR engine instance
soar_engine = SOAREngine()
