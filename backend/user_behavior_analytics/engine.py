"""
User Behavior Analytics (UBA) Engine
Local AI-Powered Security Operations Center

Analyzes user behavior patterns to detect insider threats and compromised accounts.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from collections import defaultdict
from enum import Enum
import structlog

from observability.activity_logger import log_event, EventCategory, SeverityLevel

logger = structlog.get_logger()


class RiskIndicator(str, Enum):
    """User risk indicators."""
    FAILED_LOGINS = "failed_logins"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNUSUAL_TIME = "unusual_time"
    UNUSUAL_LOCATION = "unusual_location"
    DATA_ACCESS_SPIKE = "data_access_spike"
    SUSPICIOUS_COMMANDS = "suspicious_commands"
    ACCOUNT_SHARING = "account_sharing"
    DORMANT_ACTIVATED = "dormant_activated"


class UserBehaviorProfile:
    """Behavioral profile for a user."""
    
    def __init__(self, username: str):
        self.username = username
        self.created_at = datetime.utcnow()
        self.last_activity: Optional[datetime] = None
        
        # Login patterns
        self.login_hours: List[int] = []
        self.login_days: List[int] = []
        self.login_sources: Set[str] = set()
        self.failed_logins: int = 0
        self.successful_logins: int = 0
        
        # Activity patterns
        self.commands_executed: List[str] = []
        self.files_accessed: List[str] = []
        self.hosts_accessed: Set[str] = set()
        self.data_transferred: int = 0
        
        # Privilege patterns
        self.privilege_escalations: int = 0
        self.admin_actions: int = 0
        
        # Risk score
        self.risk_score: float = 0.0
        self.risk_indicators: List[RiskIndicator] = []
        
        # Baseline statistics
        self.baseline: Dict[str, float] = {}
    
    def update_activity(self, event: Dict[str, Any]):
        """Update profile with new activity."""
        timestamp = event.get('timestamp', '')
        try:
            if timestamp:
                ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                self.last_activity = ts
                self.login_hours.append(ts.hour)
                self.login_days.append(ts.weekday())
        except:
            pass
        
        # Track login sources
        source_ip = event.get('source_ip', '')
        if source_ip:
            self.login_sources.add(source_ip)
        
        # Track commands
        command = event.get('command', '')
        if command:
            self.commands_executed.append(command[:100])
        
        # Track hosts
        host = event.get('host', '')
        if host:
            self.hosts_accessed.add(host)
        
        # Track data transfer
        bytes_out = event.get('bytes_out', 0)
        if isinstance(bytes_out, (int, float)):
            self.data_transferred += int(bytes_out)
        
        # Track privilege escalations
        if event.get('event_type') in ['PRIVILEGE_ESCALATION', 'SUDO', 'SU']:
            self.privilege_escalations += 1
        
        # Track failed logins
        if event.get('event_type') == 'LOGIN_FAILURE':
            self.failed_logins += 1
        elif event.get('event_type') == 'LOGIN_SUCCESS':
            self.successful_logins += 1
        
        # Keep lists bounded
        self.login_hours = self.login_hours[-1000:]
        self.login_days = self.login_days[-1000:]
        self.commands_executed = self.commands_executed[-100:]
    
    def calculate_baseline(self):
        """Calculate baseline behavior statistics."""
        import numpy as np
        
        if self.login_hours:
            self.baseline['avg_login_hour'] = np.mean(self.login_hours)
            self.baseline['std_login_hour'] = np.std(self.login_hours)
        
        if self.login_days:
            self.baseline['common_days'] = list(set(self.login_days))
        
        self.baseline['common_sources'] = list(self.login_sources)[:5]
        self.baseline['avg_data_transfer'] = self.data_transferred / max(1, len(self.login_hours))
        self.baseline['login_success_rate'] = self.successful_logins / max(1, self.successful_logins + self.failed_logins)
    
    def calculate_risk(self) -> float:
        """Calculate user risk score (0-100)."""
        import numpy as np
        
        risk = 0.0
        self.risk_indicators = []
        
        # Failed login ratio (0-20 points)
        total_logins = self.successful_logins + self.failed_logins
        if total_logins > 0:
            fail_ratio = self.failed_logins / total_logins
            if fail_ratio > 0.5:
                risk += 20
                self.risk_indicators.append(RiskIndicator.FAILED_LOGINS)
            elif fail_ratio > 0.3:
                risk += 10
        
        # Privilege escalations (0-25 points)
        if self.privilege_escalations > 10:
            risk += 25
            self.risk_indicators.append(RiskIndicator.PRIVILEGE_ESCALATION)
        elif self.privilege_escalations > 5:
            risk += 15
        elif self.privilege_escalations > 2:
            risk += 5
        
        # Unusual time activity (0-15 points)
        if self.login_hours:
            recent_hours = self.login_hours[-10:]
            if any(h < 6 or h > 22 for h in recent_hours):
                risk += 15
                self.risk_indicators.append(RiskIndicator.UNUSUAL_TIME)
        
        # Multiple login sources (0-15 points)
        if len(self.login_sources) > 5:
            risk += 15
            self.risk_indicators.append(RiskIndicator.UNUSUAL_LOCATION)
        elif len(self.login_sources) > 3:
            risk += 5
        
        # Data transfer spike (0-25 points)
        if self.data_transferred > 1024 * 1024 * 1024:  # 1GB
            risk += 25
            self.risk_indicators.append(RiskIndicator.DATA_ACCESS_SPIKE)
        elif self.data_transferred > 100 * 1024 * 1024:  # 100MB
            risk += 10
        
        # Suspicious commands (0-20 points)
        suspicious_cmds = ['mimikatz', 'pwdump', 'procdump', 'lazagne', 'wmic']
        for cmd in self.commands_executed[-20:]:
            if any(sus in cmd.lower() for sus in suspicious_cmds):
                risk += 20
                self.risk_indicators.append(RiskIndicator.SUSPICIOUS_COMMANDS)
                break
        
        self.risk_score = min(100, risk)
        return self.risk_score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            'username': self.username,
            'created_at': self.created_at.isoformat() + 'Z',
            'last_activity': self.last_activity.isoformat() + 'Z' if self.last_activity else None,
            'risk_score': self.risk_score,
            'risk_indicators': [i.value for i in self.risk_indicators],
            'login_sources': list(self.login_sources),
            'hosts_accessed': list(self.hosts_accessed),
            'failed_logins': self.failed_logins,
            'successful_logins': self.successful_logins,
            'privilege_escalations': self.privilege_escalations,
            'data_transferred_bytes': self.data_transferred,
            'commands_executed_count': len(self.commands_executed),
            'baseline': self.baseline,
        }


class UserBehaviorAnalytics:
    """User Behavior Analytics engine."""
    
    def __init__(self, data_dir: str = "./data/uba"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # User profiles
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        
        # Risk alerts
        self.risk_alerts: List[Dict[str, Any]] = []
        self.max_alerts = 500
        
        # Suspicious command patterns
        self.suspicious_commands = [
            'mimikatz', 'sekurlsa', 'lsadump', 'pwdump',
            'procdump lsass', 'wmic process', 'vssadmin delete',
            'bcdedit /set', 'wevtutil cl', 'netsh advfirewall',
            'invoke-mimikatz', 'frombase64', 'downloadstring',
        ]
        
        logger.info("UserBehaviorAnalytics initialized")
    
    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process event and update user behavior profiles.
        
        Args:
            event: Security event
            
        Returns:
            Risk alert if detected
        """
        username = event.get('username')
        if not username:
            return None
        
        # Get or create user profile
        if username not in self.user_profiles:
            self.user_profiles[username] = UserBehaviorProfile(username)
        
        profile = self.user_profiles[username]
        profile.update_activity(event)
        
        # Calculate baseline periodically
        if profile.successful_logins % 10 == 0:
            profile.calculate_baseline()
        
        # Calculate risk
        risk_score = profile.calculate_risk()
        
        # Generate alert if high risk
        if risk_score >= 60:
            alert = self._create_risk_alert(profile)
            return alert
        
        return None
    
    def _create_risk_alert(self, profile: UserBehaviorProfile) -> Dict[str, Any]:
        """Create a user risk alert."""
        alert_id = f"uba_{hashlib.md5(f'{profile.username}{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:12]}"
        
        alert = {
            'alert_id': alert_id,
            'username': profile.username,
            'risk_score': profile.risk_score,
            'risk_indicators': [i.value for i in profile.risk_indicators],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'profile': profile.to_dict(),
            'status': 'new',
        }
        
        self.risk_alerts.append(alert)
        if len(self.risk_alerts) > self.max_alerts:
            self.risk_alerts.pop(0)
        
        # Log the alert
        log_event(
            category=EventCategory.SECURITY_ALERT,
            event_type="UBA_RISK_ALERT",
            module="user_behavior_analytics",
            message=f"User risk alert: {profile.username}",
            severity=SeverityLevel.CRITICAL if profile.risk_score >= 80 else SeverityLevel.HIGH,
            metadata={
                'username': profile.username,
                'risk_score': profile.risk_score,
                'indicators': [i.value for i in profile.risk_indicators],
            },
        )
        
        logger.info(f"Created UBA risk alert for {profile.username}")
        return alert
    
    def get_user_profile(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user behavior profile."""
        if username in self.user_profiles:
            return self.user_profiles[username].to_dict()
        return None
    
    def get_high_risk_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get highest risk users."""
        users = [
            p.to_dict() for p in self.user_profiles.values()
            if p.risk_score >= 40
        ]
        users.sort(key=lambda x: x['risk_score'], reverse=True)
        return users[:limit]
    
    def get_alerts(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get UBA alerts."""
        alerts = self.risk_alerts
        
        if status:
            alerts = [a for a in alerts if a.get('status') == status]
        
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return alerts[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get UBA statistics."""
        risk_distribution = defaultdict(int)
        
        for profile in self.user_profiles.values():
            if profile.risk_score >= 80:
                risk_distribution['critical'] += 1
            elif profile.risk_score >= 60:
                risk_distribution['high'] += 1
            elif profile.risk_score >= 40:
                risk_distribution['medium'] += 1
            else:
                risk_distribution['low'] += 1
        
        return {
            'total_users_tracked': len(self.user_profiles),
            'risk_distribution': dict(risk_distribution),
            'total_alerts': len(self.risk_alerts),
            'high_risk_users': len([p for p in self.user_profiles.values() if p.risk_score >= 60]),
        }
    
    def save_profiles(self):
        """Save user profiles to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"uba_profiles_{timestamp}.json"
        
        data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'profiles': {k: v.to_dict() for k, v in self.user_profiles.items()},
            'alerts': self.risk_alerts,
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved UBA profiles to {filename}")


# Global UBA engine instance
uba_engine = UserBehaviorAnalytics()
