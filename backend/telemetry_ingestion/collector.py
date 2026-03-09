"""
Security Telemetry Ingestion Layer
Local AI-Powered Security Operations Center

Collects and ingests security telemetry from multiple sources.
"""

import os
import json
import glob
import socket
import structlog
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

from config import settings

logger = structlog.get_logger()


class LogFileHandler(FileSystemEventHandler):
    """Watch for new log entries in files."""
    
    def __init__(self, callback):
        self.callback = callback
    
    def on_modified(self, event):
        if not event.is_directory:
            self.callback(event.path)


class TelemetryCollector:
    """Collects security telemetry from various sources."""
    
    def __init__(self, data_dir: str = "./data/telemetry"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Log source configurations
        self.syslog_path = "/var/log/syslog"
        self.auth_log_path = "/var/log/auth.log"
        self.secure_log_path = "/var/log/secure"
        self.firewall_log_paths = [
            "/var/log/ufw.log",
            "/var/log/iptables.log",
            "/var/log/pfirewall.log",
        ]
        self.ids_log_paths = [
            "/var/log/suricata/fast.log",
            "/var/log/zeek/notice.log",
        ]
        self.dns_log_paths = [
            "/var/log/bind/query.log",
            "/var/log/dnsmasq.log",
        ]
        
        # File watchers
        self.observers = []
        
        logger.info("TelemetryCollector initialized")
    
    def collect_syslog(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Collect syslog entries.
        
        Args:
            limit: Maximum entries to collect
            
        Returns:
            List of syslog entries
        """
        entries = []
        
        # Try common syslog paths
        syslog_paths = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/system.log",
        ]
        
        for log_path in syslog_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        # Read last N lines
                        lines = f.readlines()[-limit:]
                        
                        for line in lines:
                            entry = self._parse_syslog_line(line.strip())
                            if entry:
                                entries.append(entry)
                    
                    logger.info(f"Collected syslog from {log_path}", count=len(entries))
                    break
                    
                except (PermissionError, IOError) as e:
                    logger.warning(f"Cannot read {log_path}: {str(e)}")
        
        # If no real syslog, generate sample data for demo
        if not entries:
            entries = self._generate_sample_syslog(limit)
        
        return entries
    
    def _parse_syslog_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a syslog line into structured format."""
        if not line:
            return None
        
        # Simple syslog parsing (adjust based on your syslog format)
        # Example: Mar  9 10:15:23 hostname process[pid]: message
        
        parts = line.split(" ", 5)
        if len(parts) < 5:
            return None
        
        try:
            return {
                "source": "syslog",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "raw": line,
                "month": parts[0],
                "day": parts[1],
                "time": parts[2],
                "host": parts[3],
                "process": parts[4].split("[")[0] if "[" in parts[4] else parts[4],
                "message": parts[5] if len(parts) > 5 else "",
            }
        except Exception:
            return None
    
    def _generate_sample_syslog(self, limit: int) -> List[Dict[str, Any]]:
        """Generate sample syslog entries for demonstration."""
        import random
        
        sample_messages = [
            "sshd[1234]: Accepted publickey for admin from 192.168.1.100",
            "sshd[1235]: Failed password for root from 10.0.0.50",
            "sudo[1236]: admin : TTY=pts/0 ; PWD=/home/admin ; COMMAND=/bin/ls",
            "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.50",
            "cron[1237]: (root) CMD (/usr/local/bin/backup.sh)",
            "systemd[1]: Started Daily apt download activities.",
            "sshd[1238]: Connection closed by authenticating user admin",
            "sudo[1239]: pam_unix(sudo:auth): authentication failure",
        ]
        
        entries = []
        for i in range(min(limit, len(sample_messages))):
            msg = random.choice(sample_messages)
            entry = self._parse_syslog_line(f"Mar  9 10:{i:02d}:00 localhost {msg}")
            if entry:
                entries.append(entry)
        
        return entries
    
    def collect_firewall_logs(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Collect firewall log entries.
        
        Args:
            limit: Maximum entries to collect
            
        Returns:
            List of firewall log entries
        """
        entries = []
        
        for log_path in self.firewall_log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()[-limit:]
                        
                        for line in lines:
                            entry = self._parse_firewall_line(line.strip())
                            if entry:
                                entries.append(entry)
                    
                    logger.info(f"Collected firewall logs from {log_path}", count=len(entries))
                    
                except (PermissionError, IOError):
                    pass
        
        # Generate sample if no real logs
        if not entries:
            entries = self._generate_sample_firewall(limit)
        
        return entries
    
    def _parse_firewall_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse firewall log line."""
        if "BLOCK" not in line and "DROP" not in line and "REJECT" not in line:
            return None
        
        # Extract IP addresses
        import re
        src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
        dst_match = re.search(r'DST=(\d+\.\d+\.\d+\.\d+)', line)
        proto_match = re.search(r'PROTO=(\w+)', line)
        dpt_match = re.search(r'DPT=(\d+)', line)
        
        return {
            "source": "firewall",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "raw": line,
            "action": "BLOCK" if "BLOCK" in line else "DROP" if "DROP" in line else "REJECT",
            "src_ip": src_match.group(1) if src_match else None,
            "dst_ip": dst_match.group(1) if dst_match else None,
            "protocol": proto_match.group(1) if proto_match else None,
            "dst_port": int(dpt_match.group(1)) if dpt_match else None,
        }
    
    def _generate_sample_firewall(self, limit: int) -> List[Dict[str, Any]]:
        """Generate sample firewall blocks."""
        import random
        
        blocked_ips = [
            "203.0.113.50", "198.51.100.23", "192.0.2.100",
            "185.220.101.45", "45.155.205.233", "89.248.167.131",
        ]
        
        ports = [22, 23, 80, 443, 3389, 445, 135, 139]
        
        entries = []
        for i in range(limit):
            entries.append({
                "source": "firewall",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "action": random.choice(["BLOCK", "DROP"]),
                "src_ip": random.choice(blocked_ips),
                "dst_ip": f"192.168.1.{random.randint(1, 254)}",
                "protocol": random.choice(["TCP", "UDP"]),
                "dst_port": random.choice(ports),
                "raw": f"Firewall block from {random.choice(blocked_ips)}",
            })
        
        return entries
    
    def collect_ids_logs(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Collect IDS/IPS log entries.
        
        Args:
            limit: Maximum entries to collect
            
        Returns:
            List of IDS log entries
        """
        entries = []
        
        for log_path in self.ids_log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()[-limit:]
                        
                        for line in lines:
                            entry = self._parse_ids_line(line.strip())
                            if entry:
                                entries.append(entry)
                    
                except (PermissionError, IOError):
                    pass
        
        # Generate sample if no real logs
        if not entries:
            entries = self._generate_sample_ids(limit)
        
        return entries
    
    def _parse_ids_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse IDS log line."""
        if not line:
            return None
        
        return {
            "source": "ids",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "raw": line,
            "alert_type": "IDS_ALERT",
        }
    
    def _generate_sample_ids(self, limit: int) -> List[Dict[str, Any]]:
        """Generate sample IDS alerts."""
        import random
        
        signatures = [
            "ET SCAN Potential SSH Scan",
            "GPL ATTACK_RESPONSE id check returned root",
            "ET POLICY Outbound SMTP Traffic",
            "SURICATA TCPv4 invalid checksum",
            "ET TROJAN Possible Metasploit Meterpreter Reverse HTTPS",
            "GPL DNS version BIND",
            "ET EXPLOIT Possible SQL Injection",
            "ET MALWARE Win32/Agent Generic",
        ]
        
        severities = ["low", "medium", "high", "critical"]
        
        entries = []
        for i in range(limit):
            entries.append({
                "source": "ids",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "signature": random.choice(signatures),
                "severity": random.choice(severities),
                "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "dst_ip": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
                "raw": f"IDS Alert: {random.choice(signatures)}",
            })
        
        return entries
    
    def collect_dns_logs(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Collect DNS query logs.
        
        Args:
            limit: Maximum entries to collect
            
        Returns:
            List of DNS log entries
        """
        entries = []
        
        for log_path in self.dns_log_paths:
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r") as f:
                        lines = f.readlines()[-limit:]
                        
                        for line in lines:
                            entry = self._parse_dns_line(line.strip())
                            if entry:
                                entries.append(entry)
                    
                except (PermissionError, IOError):
                    pass
        
        # Generate sample if no real logs
        if not entries:
            entries = self._generate_sample_dns(limit)
        
        return entries
    
    def _parse_dns_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS log line."""
        if not line:
            return None
        
        return {
            "source": "dns",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "raw": line,
        }
    
    def _generate_sample_dns(self, limit: int) -> List[Dict[str, Any]]:
        """Generate sample DNS queries."""
        import random
        
        domains = [
            "google.com", "microsoft.com", "github.com",
            "malicious-domain.xyz", "suspicious-site.ru",
            "phishing-attempt.com", "c2-server.net",
            "legitimate-site.com", "cdn.cloudflare.com",
        ]
        
        query_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]
        
        entries = []
        for i in range(limit):
            entries.append({
                "source": "dns",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client_ip": f"192.168.1.{random.randint(1, 254)}",
                "query_domain": random.choice(domains),
                "query_type": random.choice(query_types),
                "response_code": random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
                "raw": f"DNS query for {random.choice(domains)}",
            })
        
        return entries
    
    def collect_endpoint_events(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Collect endpoint security events.
        
        Args:
            limit: Maximum entries to collect
            
        Returns:
            List of endpoint events
        """
        # Generate sample endpoint events
        entries = self._generate_sample_endpoint(limit)
        return entries
    
    def _generate_sample_endpoint(self, limit: int) -> List[Dict[str, Any]]:
        """Generate sample endpoint events."""
        import random
        
        event_types = [
            "process_start", "process_terminate", "file_create",
            "file_modify", "registry_modify", "network_connection",
            "user_login", "user_logout", "privilege_escalation",
        ]
        
        processes = [
            "powershell.exe", "cmd.exe", "svchost.exe", "explorer.exe",
            "chrome.exe", "firefox.exe", "outlook.exe", "winword.exe",
        ]
        
        users = ["admin", "user1", "service_account", "system"]
        
        entries = []
        for i in range(limit):
            event_type = random.choice(event_types)
            
            entry = {
                "source": "endpoint",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": event_type,
                "hostname": f"WORKSTATION-{random.randint(1, 100)}",
                "username": random.choice(users),
                "process_name": random.choice(processes),
                "process_id": random.randint(1000, 65535),
                "parent_process": random.choice(processes),
                "command_line": f"{random.choice(processes)} -arg1 -arg2",
                "raw": f"Endpoint event: {event_type}",
            }
            
            # Add event-specific fields
            if event_type == "network_connection":
                entry["dst_ip"] = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                entry["dst_port"] = random.randint(1, 65535)
                entry["protocol"] = random.choice(["TCP", "UDP"])
            
            entries.append(entry)
        
        return entries
    
    def start_file_watching(self, log_paths: List[str], callback):
        """
        Start watching log files for new entries.
        
        Args:
            log_paths: List of log file paths to watch
            callback: Function to call when new log entry detected
        """
        handler = LogFileHandler(callback)
        observer = Observer()
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                parent_dir = os.path.dirname(log_path)
                observer.schedule(handler, parent_dir, recursive=False)
                logger.info(f"Watching {log_path} for changes")
        
        observer.start()
        self.observers.append(observer)
        logger.info("File watching started")
    
    def stop_file_watching(self):
        """Stop watching log files."""
        for observer in self.observers:
            observer.stop()
            observer.join()
        
        self.observers = []
        logger.info("File watching stopped")
    
    def save_telemetry(self, entries: List[Dict[str, Any]], source: str):
        """
        Save telemetry entries to disk.
        
        Args:
            entries: List of telemetry entries
            source: Source name
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.data_dir / f"{source}_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(entries, f, indent=2, default=str)
        
        logger.info(f"Saved {len(entries)} {source} entries to {filename}")


# Global telemetry collector instance
telemetry_collector = TelemetryCollector()
