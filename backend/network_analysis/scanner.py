"""
Network Analysis Module
Local AI-Powered Security Operations Center

Scans and analyzes local network for security exposure.
"""

import asyncio
import json
import socket
import structlog
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from config import settings

logger = structlog.get_logger()

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not available, using fallback scanner")


class NetworkAnalyzer:
    """Network analysis and scanning service."""
    
    def __init__(self):
        self.scan_results_dir = Path("./data/scan_results")
        self.scan_results_dir.mkdir(parents=True, exist_ok=True)
        
        self.latest_results: Dict[str, Any] = {}
        self.scan_history: List[Dict[str, Any]] = []
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=settings.MAX_CONCURRENT_SCANS)
        
        logger.info("NetworkAnalyzer initialized")
    
    async def scan(
        self,
        targets: List[str],
        scan_type: str = "basic",
        ports: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Scan network targets.
        
        Args:
            targets: List of IP addresses or CIDR ranges
            scan_type: basic, full, or aggressive
            ports: Optional port specification (e.g., "22,80,443")
            
        Returns:
            Scan results
        """
        logger.info(f"Starting {scan_type} scan on {targets}")
        
        start_time = datetime.utcnow()
        
        try:
            if NMAP_AVAILABLE:
                results = await self._nmap_scan(targets, scan_type, ports)
            else:
                results = await self._fallback_scan(targets, ports)
            
            # Add metadata
            results["scan_metadata"] = {
                "start_time": start_time.isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "targets": targets,
                "scan_type": scan_type,
                "ports": ports,
            }
            
            # Store results
            self.latest_results = results
            self.scan_history.append({
                "timestamp": start_time.isoformat(),
                "targets": targets,
                "hosts_found": len(results.get("hosts", [])),
            })
            
            # Save to disk
            self._save_scan_results(results)
            
            logger.info(f"Scan completed: {len(results.get('hosts', []))} hosts found")
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            return {
                "error": str(e),
                "hosts": [],
                "scan_metadata": {
                    "start_time": start_time.isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                    "targets": targets,
                    "scan_type": scan_type,
                },
            }
    
    async def _nmap_scan(
        self,
        targets: List[str],
        scan_type: str,
        ports: Optional[str],
    ) -> Dict[str, Any]:
        """
        Perform nmap scan.
        
        Args:
            targets: Target addresses
            scan_type: Scan type
            ports: Port specification
            
        Returns:
            Scan results
        """
        loop = asyncio.get_event_loop()
        
        def sync_scan():
            nm = nmap.PortScanner()
            
            # Build arguments
            arguments = "-T4"
            
            if scan_type == "basic":
                arguments += " -F"  # Fast scan (top 100 ports)
            elif scan_type == "full":
                arguments += " -p-"  # All ports
                arguments += " -sV"  # Service version detection
            elif scan_type == "aggressive":
                arguments += " -A"  # Aggressive (OS detection, scripts, etc.)
            
            if ports:
                arguments = f"-p {ports}"
            
            # Scan each target
            all_hosts = []
            
            for target in targets:
                try:
                    nm.scan(hosts=target, arguments=arguments)
                    
                    for host in nm.all_hosts():
                        host_data = {
                            "ip": host,
                            "hostname": nm[host].hostname() or "",
                            "state": nm[host].state(),
                            "vendor": nm[host].vendor() or "",
                            "os": nm[host].os() or [],
                            "ports": [],
                            "vulnerabilities": [],
                        }
                        
                        # Get port information
                        for proto in nm[host].all_protocols():
                            for port in nm[host][proto].keys():
                                port_data = nm[host][proto][port]
                                host_data["ports"].append({
                                    "port": port,
                                    "protocol": proto,
                                    "state": port_data.get("state", ""),
                                    "service": port_data.get("name", ""),
                                    "product": port_data.get("product", ""),
                                    "version": port_data.get("version", ""),
                                })
                                
                                # Check for common vulnerable services
                                vulns = self._check_service_vulnerabilities(
                                    port_data.get("product", ""),
                                    port_data.get("version", ""),
                                    port,
                                )
                                host_data["vulnerabilities"].extend(vulns)
                        
                        all_hosts.append(host_data)
                
                except Exception as e:
                    logger.error(f"Failed to scan {target}: {str(e)}")
            
            return {"hosts": all_hosts}
        
        return await loop.run_in_executor(self.executor, sync_scan)
    
    async def _fallback_scan(
        self,
        targets: List[str],
        ports: Optional[str],
    ) -> Dict[str, Any]:
        """
        Fallback socket-based scanner when nmap is not available.
        
        Args:
            targets: Target addresses
            ports: Port specification
            
        Returns:
            Scan results
        """
        # Parse ports
        if ports:
            port_list = [int(p.strip()) for p in ports.split(",")]
        else:
            # Default common ports
            port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
        
        all_hosts = []
        
        # Expand CIDR ranges (simplified)
        ip_addresses = []
        for target in targets:
            if "/" in target:
                # Simple /24 expansion
                base_ip = target.split("/")[0]
                if base_ip.count(".") == 3:
                    prefix = ".".join(base_ip.split(".")[:3])
                    ip_addresses.extend([f"{prefix}.{i}" for i in range(1, 255)])
            else:
                ip_addresses.append(target)
        
        # Scan IPs
        for ip in ip_addresses:
            host_data = {
                "ip": ip,
                "hostname": "",
                "state": "down",
                "ports": [],
                "vulnerabilities": [],
            }
            
            # Check if host is up
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, 22))  # Try SSH first
                sock.close()
                
                if result == 0:
                    host_data["state"] = "up"
                    
                    # Scan common ports
                    for port in port_list:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            result = sock.connect_ex((ip, port))
                            sock.close()
                            
                            if result == 0:
                                service_name = self._get_service_name(port)
                                host_data["ports"].append({
                                    "port": port,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": service_name,
                                    "product": "",
                                    "version": "",
                                })
                                
                                # Check vulnerabilities
                                vulns = self._check_service_vulnerabilities(
                                    service_name,
                                    "",
                                    port,
                                )
                                host_data["vulnerabilities"].extend(vulns)
                        
                        except Exception:
                            pass
                    
                    # Try to get hostname
                    try:
                        host_data["hostname"] = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        pass
                
            except Exception as e:
                logger.debug(f"Failed to scan {ip}: {str(e)}")
            
            if host_data["state"] == "up" or host_data["ports"]:
                all_hosts.append(host_data)
        
        return {"hosts": all_hosts}
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports."""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
        }
        return services.get(port, f"port-{port}")
    
    def _check_service_vulnerabilities(
        self,
        product: str,
        version: str,
        port: int,
    ) -> List[Dict[str, Any]]:
        """
        Check for known vulnerabilities in service.
        
        Args:
            product: Service product name
            version: Service version
            port: Port number
            
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        # Check for common vulnerable services
        if port == 23:
            vulnerabilities.append({
                "type": "insecure_service",
                "name": "Telnet - Unencrypted Protocol",
                "severity": "HIGH",
                "description": "Telnet transmits data in cleartext, including credentials",
                "recommendation": "Use SSH instead of Telnet",
            })
        
        if port == 21:
            vulnerabilities.append({
                "type": "insecure_service",
                "name": "FTP - Unencrypted Protocol",
                "severity": "MEDIUM",
                "description": "FTP transmits credentials in cleartext",
                "recommendation": "Use SFTP or FTPS instead",
            })
        
        if "apache" in product.lower() and version:
            vulnerabilities.append({
                "type": "outdated_software",
                "name": f"Apache {version} - Check for CVEs",
                "severity": "MEDIUM",
                "description": "Verify this Apache version is not vulnerable",
                "recommendation": "Update to latest stable version",
            })
        
        if "nginx" in product.lower() and version:
            vulnerabilities.append({
                "type": "outdated_software",
                "name": f"Nginx {version} - Check for CVEs",
                "severity": "MEDIUM",
                "description": "Verify this Nginx version is not vulnerable",
                "recommendation": "Update to latest stable version",
            })
        
        return vulnerabilities
    
    def _save_scan_results(self, results: Dict[str, Any]):
        """Save scan results to disk."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = self.scan_results_dir / f"scan_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.debug(f"Saved scan results to {filename}")
    
    async def get_latest_results(self) -> Dict[str, Any]:
        """
        Get latest scan results.
        
        Returns:
            Latest scan results
        """
        if not self.latest_results:
            # Load most recent scan from disk
            scan_files = sorted(self.scan_results_dir.glob("scan_*.json"))
            if scan_files:
                with open(scan_files[-1], "r") as f:
                    self.latest_results = json.load(f)
        
        return self.latest_results
    
    async def identify_hosts(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Identify live hosts in target ranges.
        
        Args:
            targets: Target addresses
            
        Returns:
            List of live hosts
        """
        results = await self.scan(targets, scan_type="basic")
        return results.get("hosts", [])
    
    async def detect_open_ports(
        self,
        target: str,
    ) -> List[Dict[str, Any]]:
        """
        Detect open ports on a specific target.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            List of open ports
        """
        results = await self.scan([target], scan_type="full")
        hosts = results.get("hosts", [])
        
        if hosts:
            return hosts[0].get("ports", [])
        
        return []
    
    async def identify_running_services(
        self,
        target: str,
    ) -> List[Dict[str, Any]]:
        """
        Identify running services on a target.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            List of running services
        """
        ports = await self.detect_open_ports(target)
        
        return [
            {
                "port": p["port"],
                "service": p.get("service", ""),
                "product": p.get("product", ""),
                "version": p.get("version", ""),
            }
            for p in ports
        ]
    
    async def match_services_to_vulnerabilities(
        self,
        target: str,
    ) -> Dict[str, Any]:
        """
        Match detected services to known vulnerabilities.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Services with associated vulnerabilities
        """
        results = await self.scan([target], scan_type="full")
        hosts = results.get("hosts", [])
        
        if not hosts:
            return {"error": "Host not found"}
        
        host = hosts[0]
        
        return {
            "ip": host["ip"],
            "hostname": host.get("hostname", ""),
            "services": [
                {
                    "port": p["port"],
                    "service": p.get("service", ""),
                    "product": p.get("product", ""),
                    "version": p.get("version", ""),
                    "vulnerabilities": p.get("vulnerabilities", []),
                }
                for p in host.get("ports", [])
            ],
            "total_vulnerabilities": sum(
                len(p.get("vulnerabilities", []))
                for p in host.get("ports", [])
            ),
        }
