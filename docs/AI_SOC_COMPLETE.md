# Autonomous AI-Powered Security Operations Center (AI-SOC)

## Executive Summary

This document outlines the architecture and implementation status of the **Local Autonomous AI Security Operations Center** - a comprehensive cybersecurity monitoring, detection, investigation, and automated response platform that operates entirely locally without cloud dependencies.

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Autonomous AI-SOC Platform                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    SOC Dashboards & Visualization                     │  │
│  │  - Threat Landscape  - Attack Map  - Activity Log  - Intelligence    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ▲                                               │
│  ┌───────────────────────────┴──────────────────────────────────────────┐  │
│  │                    AI Security Agents Layer                           │  │
│  │  - Threat Hunter  - Incident Investigator  - Vulnerability Analyst   │  │
│  │  - IOC Correlation  - Network Monitor  - Response Coordinator        │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ▲                                               │
│  ┌───────────────────────────┴──────────────────────────────────────────┐  │
│  │                    Detection & Analysis Engine                        │  │
│  │  - Rule-based Detection  - IOC Matching  - MITRE ATT&CK Mapping      │  │
│  │  - Anomaly Detection  - Attack Path Analysis  - Risk Scoring         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ▲                                               │
│  ┌───────────────────────────┴──────────────────────────────────────────┐  │
│  │                    Intelligence Correlation                           │  │
│  │  - Threat Intel Graph  - IOC Database  - CVE Database                │  │
│  │  - Threat Actor Profiles  - Malware Signatures                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ▲                                               │
│  ┌───────────────────────────┴──────────────────────────────────────────┐  │
│  │                    Log Normalization Engine                           │  │
│  │  - Syslog  - Firewall  - IDS/IPS  - DNS  - Endpoint  - Network       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                              ▲                                               │
│  ┌───────────────────────────┴──────────────────────────────────────────┐  │
│  │                    Security Telemetry Sources                         │  │
│  │  - Linux Syslog  - Windows Events  - Firewall Logs  - IDS Logs       │  │
│  │  - DNS Queries  - Network Flows  - Endpoint Events                   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Status

### ✅ Completed Modules

| Module | Status | Location | Description |
|--------|--------|----------|-------------|
| **RAG Engine** | ✅ Complete | `backend/rag/` | AI-powered threat intelligence queries |
| **AI Agents** | ✅ Complete | `backend/agents/` | 5 autonomous security agents |
| **Network Analysis** | ✅ Complete | `backend/network_analysis/` | nmap integration, vulnerability scanning |
| **IOC Correlation** | ✅ Complete | `backend/ioc_correlation/` | IOC matching and pattern detection |
| **Threat Graph** | ✅ Complete | `backend/threat_graph/` | Knowledge graph for threat intel |
| **Attack Map** | ✅ Complete | `backend/attack_map/` | 3D globe visualization of attacks |
| **Activity Log** | ✅ Complete | `backend/observability/` | Real-time SOC event console |
| **Intelligence Engine** | ✅ Complete | `backend/intelligence_engine/` | Zero-day detection, CVE analysis |
| **Attack Simulation** | ✅ Complete | `backend/attack_simulation/` | Educational attack scenarios |
| **Scheduler** | ✅ Complete | `backend/scheduler/` | Automated task scheduling |
| **Threat Ingestion** | ✅ Complete | `backend/threat_ingestion/` | CVE feeds, MITRE ATT&CK import |
| **Frontend Dashboards** | ✅ Complete | `frontend/` | 4 dashboard pages |

### 🟡 In Progress Modules

| Module | Status | Location | Description |
|--------|--------|----------|-------------|
| **Telemetry Ingestion** | 🟡 Partial | `backend/telemetry_ingestion/` | Log collection from multiple sources |
| **Log Normalization** | 🟡 Planned | `backend/log_normalization/` | Standardize log formats |
| **Detection Engine** | 🟡 Planned | `backend/detection_engine/` | Rule-based threat detection |
| **Threat Hunting** | 🟡 Planned | `backend/threat_hunting/` | Proactive threat search |
| **Investigation Engine** | 🟡 Planned | `backend/investigation_engine/` | Automated incident investigation |
| **SOAR Response** | 🟡 Planned | `backend/response_engine/` | Automated response actions |
| **Playbooks** | 🟡 Planned | `backend/playbooks/` | Security response playbooks |
| **Endpoint Monitoring** | 🟡 Planned | `backend/endpoint_monitor/` | EDR-lite capabilities |
| **Risk Scoring** | 🟡 Planned | `backend/risk_scoring/` | Security risk calculation |

---

## Core Architecture Components

### 1. Security Telemetry Ingestion Layer

**Purpose:** Collect security logs from multiple sources

**Supported Sources:**
- Linux syslog (`/var/log/syslog`, `/var/log/auth.log`)
- Windows Event Logs (via WinRM or agent)
- Firewall logs (pfSense, UFW, iptables)
- IDS/IPS logs (Suricata, Zeek)
- DNS query logs (BIND, dnsmasq)
- Network flow logs (NetFlow, sFlow)
- Endpoint logs (process execution, file changes)

**Implementation:**
```python
from telemetry_ingestion.collector import TelemetryCollector

collector = TelemetryCollector()

# Collect various log types
syslog_entries = collector.collect_syslog(limit=1000)
firewall_logs = collector.collect_firewall_logs(limit=500)
ids_alerts = collector.collect_ids_logs(limit=500)
dns_queries = collector.collect_dns_logs(limit=500)
endpoint_events = collector.collect_endpoint_events(limit=500)
```

### 2. Log Normalization Engine

**Purpose:** Convert raw logs into standardized Common Event Format (CEF)

**Normalized Event Schema:**
```json
{
  "event_id": "evt_001",
  "timestamp": "2026-03-09T12:00:00Z",
  "source_type": "firewall",
  "source_ip": "203.0.113.50",
  "destination_ip": "192.168.1.100",
  "source_port": 54321,
  "destination_port": 22,
  "protocol": "TCP",
  "action": "BLOCK",
  "severity": "medium",
  "host": "firewall-01",
  "username": null,
  "process": null,
  "command": null,
  "raw_log": "Firewall block from 203.0.113.50"
}
```

### 3. Detection Engine

**Purpose:** Identify suspicious activity through rules and analytics

**Detection Methods:**

#### Rule-Based Detection
```python
# Example: Brute Force Detection
{
  "rule_id": "BRUTE_FORCE_001",
  "name": "SSH Brute Force Detection",
  "description": "Detect SSH brute force attempts",
  "condition": "failed_logins > 20 within 60 seconds from same source IP",
  "severity": "high",
  "mitre_attack": ["T1110.001"],
  "response": "block_ip"
}
```

#### IOC Matching
```python
# Match against known malicious indicators
{
  "indicator_type": "ip",
  "indicator_value": "203.0.113.50",
  "threat_type": "botnet_c2",
  "confidence": "high",
  "source": "threat_intel_feed"
}
```

#### Behavior Anomaly Detection
```python
# Detect unusual patterns
{
  "anomaly_type": "unusual_outbound_traffic",
  "baseline": "average 50MB/day",
  "current": "5GB in 1 hour",
  "deviation": "100x normal",
  "severity": "critical"
}
```

### 4. AI Investigation Agents

**Purpose:** Autonomous investigation of security alerts

**Agent Types:**

| Agent | Function | Example Actions |
|-------|----------|-----------------|
| **Threat Hunter** | Proactive threat search | Query logs, check IOCs, identify patterns |
| **Incident Investigator** | Alert investigation | Gather context, build timeline, assess impact |
| **Vulnerability Analyst** | Vulnerability assessment | Check CVEs, assess exploitability |
| **IOC Correlation** | Indicator matching | Match telemetry against threat intel |
| **Network Monitor** | Network anomaly detection | Identify unusual traffic patterns |

**Investigation Workflow:**
```
Alert Triggered
    ↓
Agent Activated
    ↓
Gather Related Events (±1 hour)
    ↓
Check Threat Intelligence
    ↓
Identify Attack Pattern (MITRE ATT&CK)
    ↓
Assess Severity & Impact
    ↓
Generate Investigation Report
    ↓
Recommend Response Actions
```

### 5. SOAR Response Engine

**Purpose:** Automated security response actions

**Response Actions:**

| Action | Description | Automation Level |
|--------|-------------|------------------|
| **Block IP** | Add to firewall blocklist | Fully Automated |
| **Disable Account** | Disable compromised user | Human Approval |
| **Terminate Process** | Kill suspicious process | Human Approval |
| **Isolate Host** | Network quarantine | Human Approval |
| **Update Rule** | Add detection rule | Semi-Automated |
| **Create Ticket** | Open incident ticket | Fully Automated |
| **Send Alert** | Notify SOC team | Fully Automated |

**Example Playbook:**
```yaml
playbook:
  name: "Brute Force Response"
  trigger: "BRUTE_FORCE_DETECTED"
  
  steps:
    - action: "enrich"
      source: "threat_intel"
      check: "Is source IP known malicious?"
    
    - action: "decision"
      condition: "ip_malicious == true"
      if_true: "block_ip"
      if_false: "rate_limit"
    
    - action: "notify"
      channel: "slack"
      message: "Brute force attack blocked"
    
    - action: "create_ticket"
      system: "jira"
      priority: "high"
```

### 6. Threat Intelligence Graph

**Purpose:** Knowledge graph for security intelligence

**Entity Types:**
- IP Address
- Domain
- Malware
- Threat Actor
- CVE/Vulnerability
- Host/Endpoint
- User Account
- Attack Technique (MITRE ATT&CK)

**Relationships:**
```
Threat Actor ─[uses]→ Malware
Malware ─[exploits]→ Vulnerability
Vulnerability ─[affects]→ Software
IP Address ─[hosts]→ Malware Infrastructure
Domain ─[resolves_to]→ IP Address
Threat Actor ─[targets]→ Industry Sector
Attack Technique ─[part_of]→ Tactic
```

### 7. Attack Path Analysis

**Purpose:** Model and analyze attacker movement

**Attack Chain Example:**
```
1. Initial Access (T1190)
   ↓ Exploit public-facing application
2. Execution (T1059)
   ↓ PowerShell command execution
3. Persistence (T1053)
   ↓ Scheduled task created
4. Credential Access (T1003)
   ↓ LSASS memory dump
5. Lateral Movement (T1021)
   ↓ SMB to internal host
6. Exfiltration (T1041)
   ↓ Data transfer to external IP
```

### 8. Security Risk Scoring

**Purpose:** Quantify security risk for prioritization

**Risk Score Calculation:**
```python
def calculate_host_risk(host):
    base_score = 0
    
    # Vulnerability risk (0-40)
    vuln_score = sum(cve['cvss_score'] for cve in host.cves) / len(host.cves) * 4
    base_score += min(40, vuln_score)
    
    # Exposure risk (0-30)
    if host.public_facing:
        base_score += 15
    if host.open_ports > 10:
        base_score += 15
    
    # Activity risk (0-30)
    if host.suspicious_connections:
        base_score += 15
    if host.failed_logins > 10:
        base_score += 15
    
    return min(100, base_score)
```

**Risk Levels:**
- **Critical (90-100):** Immediate action required
- **High (70-89):** Urgent attention needed
- **Medium (40-69):** Schedule remediation
- **Low (0-39):** Monitor and review

---

## API Endpoints

### Telemetry & Logs
```
POST /api/telemetry/ingest          - Ingest log entries
GET  /api/telemetry/query           - Query collected telemetry
GET  /api/logs/normalized           - Get normalized logs
GET  /api/logs/raw                   - Get raw logs
```

### Detection & Alerts
```
GET  /api/detections/rules           - List detection rules
POST /api/detections/rules           - Create detection rule
GET  /api/detections/alerts          - Get active alerts
POST /api/detections/alerts/resolve  - Resolve alert
```

### Investigation
```
POST /api/investigation/start        - Start investigation
GET  /api/investigation/{id}         - Get investigation status
GET  /api/investigation/{id}/report  - Get investigation report
```

### Response
```
POST /api/response/execute           - Execute response action
GET  /api/response/playbooks         - List playbooks
POST /api/response/playbooks/run     - Run playbook
```

### Threat Intelligence
```
GET  /api/threat-intel/iocs          - Query IOCs
GET  /api/threat-intel/actors        - Get threat actors
GET  /api/threat-intel/graph         - Query threat graph
```

---

## SOC Dashboards

### 1. Threat Landscape Dashboard
- Active alerts by severity
- Attack statistics
- Top threat actors
- Most targeted assets

### 2. Attack Map
- 3D globe visualization
- Animated attack arcs
- Threat actor attribution
- Real-time event streaming

### 3. Activity Log Console
- Real-time event feed
- Filterable by category/severity
- Search functionality
- Export capabilities

### 4. Network Exposure Map
- Discovered hosts
- Open ports
- Vulnerable services
- Risk scores

### 5. Threat Intelligence Graph
- Entity relationship visualization
- Interactive exploration
- Attack chain mapping

---

## Deployment Architecture

### Docker Services
```yaml
services:
  ollama:              # Local LLM runtime
  aisoc-backend:       # FastAPI application
  aisoc-frontend:      # Web dashboard
  postgres:            # (Optional) Event database
  redis:               # (Optional) Cache/queue
```

### Data Storage
```
/data/
├── telemetry/          # Raw collected logs
├── logs/
│   ├── raw/           # Original log files
│   └── normalized/    # Normalized events
├── detections/         # Detection alerts
├── incidents/          # Investigation cases
├── threat_intel/       # Intelligence datasets
└── vector_store/       # RAG embeddings
```

---

## Integration Points

### External Systems (Optional)
| System | Integration Method | Purpose |
|--------|-------------------|---------|
| **SIEM** | Syslog/CEF | Forward alerts |
| **Ticketing** | REST API | Create incidents |
| **Firewall** | SSH/API | Block malicious IPs |
| **EDR** | Agent API | Endpoint telemetry |
| **Slack/Teams** | Webhook | Alert notifications |

### Log Sources
| Source | Collection Method |
|--------|------------------|
| Linux Syslog | File monitoring |
| Windows Events | WinRM/agent |
| Firewall | Syslog/API |
| IDS/IPS | File monitoring |
| DNS | File monitoring |
| Network Flow | NetFlow collector |

---

## Security Considerations

### Data Protection
- All data stored locally
- Optional encryption at rest
- No external telemetry
- Air-gap capable

### Access Control
- API key authentication
- Role-based access (planned)
- Audit logging

### Secure Operations
- Run as non-root user
- Minimal network exposure
- Regular dependency updates

---

## Performance Specifications

| Metric | Target |
|--------|--------|
| Log Ingestion Rate | 10,000 events/second |
| Detection Latency | <1 second |
| Alert Generation | <5 seconds |
| RAG Query Response | <10 seconds |
| Dashboard Load | <3 seconds |

---

## Roadmap

### Phase 1 (Current) - Foundation ✅
- [x] RAG Engine
- [x] AI Agents
- [x] Network Analysis
- [x] Attack Map
- [x] Activity Log

### Phase 2 (In Progress) - Detection 🟡
- [ ] Log Normalization
- [ ] Detection Rules Engine
- [ ] IOC Matching
- [ ] Alert Management

### Phase 3 (Planned) - Response 📋
- [ ] SOAR Engine
- [ ] Playbooks
- [ ] Automated Blocking
- [ ] Incident Management

### Phase 4 (Planned) - Advanced 📋
- [ ] Machine Learning Anomaly Detection
- [ ] User Behavior Analytics
- [ ] Threat Hunting Queries
- [ ] Advanced Persistence Tracking

---

## Getting Started

### Quick Start
```bash
# Start all services
cd aisoc
docker-compose up -d

# Access dashboards
# Main Dashboard: http://localhost:3000
# Attack Map: http://localhost:3000/attack_map.html
# Activity Log: http://localhost:3000/activity_log.html
# API Docs: http://localhost:8000/docs
```

### Collect Initial Telemetry
```bash
# Run telemetry collection
curl -X POST http://localhost:8000/api/telemetry/collect

# View collected logs
curl http://localhost:8000/api/telemetry/query?limit=100
```

### Run Detection Engine
```bash
# Trigger detection scan
curl -X POST http://localhost:8000/api/detections/scan

# View active alerts
curl http://localhost:8000/api/detections/alerts
```

---

## Conclusion

The Autonomous AI-SOC platform provides a **comprehensive, local-first security operations capability** that combines:

- **Telemetry Collection** from multiple security sources
- **Log Normalization** for consistent analysis
- **Detection Engine** with rule-based and AI-powered detection
- **AI Investigation Agents** for automated analysis
- **SOAR Response** for automated containment
- **Threat Intelligence** correlation and graph analysis
- **SOC Dashboards** for real-time monitoring

All running **100% locally** with **no cloud dependencies**, ensuring **complete privacy** and **offline capability** while providing enterprise-grade security operations capabilities.

---

**AI-SOC** — Autonomous Security Intelligence, 100% Local

Built for security researchers, SOC analysts, and organizations that prioritize privacy and local-first security operations.
