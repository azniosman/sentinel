# AI-SOC Architecture

## System Overview

AI-SOC is a **local-first, offline-capable cybersecurity intelligence platform** that provides comprehensive security operations center capabilities without relying on any cloud services.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI-SOC Platform                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│  │   Frontend       │     │   Backend API    │     │   Local AI       │   │
│  │   Dashboard      │────▶│   (FastAPI)      │────▶│   Services       │   │
│  │   (Port 3000)    │     │   (Port 8000)    │     │   (Ollama)       │   │
│  │                  │     │                  │     │   (Port 11434)   │   │
│  └──────────────────┘     └──────────────────┘     └──────────────────┘   │
│           │                       │                          │             │
│           │                       ▼                          │             │
│           │              ┌──────────────────┐                │             │
│           │              │  Service Layer   │                │             │
│           │              │                  │                │             │
│           │              │ - RAG Engine     │                │             │
│           │              │ - Intelligence   │                │             │
│           │              │ - Network Scan   │                │             │
│           │              │ - IOC Correlation│                │             │
│           │              │ - Threat Graph   │                │             │
│           │              │ - Agents         │                │             │
│           │              │ - Simulation     │                │             │
│           │              └──────────────────┘                │             │
│           │                       │                          │             │
│           │                       ▼                          │             │
│           │              ┌──────────────────┐                │             │
│           │              │  Data Layer      │                │             │
│           │              │                  │                │             │
│           │              │ - ChromaDB       │◀───────────────┘             │
│           │              │ - JSON Files     │                              │
│           │              │ - NetworkX Graph │                              │
│           │              └──────────────────┘                              │
│           │                                                                  │
│           └────────────────── WebSocket ───────────────────────────────────┘
│                              (Real-time Logs)
│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Frontend Dashboard

**Technology:** Vanilla JavaScript, CSS Grid, WebSocket

**Components:**
- **Threat Landscape Panel** - Real-time statistics from threat intelligence
- **Recent Threats List** - Latest critical CVEs with severity indicators
- **AI Assistant Chat** - Natural language interface to RAG system
- **Network Exposure Map** - Visualization of scanned network
- **SOC Logs Console** - Real-time system activity via WebSocket

**Data Flow:**
```
User Action → API Call → Backend → Response → UI Update
                      ↓
                  WebSocket ← Real-time Logs
```

---

### 2. Backend API Layer

**Technology:** FastAPI, uvicorn, Pydantic

**Endpoints:**
```
/api/health                    - Health check
/api/threat-intel/summary      - Threat summary
/api/threat-intel/cves         - CVE database
/api/threat-intel/zero-days    - Zero-day alerts
/api/threat-intel/threat-actors - Threat actors
/api/rag/query                 - RAG-powered queries
/api/chat                      - AI chat interface
/api/network/scan              - Network scanning
/api/ioc/check                 - IOC correlation
/api/graph/query               - Threat graph queries
/api/simulation/run            - Attack simulation
/api/agents/status             - Agent status
/api/agents/{id}/trigger       - Trigger agent
/ws/logs                       - WebSocket for logs
```

**Security:**
- Optional API key authentication
- CORS configuration
- Rate limiting
- Input validation

---

### 3. Threat Ingestion Service

**Location:** `backend/threat_ingestion/`

**Data Sources:**
- **NVD API** - CVE database (https://services.nvd.nist.gov)
- **MITRE ATT&CK** - Attack techniques (GitHub)
- **CISA KEV** - Known exploited vulnerabilities

**Pipeline:**
```
Raw Feeds → Download → Parse → Validate → Transform → Store
              ↓                                    ↓
        /data/raw_feeds                     /data/threat_intel
```

**Schema:**
- `CVEMetric` - Vulnerability records
- `ZeroDayAlert` - Zero-day detections
- `ThreatActor` - APT/criminal group profiles
- `MalwareFamily` - Malware classifications
- `IOCRecord` - Indicators of compromise
- `SecurityAdvisory` - Vendor/CERT advisories

---

### 4. RAG Engine

**Location:** `backend/rag/`

**Components:**
- **Embedding Model** - sentence-transformers (all-MiniLM-L6-v2)
- **Vector Database** - ChromaDB (persistent storage)
- **LLM Interface** - Ollama (Llama 3, Mistral, etc.)

**Pipeline:**
```
User Query
    ↓
Embedding Generation (sentence-transformers)
    ↓
Vector Search (ChromaDB cosine similarity)
    ↓
Top-K Document Retrieval
    ↓
Context Construction
    ↓
LLM Prompt Building
    ↓
Response Generation (Ollama)
    ↓
Answer + Sources
```

**Optimization:**
- Batch embedding generation
- Persistent vector storage
- Cosine similarity search
- Source attribution

---

### 5. Intelligence Engine

**Location:** `backend/intelligence_engine/`

**Capabilities:**

**Zero-Day Detection:**
```python
risk_score = (
    CVSS_score ×           # Base severity
    exploit_multiplier ×   # 1.5x if exploit available
    patch_factor ×         # 0.5x if patch available
    active_multiplier ×    # 2.0x if active exploitation
    epss_adjustment        # 1.0 + EPSS score
)
```

**Threat Correlation:**
- CVE to MITRE ATT&CK mapping
- Threat actor to malware association
- Campaign pattern detection
- Exploit trend analysis

**Risk Scoring:**
- CVSS-based severity
- EPSS exploitation probability
- Active exploitation status
- Patch availability

---

### 6. Network Analysis

**Location:** `backend/network_analysis/`

**Scanning Modes:**
- **Basic** - Top 100 ports, fast scan
- **Full** - All ports, service version detection
- **Aggressive** - OS detection, scripts, vuln scanning

**Fallback Scanner:**
When nmap is unavailable, uses socket-based scanning:
- SYN connect scan
- Service identification by port
- Basic vulnerability heuristics

**Vulnerability Matching:**
```
Detected Service → Product/Version → CVE Database → Vulnerabilities
```

**Output:**
- Host discovery
- Open ports
- Running services
- Potential vulnerabilities
- Remediation recommendations

---

### 7. IOC Correlation Engine

**Location:** `backend/ioc_correlation/`

**IOC Types:**
- IP addresses
- Domains
- File hashes (MD5, SHA1, SHA256)
- URLs
- Email addresses
- File paths
- Registry keys

**Correlation Methods:**
- Exact matching
- Subdomain matching
- Pattern detection (DGA domains)
- Campaign association
- Risk level calculation

**Bulk Analysis:**
```
Input: List of IOCs
    ↓
Parallel Lookup
    ↓
Aggregation
    ↓
Risk Summary
    ↓
Recommended Actions
```

---

### 8. Threat Graph

**Location:** `backend/threat_graph/`

**Technology:** NetworkX (MultiDiGraph)

**Entity Types:**
- Threat Actor
- Malware
- Vulnerability (CVE)
- Attack Technique (MITRE ATT&CK)
- Industry Target
- Infrastructure Node

**Relationships:**
- `uses` - Threat Actor → Malware
- `exploits` - Malware → Vulnerability
- `targets` - Threat Actor → Industry
- `mitigates` - Control → Vulnerability
- `related_to` - Generic association

**Query Types:**
- Entity lookup
- Neighborhood exploration
- Path finding
- Subgraph extraction
- Statistics

---

### 9. Attack Simulation

**Location:** `backend/attack_simulation/`

**Scenarios:**
1. **Phishing Campaign** - Spear-phishing with malicious attachment
2. **Web App Exploitation** - SQL injection / RCE
3. **Insider Threat** - Data exfiltration
4. **Ransomware Deployment** - Network-wide encryption

**Simulation Steps:**
```
Reconnaissance → Weaponization → Delivery → Execution → Persistence → C2
```

**Detection Validation:**
- Each step has detection opportunities
- Simulated detection (50% probability)
- Gap analysis
- Recommendations

**Educational Purpose:**
- NOT real attack execution
- Simulation only
- Detection testing
- Security control validation

---

### 10. AI Security Agents

**Location:** `backend/agents/`

**Agent Types:**

| Agent | Purpose | Interval |
|-------|---------|----------|
| **Threat Hunter** | Analyze emerging threats | 6 hours |
| **Vulnerability Analyst** | Prioritize CVEs | 6 hours |
| **Network Monitor** | Detect anomalies | 6 hours |
| **IOC Correlation** | Match indicators | 6 hours |
| **Attack Simulation** | Run scenarios | On-demand |

**Agent Architecture:**
```python
class BaseAgent:
    async def execute(parameters) -> Dict:
        # Agent-specific logic
        pass
    
    async def run(parameters) -> Dict:
        # Error handling, logging, state management
```

**Orchestration:**
- Sequential or parallel execution
- Result aggregation
- Cross-agent correlation
- Report generation

---

### 11. Scheduler

**Location:** `backend/scheduler/`

**Technology:** APScheduler (AsyncIOScheduler)

**Scheduled Tasks:**

| Task | Interval | Description |
|------|----------|-------------|
| `cve_update` | 6 hours | Download NVD CVE feed |
| `embedding_update` | 12 hours | Refresh vector embeddings |
| `network_scan` | 6 hours | Scan default targets |
| `threat_intel_update` | 6 hours | Full ingestion pipeline |
| `agent_run` | 6 hours | Execute all agents |

**Task Management:**
- Start/stop control
- Manual trigger
- Status tracking
- Error handling

---

## Data Flow

### Threat Intelligence Ingestion

```
External APIs (NVD, MITRE, CISA)
    ↓
ThreatIngestionService
    ↓
Raw JSON Files (/data/raw_feeds)
    ↓
Schema Validation
    ↓
Transformation
    ↓
Processed JSON (/data/threat_intel)
    ↓
RAG Engine (embeddings)
    ↓
ChromaDB (vector store)
```

### RAG Query Flow

```
User Query (Frontend)
    ↓
FastAPI Endpoint
    ↓
RAG Engine
    ↓
Embedding Generation
    ↓
ChromaDB Search
    ↓
Top-K Documents
    ↓
Context Builder
    ↓
LLM Prompt
    ↓
Ollama (Llama 3)
    ↓
Response + Sources
    ↓
Frontend Display
```

### Network Scan Flow

```
User Request (Frontend)
    ↓
FastAPI Endpoint
    ↓
NetworkAnalyzer
    ↓
nmap / socket scan
    ↓
Raw Results
    ↓
Vulnerability Matching
    ↓
Risk Assessment
    ↓
Results Storage
    ↓
Frontend Display
```

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────┐
│          Network Layer                  │
│  - Localhost binding (default)          │
│  - CORS configuration                   │
│  - Rate limiting                        │
├─────────────────────────────────────────┤
│          Application Layer              │
│  - Input validation                     │
│  - API key authentication (optional)    │
│  - WebSocket origin checking            │
├─────────────────────────────────────────┤
│          Data Layer                     │
│  - No external telemetry                │
│  - Local storage only                   │
│  - Optional encryption at rest          │
├─────────────────────────────────────────┤
│          AI Layer                       │
│  - Local LLM (no cloud API calls)       │
│  - Local embeddings                     │
│  - Air-gappable                         │
└─────────────────────────────────────────┘
```

### Privacy Guarantees

1. **No Cloud Dependencies** - All processing local
2. **No Telemetry** - No analytics or tracking
3. **No External Calls** - After initial setup
4. **Data Locality** - All data stays on device
5. **Optional Encryption** - For stored datasets

---

## Deployment Architecture

### Docker Compose

```yaml
services:
  ollama:        # Local LLM runtime
    port: 11434
    volumes: ollama_data
  
  aisoc-backend: # FastAPI application
    port: 8000
    volumes: data, vector_store
    depends_on: ollama
  
  aisoc-frontend: # Nginx static server
    port: 3000
    depends_on: backend
```

### Volumes

- `ollama_data` - LLM models
- `aisoc_data` - Threat intelligence datasets
- `aisoc_vector_store` - ChromaDB vectors

### Network

- Isolated bridge network
- Internal service communication
- Port mapping for external access

---

## Observability

### Logging

**Technology:** structlog (structured JSON logging)

**Log Levels:**
- DEBUG - Detailed technical information
- INFO - Normal operations
- WARNING - Potential issues
- ERROR - Errors that don't stop the system
- CRITICAL - System-stopping errors

**Log Events:**
- `[CVE_FEED_UPDATED]` - Feed ingestion
- `[THREAT_DATASET_PROCESSED]` - Dataset processing
- `[ZERO_DAY_ALERT]` - Zero-day detection
- `[RAG_QUERY_EXECUTED]` - AI queries
- `[NETWORK_SCAN_COMPLETED]` - Scan results
- `[IOC_MATCH_DETECTED]` - IOC correlation
- `[AGENT_EXECUTED]` - Agent runs

### Real-time Monitoring

**WebSocket Endpoint:** `/ws/logs`

**Log Format:**
```json
{
  "level": "INFO",
  "timestamp": "2024-01-01T12:00:00Z",
  "message": "CVE feed updated",
  "source": "aisoc",
  "data": {"cves_downloaded": 150}
}
```

---

## Performance Considerations

### Bottlenecks

1. **LLM Inference** - Slowest operation (seconds)
2. **Embedding Generation** - Moderate (milliseconds per document)
3. **Vector Search** - Fast (milliseconds)
4. **Network Scanning** - Variable (depends on network size)

### Optimizations

- **Batch Processing** - Embeddings in batches
- **Caching** - Frequent queries cached
- **Async I/O** - Non-blocking operations
- **GPU Acceleration** - Ollama with NVIDIA GPU
- **Model Selection** - Smaller models for speed

### Resource Usage

| Operation | CPU | RAM | Time |
|-----------|-----|-----|------|
| LLM Query | High | 4-8GB | 2-10s |
| Embedding | Medium | 1-2GB | 100ms/doc |
| Vector Search | Low | <1GB | <50ms |
| Network Scan | Medium | <1GB | 1-60s |

---

## Extensibility

### Adding New Data Sources

1. Create download method in `ThreatIngestionService`
2. Define schema in `threat_ingestion/schema.py`
3. Add to ingestion pipeline
4. Create embeddings for RAG

### Adding New Agents

1. Inherit from `BaseAgent`
2. Implement `execute()` method
3. Register in `AgentOrchestrator`
4. Configure schedule

### Adding New IOC Types

1. Update `IOCRecord` schema
2. Add to `IOCCorrelator` index
3. Implement matching logic
4. Update frontend display

---

## Future Enhancements

### Planned Features

- [ ] STIX/TAXII integration
- [ ] YARA rule matching
- [ ] Sandbox integration (Cuckoo, Joe Sandbox)
- [ ] Threat intel sharing (MISP)
- [ ] Advanced graph visualization
- [ ] Machine learning anomaly detection
- [ ] Automated playbooks
- [ ] Multi-tenant support

### Research Areas

- Federated learning for threat detection
- Privacy-preserving IOC sharing
- Adversarial ML robustness
- Automated threat report generation

---

## Conclusion

AI-SOC provides a **comprehensive, local-first security operations platform** that combines:

- **Threat Intelligence** - CVE, zero-days, threat actors
- **AI-Powered Analysis** - RAG, LLM, autonomous agents
- **Network Security** - Scanning, vulnerability matching
- **Threat Hunting** - IOC correlation, graph analysis
- **Education** - Attack simulation, detection validation

All running **100% locally** with **no cloud dependencies**, ensuring **complete privacy** and **offline capability**.
