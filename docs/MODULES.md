# AI-SOC Module Documentation

Comprehensive documentation for all AI-SOC backend modules.

---

## Module Index

| Module | Path | Purpose |
|--------|------|---------|
| [**Main API**](#main-api) | `backend/main.py` | FastAPI application and endpoints |
| [**Configuration**](#configuration) | `backend/config.py` | Settings and environment management |
| [**Threat Ingestion**](#threat-ingestion) | `backend/threat_ingestion/` | Threat feed download and processing |
| [**RAG Engine**](#rag-engine) | `backend/rag/` | Retrieval-Augmented Generation pipeline |
| [**Intelligence Engine**](#intelligence-engine) | `backend/intelligence_engine/` | Zero-day detection and analysis |
| [**Network Analysis**](#network-analysis) | `backend/network_analysis/` | Network scanning and vulnerability detection |
| [**IOC Correlation**](#ioc-correlation) | `backend/ioc_correlation/` | Indicator of Compromise matching |
| [**AI Security Agents**](#ai-security-agents) | `backend/agents/` | Autonomous threat hunting agents |
| [**Threat Graph**](#threat-graph) | `backend/threat_graph/` | Graph-based threat relationship mapping |
| [**Attack Simulation**](#attack-simulation) | `backend/attack_simulation/` | Educational attack scenarios |
| [**Scheduler**](#scheduler) | `backend/scheduler/` | Automated task scheduling |

---

## Main API

**File:** `backend/main.py`

### Overview

The main FastAPI application that provides all REST API endpoints and WebSocket connections for the AI-SOC platform.

### Key Components

#### Application Lifespan

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize all services
    # Shutdown: Clean shutdown of services
```

**Startup Sequence:**
1. Initialize ThreatIngestionService
2. Initialize RAGEngine
3. Initialize IntelligenceEngine
4. Initialize NetworkAnalyzer
5. Initialize IOCCorrelator
6. Initialize AttackSimulator
7. Initialize ThreatGraph
8. Initialize AgentOrchestrator
9. Initialize IntelligenceScheduler
10. Load threat data into graph
11. Start scheduled tasks

### API Endpoints

#### Health & Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint with service info |
| `/api/health` | GET | Detailed health check |

#### Threat Intelligence

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/threat-intel/summary` | GET | Get threat intelligence summary |
| `/api/threat-intel/cves` | GET | Get CVE database with filtering |
| `/api/threat-intel/zero-days` | GET | Get zero-day vulnerability alerts |
| `/api/threat-intel/threat-actors` | GET | Get threat actor profiles |
| `/api/threat-intel/mitre-attack` | GET | Get MITRE ATT&CK data |

#### RAG & AI

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rag/query` | POST | Query threat intel using RAG |
| `/api/chat` | POST | AI chat interface |

#### Network Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/scan` | POST | Initiate network scan |
| `/api/network/results` | GET | Get latest scan results |

#### IOC Correlation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ioc/check` | POST | Check single IOC |
| `/api/ioc/bulk-check` | POST | Bulk check multiple IOCs |

#### Attack Simulation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulation/run` | POST | Run attack simulation |
| `/api/simulation/scenarios` | GET | Get available scenarios |

#### Threat Graph

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/graph/query` | POST | Query threat graph |
| `/api/graph/entities` | GET | Get entity types |

#### AI Agents

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/agents/status` | GET | Get agent status |
| `/api/agents/{agent_id}/trigger` | POST | Trigger specific agent |

#### Maintenance

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ingestion/update` | POST | Trigger threat feed ingestion |

#### WebSocket

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ws/logs` | WebSocket | Real-time SOC logs |

### Security

- **API Key Authentication**: Optional, configured via `API_KEY` environment variable
- **CORS**: Configured for allowed origins only
- **Input Validation**: Pydantic models for all requests

### Example Usage

```bash
# Health check
curl http://localhost:8000/api/health

# Query threat intelligence
curl -X POST http://localhost:8000/api/rag/query \
  -H "Content-Type: application/json" \
  -d '{"query": "latest critical CVEs", "top_k": 5}'

# Network scan
curl -X POST http://localhost:8000/api/network/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "basic"}'
```

---

## Configuration

**File:** `backend/config.py`

### Overview

Centralized configuration management using Pydantic Settings with environment variable support.

### Settings Categories

#### Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `AI-SOC Backend` | Application name |
| `APP_VERSION` | `1.0.0` | Version number |
| `DEBUG` | `True` | Debug mode |
| `LOG_LEVEL` | `INFO` | Logging level |

#### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8000` | Port number |
| `ALLOWED_ORIGINS` | `[localhost:3000, ...]` | CORS origins |

#### LLM Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama endpoint |
| `LLM_MODEL` | `llama3` | LLM for generation |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Embedding model |
| `LLM_TEMPERATURE` | `0.1` | LLM temperature |
| `LLM_MAX_TOKENS` | `2048` | Max response tokens |

#### Vector Database Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `VECTOR_STORE_PATH` | `./vector_store/chroma_db` | ChromaDB path |
| `VECTOR_STORE_COLLECTION` | `threat_intelligence` | Collection name |

#### Data Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `./data` | Data root directory |
| `THREAT_INTEL_DIR` | `./data/threat_intel` | Processed intel |
| `RAW_FEEDS_DIR` | `./data/raw_feeds` | Raw feeds |

#### Network Analysis Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_SCAN_TARGETS` | `["192.168.1.0/24", ...]` | Scan targets |
| `SCAN_TIMEOUT` | `300` | Scan timeout (seconds) |
| `MAX_CONCURRENT_SCANS` | `5` | Max concurrent scans |

#### Scheduler Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_ENABLED` | `True` | Enable scheduler |
| `CVE_UPDATE_INTERVAL_HOURS` | `6` | CVE update interval |
| `EMBEDDING_UPDATE_INTERVAL_HOURS` | `12` | Embedding refresh |
| `NETWORK_SCAN_INTERVAL_HOURS` | `6` | Network scan interval |
| `THREAT_INTEL_UPDATE_INTERVAL_HOURS` | `6` | Intel update interval |

#### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `None` | Optional API key |
| `ENCRYPT_DATA_AT_REST` | `False` | Enable encryption |
| `ENCRYPTION_KEY` | `None` | Encryption key |

#### Threat Intelligence Sources

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_URL` | `https://services.nvd.nist.gov/...` | NVD CVE API |
| `MITRE_ATTACK_URL` | `https://raw.githubusercontent.com/...` | MITRE ATT&CK |
| `CISA_KNOWN_EXPLOITED_URL` | `https://www.cisa.gov/...` | CISA KEV |

### Usage

```python
from config import settings

# Access settings
print(settings.OLLAMA_HOST)
print(settings.PORT)

# Ensure directories exist
from config import ensure_directories
ensure_directories()
```

### Environment File

Create `.env` file in `backend/` directory:

```bash
# .env
HOST=0.0.0.0
PORT=8000
DEBUG=false
LOG_LEVEL=INFO
OLLAMA_HOST=http://ollama:11434
LLM_MODEL=llama3
API_KEY=your-secure-key
```

---

## Threat Ingestion

**Files:** `backend/threat_ingestion/`

### Overview

Automated threat intelligence feed ingestion from multiple sources including NVD, MITRE ATT&CK, and CISA.

### Module Structure

```
threat_ingestion/
├── __init__.py
├── schema.py        # Pydantic data models
└── ingestion.py     # Feed download and processing
```

### Data Models (`schema.py`)

#### SeverityLevel (Enum)

```python
class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
```

#### CVEMetric

CVE vulnerability record with 35 fields:

```python
class CVEMetric(BaseModel):
    cve_id: str                    # CVE-YYYY-NNNNN
    description: str               # Vulnerability description
    cvss_score: float              # CVSS severity score
    cvss_vector: str               # CVSS vector string
    severity: SeverityLevel        # Severity classification
    published_date: datetime       # Publication date
    last_modified: datetime        # Last modification
    # ... 29 more fields
```

#### ZeroDayAlert

Zero-day vulnerability alert:

```python
class ZeroDayAlert(BaseModel):
    alert_id: str                  # Unique identifier
    cve_id: Optional[str]          # Associated CVE
    title: str                     # Alert title
    risk_score: float              # Calculated risk (0-100)
    affected_products: List[str]   # Affected software
    exploit_available: bool        # Exploit availability
    patch_available: bool          # Patch availability
    active_exploitation: bool      # Active in the wild
    # ... more fields
```

#### ThreatActor

APT and criminal group profiles:

```python
class ThreatActor(BaseModel):
    actor_id: str                  # Unique identifier
    name: str                      # Actor name
    aliases: List[str]             # Known aliases
    type: str                      # Nation-state, criminal, etc.
    country: Optional[str]         # Origin country
    motivation: List[str]          # Espionage, financial, etc.
    targeted_industries: List[str] # Targeted sectors
    associated_malware: List[str]  # Malware used
    # ... more fields
```

#### IOCRecord

Indicator of Compromise:

```python
class IOCRecord(BaseModel):
    ioc_id: str                    # Unique identifier
    ioc_type: str                  # ip, domain, hash, url, etc.
    value: str                     # IOC value
    severity: SeverityLevel        # Severity level
    confidence: int                # Confidence (0-100)
    source: str                    # Intelligence source
    # ... more fields
```

### Ingestion Service (`ingestion.py`)

#### ThreatIngestionService

Main service class for threat feed ingestion.

**Methods:**

```python
async def download_cve_feed() -> List[CVEMetric]
    """Download CVE feed from NVD API."""

async def download_mitre_attack_dataset() -> Dict
    """Download MITRE ATT&CK STIX data."""

async def download_cisa_known_exploited() -> List[Dict]
    """Download CISA Known Exploited Vulnerabilities."""

async def download_security_advisories() -> List[SecurityAdvisory]
    """Download security advisories from RSS feeds."""

async def process_and_save_datasets() -> Dict
    """Process all feeds and save to disk."""

async def run_full_ingestion() -> Dict
    """Run complete ingestion pipeline."""
```

### Ingestion Pipeline

```
External APIs
    ↓
Download (HTTP)
    ↓
Parse (JSON/XML)
    ↓
Validate (Pydantic)
    ↓
Transform
    ↓
Store (JSON files)
    ↓
Embed (RAG)
    ↓
Vector DB (ChromaDB)
```

### Usage Example

```python
from threat_ingestion.ingestion import ThreatIngestionService

service = ThreatIngestionService()

# Run full ingestion
results = await service.run_full_ingestion()
print(f"Downloaded {results['cves']} CVEs")

# Download specific feed
cves = await service.download_cve_feed()
```

### Data Sources

| Source | URL | Update Frequency |
|--------|-----|------------------|
| NVD CVE | https://services.nvd.nist.gov | Every 6 hours |
| MITRE ATT&CK | GitHub | Monthly |
| CISA KEV | https://www.cisa.gov | Daily |

---

## RAG Engine

**File:** `backend/rag/rag_engine.py`

### Overview

Retrieval-Augmented Generation engine for semantic search over threat intelligence using local embeddings and LLM.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     RAG Pipeline                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  User Query                                              │
│      ↓                                                   │
│  ┌─────────────────┐                                    │
│  │ Embedding Model │ sentence-transformers              │
│  │ (all-MiniLM-L6) │                                    │
│  └─────────────────┘                                    │
│      ↓                                                   │
│  ┌─────────────────┐                                    │
│  │  Vector Search  │ ChromaDB cosine similarity         │
│  └─────────────────┘                                    │
│      ↓                                                   │
│  ┌─────────────────┐                                    │
│  │ Top-K Documents │ Retrieved context                  │
│  └─────────────────┘                                    │
│      ↓                                                   │
│  ┌─────────────────┐                                    │
│  │  Context Build  │ Prompt construction                │
│  └─────────────────┘                                    │
│      ↓                                                   │
│  ┌─────────────────┐                                    │
│  │  LLM (Ollama)   │ llama3, mistral, etc.              │
│  └─────────────────┘                                    │
│      ↓                                                   │
│  Response + Sources                                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### RAGEngine Class

**Methods:**

```python
async def generate_embedding(text: str) -> List[float]
    """Generate embedding vector for text."""

async def add_document(document: str, metadata: Dict) -> str
    """Add document to vector store."""

async def add_threat_intelligence(record: Dict) -> str
    """Add threat intel record with auto-metadata."""

async def query(query: str, top_k: int = 5, include_sources: bool = True) -> Dict
    """Query threat intelligence using RAG."""

async def _query_llm(query: str, context: str) -> str
    """Query Ollama LLM with context."""

async def bulk_ingest_documents(documents: List[Dict]) -> int
    """Bulk ingest multiple documents."""

async def get_collection_stats() -> Dict
    """Get vector store statistics."""
```

### Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence transformer |
| `VECTOR_STORE_COLLECTION` | `threat_intelligence` | ChromaDB collection |
| `LLM_MODEL` | `llama3` | Ollama LLM model |
| `LLM_TEMPERATURE` | `0.1` | Response creativity |
| `LLM_MAX_TOKENS` | `2048` | Max response length |

### Query Process

1. **Embedding Generation**: Convert query to 384-dimensional vector
2. **Vector Search**: Find top-K similar documents using cosine similarity
3. **Context Building**: Construct prompt with retrieved documents
4. **LLM Query**: Send prompt to Ollama for response generation
5. **Response**: Return answer with source attribution

### Example Usage

```python
from rag.rag_engine import RAGEngine

engine = RAGEngine()

# Query threat intelligence
response = await engine.query(
    query="What are the most critical CVEs exploited by ransomware?",
    top_k=5,
    include_sources=True
)

print(response['answer'])
print(response['sources'])  # Document sources

# Add custom document
doc_id = await engine.add_document(
    document="Your threat report content...",
    metadata={"source": "custom", "type": "report"}
)
```

### Performance

| Operation | Latency | Notes |
|-----------|---------|-------|
| Embedding | ~100ms/doc | Batch processing available |
| Vector Search | <50ms | Cosine similarity |
| LLM Response | 2-10s | Depends on model size |

### Storage

- **Location**: `vector_store/chroma_db/`
- **Format**: ChromaDB persistent storage
- **Size**: ~10MB per 1,000 documents

---

## Intelligence Engine

**File:** `backend/intelligence_engine/analyzer.py`

### Overview

Core intelligence analysis engine providing zero-day detection, risk scoring, and threat correlation.

### IntelligenceEngine Class

**Methods:**

```python
async def load_datasets() -> Dict
    """Load threat intelligence from disk."""

async def calculate_zero_day_risk_score(cve: CVEMetric) -> float
    """Calculate risk score for potential zero-day."""

async def detect_zero_day_vulnerabilities() -> List[ZeroDayAlert]
    """Detect zero-day vulnerabilities from CVE data."""

async def map_cve_to_mitre_attack(cve_id: str) -> List[Dict]
    """Map CVE to MITRE ATT&CK techniques."""

async def get_threat_summary() -> Dict
    """Get comprehensive threat summary."""

async def get_cves(severity: str = None, limit: int = 50) -> List[CVEMetric]
    """Get CVE entries with filtering."""

async def get_zero_day_alerts() -> List[ZeroDayAlert]
    """Get zero-day vulnerability alerts."""

async def get_threat_actors() -> List[ThreatActor]
    """Get threat actor profiles."""

async def get_mitre_attack_data() -> Dict
    """Get MITRE ATT&CK framework data."""

async def correlate_threat_actor_activity(actor_name: str) -> Dict
    """Correlate threat actor with recent activity."""

async def detect_exploit_trends() -> Dict
    """Detect trending exploits and vulnerabilities."""
```

### Zero-Day Detection Algorithm

```python
risk_score = (
    cvss_score *                    # Base severity (0-10)
    exploit_multiplier *            # 1.5x if exploit available
    patch_factor *                  # 0.5x if patch available
    active_exploitation_multiplier * # 2.0x if active in wild
    (1.0 + epss_score)              # EPSS probability adjustment
)

# Risk thresholds:
# 80-100: CRITICAL
# 60-80:  HIGH
# 40-60:  MEDIUM
# <40:    LOW
```

### Risk Factors

| Factor | Multiplier | Description |
|--------|------------|-------------|
| Exploit Available | 1.5x | Public exploit code |
| Patch Available | 0.5x | Vendor patch exists |
| Active Exploitation | 2.0x | Being exploited in wild |
| EPSS Score | 1.0 + EPSS | Exploitation probability |

### MITRE ATT&CK Mapping

Maps CVEs to attack techniques:

```
CVE → CWE → MITRE ATT&CK Technique → Tactic
```

Example:
- CVE-2021-44228 (Log4Shell)
- CWE-502 (Deserialization)
- T1190 (Exploit Public-Facing Application)
- TA0001 (Initial Access)

### Example Usage

```python
from intelligence_engine.analyzer import IntelligenceEngine

engine = IntelligenceEngine()

# Get threat summary
summary = await engine.get_threat_summary()
print(f"Total CVEs: {summary['total_cves']}")
print(f"Critical: {summary['critical_cves']}")

# Get zero-day alerts
zero_days = await engine.get_zero_day_alerts()
for alert in zero_days:
    print(f"{alert.cve_id}: Risk {alert.risk_score}")

# Map CVE to MITRE ATT&CK
mapping = await engine.map_cve_to_mitre_attack("CVE-2024-1234")
```

---

## Network Analysis

**File:** `backend/network_analysis/scanner.py`

### Overview

Network scanning and vulnerability detection using nmap integration with fallback socket scanner.

### NetworkAnalyzer Class

**Methods:**

```python
async def scan(targets: List[str], scan_type: str = "basic", ports: str = None) -> Dict
    """Scan network targets."""

async def _nmap_scan(targets: List[str], scan_type: str) -> Dict
    """Perform nmap scan (if available)."""

async def _fallback_scan(targets: List[str]) -> Dict
    """Fallback socket-based scanner."""

async def _get_service_name(port: int, protocol: str) -> str
    """Get service name for port."""

async def _check_service_vulnerabilities(service: Dict) -> List[Dict]
    """Check service for known vulnerabilities."""

async def _save_scan_results(results: Dict) -> str
    """Save scan results to disk."""

async def get_latest_results() -> Dict
    """Get latest scan results."""

async def identify_hosts(targets: List[str]) -> List[str]
    """Identify live hosts."""

async def detect_open_ports(host: str) -> List[Dict]
    """Detect open ports on host."""

async def identify_running_services(host: str) -> List[Dict]
    """Identify running services."""

async def match_services_to_vulnerabilities(services: List[Dict]) -> Dict
    """Match services to known vulnerabilities."""
```

### Scan Types

| Type | Description | Ports | Time |
|------|-------------|-------|------|
| **Basic** | Top 100 ports, fast | 1-1000 | ~10s |
| **Full** | All ports, version detection | 1-65535 | ~60s |
| **Aggressive** | OS detection, scripts | 1-65535 | ~120s |

### Scanning Modes

#### Nmap Scanner (Primary)

Uses python-nmap library when available:

```python
import nmap
nm = nmap.PortScanner()
nm.scan(hosts=target, arguments='-sV -sC')
```

#### Fallback Scanner

Pure Python socket-based scanner:

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)
result = sock.connect_ex((host, port))
```

### Vulnerability Matching

```
Detected Service
    ↓
Product/Version Extraction
    ↓
CVE Database Lookup
    ↓
Matching Vulnerabilities
    ↓
Risk Assessment
```

### Example Usage

```python
from network_analysis.scanner import NetworkAnalyzer

analyzer = NetworkAnalyzer()

# Basic scan
results = await analyzer.scan(
    targets=["192.168.1.0/24"],
    scan_type="basic"
)

# Full scan with custom ports
results = await analyzer.scan(
    targets=["192.168.1.1"],
    scan_type="full",
    ports="22,80,443,8080"
)

# Get results
print(f"Hosts found: {results['hosts']}")
print(f"Open ports: {results['open_ports']}")
print(f"Vulnerabilities: {results['vulnerabilities']}")
```

### Output Format

```json
{
  "scan_id": "scan_20240101_120000",
  "timestamp": "2024-01-01T12:00:00Z",
  "targets": ["192.168.1.0/24"],
  "scan_type": "basic",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "status": "up",
      "hostname": "router.local",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "nginx 1.18.0",
          "vulnerabilities": []
        }
      ]
    }
  ],
  "summary": {
    "total_hosts": 10,
    "hosts_up": 5,
    "total_open_ports": 25
  }
}
```

---

## IOC Correlation

**File:** `backend/ioc_correlation/correlator.py`

### Overview

Indicator of Compromise (IOC) correlation and matching engine for threat intelligence.

### IOCCorrelator Class

**Methods:**

```python
async def load_ioc_database() -> List[IOCRecord]
    """Load IOC database from disk."""

async def _build_ioc_index() -> Dict
    """Build index for fast IOC lookup."""

async def add_ioc(ioc: IOCRecord) -> str
    """Add IOC to database."""

async def check_ioc(ioc_type: str, value: str) -> Dict
    """Check single IOC against database."""

async def _ioc_matches(ioc: IOCRecord, query: str) -> bool
    """Check if IOC matches query."""

async def _check_partial_matches(query: str) -> List[Dict]
    """Check for partial matches (subdomains, etc.)."""

async def _calculate_risk_level(matches: List[Dict]) -> str
    """Calculate overall risk level."""

async def _get_recommended_actions(risk_level: str, ioc_type: str) -> List[str]
    """Get recommended response actions."""

async def bulk_check(iocs: List[IOCQuery]) -> List[Dict]
    """Bulk check multiple IOCs."""

async def match_ip_to_known_threat_actor(ip: str) -> Optional[ThreatActor]
    """Match IP to known threat actor."""

async def detect_malware_hash_matches(hash_value: str) -> List[Dict]
    """Check hash against malware database."""

async def identify_malicious_domains(domain: str) -> Dict
    """Check domain for malicious indicators."""

async def correlate_ioc_patterns(iocs: List[str]) -> Dict
    """Correlate IOC patterns for campaign detection."""
```

### IOC Types

| Type | Description | Matching |
|------|-------------|----------|
| `ip` | IP addresses | Exact, subnet |
| `domain` | Domain names | Exact, subdomain |
| `hash` | File hashes (MD5/SHA1/SHA256) | Exact |
| `url` | URLs | Exact, pattern |
| `email` | Email addresses | Exact, domain |
| `file_path` | File system paths | Pattern |
| `registry_key` | Windows registry | Pattern |

### Risk Calculation

```python
def _calculate_risk_level(matches):
    if any(m['confidence'] > 90 for m in matches):
        return "CRITICAL"
    elif any(m['confidence'] > 70 for m in matches):
        return "HIGH"
    elif any(m['confidence'] > 50 for m in matches):
        return "MEDIUM"
    else:
        return "LOW"
```

### Pattern Detection

#### DGA Domain Detection

Detects Domain Generation Algorithm (DGA) domains:

```python
def _detect_dga_domains(domains: List[str]) -> List[str]:
    # Check for:
    # - High entropy
    # - Unusual length
    # - Random character patterns
    # - Uncommon TLDs
```

#### Campaign Correlation

Groups related IOCs:

```
IP: 192.168.1.100 ─┬─→ Domain: evil.com
                   └─→ Hash: abc123...
                   
Campaign: APT29 Campaign
Confidence: 85%
```

### Example Usage

```python
from ioc_correlation.correlator import IOCCorrelator

correlator = IOCCorrelator()

# Check single IOC
result = await correlator.check_ioc(
    ioc_type="ip",
    value="192.168.1.100"
)
print(f"Risk: {result['risk_level']}")
print(f"Actions: {result['recommended_actions']}")

# Bulk check
iocs = [
    {"ioc_type": "ip", "value": "1.2.3.4"},
    {"ioc_type": "domain", "value": "malicious.com"},
    {"ioc_type": "hash", "value": "abc123..."}
]
results = await correlator.bulk_check(iocs)

# Pattern correlation
patterns = await correlator.correlate_ioc_patterns(
    ["1.2.3.4", "evil.com", "abc123..."]
)
```

### Response Format

```json
{
  "query": "192.168.1.100",
  "ioc_type": "ip",
  "match_found": true,
  "risk_level": "HIGH",
  "confidence": 85,
  "matches": [
    {
      "ioc_id": "ioc_001",
      "source": "threat_feed",
      "confidence": 85,
      "associated_actor": "APT29",
      "campaign": "SolarWinds"
    }
  ],
  "recommended_actions": [
    "Block IP at firewall",
    "Search logs for connections",
    "Check for lateral movement"
  ]
}
```

---

## AI Security Agents

**File:** `backend/agents/agent_orchestrator.py`

### Overview

Autonomous AI security agents for continuous threat hunting, vulnerability analysis, and network monitoring.

### Agent Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Agent Orchestrator                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────┐  ┌──────────────────┐            │
│  │ Threat Hunter    │  │ Vulnerability    │            │
│  │ Agent            │  │ Analyst Agent    │            │
│  └──────────────────┘  └──────────────────┘            │
│                                                          │
│  ┌──────────────────┐  ┌──────────────────┐            │
│  │ Network Monitor  │  │ IOC Correlation  │            │
│  │ Agent            │  │ Agent            │            │
│  └──────────────────┘  └──────────────────┘            │
│                                                          │
│  ┌──────────────────┐                                   │
│  │ Attack Simulation│                                   │
│  │ Agent            │                                   │
│  └──────────────────┘                                   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### BaseAgent (Abstract Class)

```python
class BaseAgent(ABC):
    """Abstract base class for all AI security agents."""
    
    def __init__(self, agent_id: str, name: str, description: str):
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.enabled = True
        self.last_run = None
        self.execution_count = 0
        self.status = "idle"
    
    @abstractmethod
    async def execute(self, parameters: Dict) -> Dict:
        """Execute agent-specific logic."""
        pass
    
    async def run(self, parameters: Dict = None) -> Dict:
        """Run agent with error handling and state management."""
```

### Agent Types

#### ThreatHunterAgent

**Purpose:** Autonomous threat hunting and emerging threat analysis

**Execution:**
```python
async def execute(self, parameters: Dict) -> Dict:
    # 1. Analyze new CVEs
    # 2. Check for active exploitation
    # 3. Correlate with threat actors
    # 4. Generate hunting hypotheses
    # 5. Produce threat report
```

**Output:**
- Emerging threat alerts
- Hunting recommendations
- Priority targets

#### VulnerabilityAnalystAgent

**Purpose:** CVE prioritization and vulnerability analysis

**Execution:**
```python
async def execute(self, parameters: Dict) -> Dict:
    # 1. Load recent CVEs
    # 2. Calculate risk scores
    # 3. Match to asset inventory
    # 4. Prioritize remediation
    # 5. Generate patching recommendations
```

**Output:**
- Prioritized CVE list
- Remediation guidance
- Risk assessment

#### NetworkMonitorAgent

**Purpose:** Network anomaly detection and monitoring

**Execution:**
```python
async def execute(self, parameters: Dict) -> Dict:
    # 1. Scan network
    # 2. Compare to baseline
    # 3. Detect new services
    # 4. Identify anomalies
    # 5. Alert on suspicious activity
```

**Output:**
- Network changes
- Anomaly alerts
- Exposure assessment

#### IOCCorrelationAgent

**Purpose:** IOC matching and campaign detection

**Execution:**
```python
async def execute(self, parameters: Dict) -> Dict:
    # 1. Load latest IOCs
    # 2. Check against logs
    # 3. Detect patterns
    # 4. Correlate campaigns
    # 5. Update threat graph
```

**Output:**
- IOC matches
- Campaign indicators
- Threat actor attribution

#### AttackSimulationAgent

**Purpose:** Educational attack scenario execution

**Execution:**
```python
async def execute(self, parameters: Dict) -> Dict:
    # 1. Select scenario
    # 2. Run simulation steps
    # 3. Check detection points
    # 4. Identify gaps
    # 5. Generate recommendations
```

**Output:**
- Simulation results
- Detection gaps
- Improvement recommendations

### AgentOrchestrator

Manages all agents:

```python
class AgentOrchestrator:
    async def register_agent(self, agent: BaseAgent)
        """Register an agent."""
    
    async def get_status(self) -> Dict
        """Get status of all agents."""
    
    async def trigger_agent(self, agent_id: str, parameters: Dict) -> Dict
        """Trigger specific agent."""
    
    async def run_all_agents(self) -> Dict
        """Run all enabled agents."""
    
    async def schedule_agent(self, agent_id: str, interval: int)
        """Schedule agent execution."""
```

### Example Usage

```python
from agents.agent_orchestrator import AgentOrchestrator

orchestrator = AgentOrchestrator()

# Get agent status
status = await orchestrator.get_status()
for agent in status['agents']:
    print(f"{agent['name']}: {agent['status']}")

# Trigger specific agent
result = await orchestrator.trigger_agent(
    agent_id="threat_hunter",
    parameters={"focus": "ransomware"}
)

# Run all agents
results = await orchestrator.run_all_agents()
```

### Agent Status

| Status | Description |
|--------|-------------|
| `idle` | Waiting for execution |
| `running` | Currently executing |
| `completed` | Last run successful |
| `error` | Last run failed |
| `disabled` | Agent disabled |

---

## Threat Graph

**File:** `backend/threat_graph/graph.py`

### Overview

Graph-based threat intelligence database using NetworkX for relationship mapping between threats.

### ThreatGraph Class

**Methods:**

```python
async def load_from_datasets(self) -> Dict
    """Load threat data into graph from datasets."""

async def add_entity(self, entity_type: str, entity_id: str, attributes: Dict) -> str
    """Add entity to graph."""

async def add_relationship(self, source: str, target: str, relationship_type: str, attributes: Dict) -> str
    """Add relationship between entities."""

async def query(self, entity_type: str = None, entity_id: str = None, 
                relationship_type: str = None, depth: int = 2) -> Dict
    """Query the threat graph."""

async def get_entity_types(self) -> List[str]
    """Get all entity types in graph."""

async def find_paths(self, source: str, target: str, max_length: int = 5) -> List[List[str]]
    """Find paths between entities."""

async def get_neighbors(self, entity_id: str, depth: int = 1) -> Dict
    """Get neighbors of entity."""

async def get_statistics(self) -> Dict
    """Get graph statistics."""

async def save_graph(self, path: str) -> str
    """Save graph to disk."""

async def load_graph(self, path: str) -> bool
    """Load graph from disk."""
```

### Entity Types

| Type | Description | Example |
|------|-------------|---------|
| `threat_actor` | APT groups, criminals | APT29, Lazarus |
| `malware` | Malware families | Emotet, TrickBot |
| `vulnerability` | CVEs | CVE-2021-44228 |
| `attack_technique` | MITRE ATT&CK | T1190, T1059 |
| `industry` | Targeted sectors | Finance, Healthcare |
| `infrastructure` | C2 servers, domains | evil.com |

### Relationships

| Relationship | Source → Target | Example |
|--------------|-----------------|---------|
| `uses` | Actor → Malware | APT29 uses WellMess |
| `exploits` | Malware → Vulnerability | Log4Shell exploits CVE-2021-44228 |
| `targets` | Actor → Industry | Lazarus targets Finance |
| `mitigates` | Control → Vulnerability | Patch mitigates CVE |
| `related_to` | Generic association | Related campaigns |

### Graph Structure

```
┌──────────────┐     uses     ┌──────────────┐
│ Threat Actor │─────────────▶│   Malware    │
│   APT29      │              │  WellMess    │
└──────────────┘              └──────────────┘
       │                             │
       │ targets                     │ exploits
       ▼                             ▼
┌──────────────┐              ┌──────────────┐
│  Industry    │              │Vulnerability │
│   Finance    │              │CVE-2020-1234 │
└──────────────┘              └──────────────┘
```

### Query Examples

```python
from threat_graph.graph import ThreatGraph

graph = ThreatGraph()

# Find all malware used by APT29
result = await graph.query(
    entity_type="malware",
    entity_id="APT29",
    relationship_type="uses",
    depth=1
)

# Find paths between actor and vulnerability
paths = await graph.find_paths(
    source="APT29",
    target="CVE-2021-44228",
    max_length=5
)

# Get neighbors of entity
neighbors = await graph.get_neighbors(
    entity_id="Emotet",
    depth=2
)

# Graph statistics
stats = await graph.get_statistics()
print(f"Entities: {stats['total_entities']}")
print(f"Relationships: {stats['total_relationships']}")
```

### Statistics

```json
{
  "total_entities": 1500,
  "total_relationships": 3500,
  "entity_types": {
    "threat_actor": 50,
    "malware": 200,
    "vulnerability": 1000,
    "attack_technique": 200,
    "industry": 20,
    "infrastructure": 30
  },
  "avg_degree": 4.67,
  "connected_components": 15
}
```

---

## Attack Simulation

**File:** `backend/attack_simulation/simulator.py`

### Overview

Educational attack simulation engine for security control validation and detection testing.

### AttackSimulator Class

**Methods:**

```python
async def _load_scenarios(self) -> List[Dict]
    """Load simulation scenarios."""

async def run_simulation(self, scenario: str, target_type: str) -> Dict
    """Execute attack simulation."""

async def _generate_recommendations(self, results: Dict) -> List[str]
    """Generate security recommendations."""

async def _generate_educational_notes(self, scenario: str) -> List[str]
    """Generate educational notes for scenario."""

async def _save_simulation_results(self, results: Dict) -> str
    """Save simulation results to disk."""

async def get_scenarios(self) -> List[Dict]
    """Get available simulation scenarios."""

async def get_simulation_history(self, limit: int = 10) -> List[Dict]
    """Get simulation history."""
```

### Simulation Scenarios

#### 1. Phishing Campaign

**MITRE ATT&CK:** T1566 (Phishing)

**Steps:**
1. Reconnaissance - Target research
2. Weaponization - Malicious attachment
3. Delivery - Email send
4. Execution - User clicks
5. Persistence - Macro execution
6. C2 - Beacon establishment

**Detection Points:**
- Email gateway filtering
- Attachment analysis
- User reporting
- Macro execution alerts

#### 2. Web Application Exploitation

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

**Steps:**
1. Reconnaissance - Vulnerability scanning
2. Weaponization - Exploit preparation
3. Delivery - HTTP request
4. Execution - Code execution
5. Exfiltration - Data theft

**Detection Points:**
- WAF alerts
- Unusual HTTP patterns
- Database queries
- File access anomalies

#### 3. Insider Threat

**MITRE ATT&CK:** T1537 (Transfer Data to Cloud Account)

**Steps:**
1. Access - Legitimate credentials
2. Collection - Data gathering
3. Exfiltration - Cloud upload
4. Cover tracks - Log deletion

**Detection Points:**
- Unusual access patterns
- Large data transfers
- After-hours activity
- Log anomalies

#### 4. Ransomware Deployment

**MITRE ATT&CK:** T1486 (Data Encrypted for Impact)

**Steps:**
1. Initial Access - Phishing/exploit
2. Execution - Payload run
3. Persistence - Registry/run keys
4. Lateral Movement - Network spread
5. Impact - File encryption

**Detection Points:**
- EDR alerts
- File system changes
- Network scanning
- Encryption patterns

### Simulation Output

```json
{
  "simulation_id": "sim_20240101_120000",
  "scenario": "phishing_campaign",
  "target_type": "workstation",
  "timestamp": "2024-01-01T12:00:00Z",
  "steps": [
    {
      "step": 1,
      "name": "Reconnaissance",
      "mitre_id": "TA0043",
      "status": "completed",
      "detection_opportunity": true,
      "detection_triggered": false
    }
  ],
  "detection_gaps": [
    "No email attachment analysis",
    "Macro execution not monitored"
  ],
  "recommendations": [
    "Enable attachment sandboxing",
    "Implement application whitelisting"
  ],
  "educational_notes": [
    "Phishing is the #1 initial access vector",
    "User training reduces success rate by 70%"
  ]
}
```

### Educational Mode

All simulations run in educational mode only:

- No real attacks executed
- Simulated detection (50% probability)
- Focus on learning and gap analysis
- MITRE ATT&CK mapping included

### Example Usage

```python
from attack_simulation.simulator import AttackSimulator

simulator = AttackSimulator()

# Get scenarios
scenarios = await simulator.get_scenarios()
for s in scenarios:
    print(f"{s['id']}: {s['name']}")

# Run simulation
result = await simulator.run_simulation(
    scenario="phishing_campaign",
    target_type="workstation"
)

print(f"Detection gaps: {result['detection_gaps']}")
print(f"Recommendations: {result['recommendations']}")
```

---

## Scheduler

**File:** `backend/scheduler/scheduler.py`

### Overview

Automated task scheduling using APScheduler for continuous threat intelligence updates and monitoring.

### IntelligenceScheduler Class

**Methods:**

```python
async def start(self) -> bool
    """Start the scheduler."""

async def stop(self) -> bool
    """Stop the scheduler."""

async def _update_cve_feed(self) -> Dict
    """Update CVE feed from NVD."""

async def _update_embeddings(self) -> Dict
    """Refresh vector embeddings."""

async def _scan_network(self) -> Dict
    """Run scheduled network scan."""

async def _update_threat_intel(self) -> Dict
    """Run full threat intel update."""

async def _run_agents(self) -> Dict
    """Execute all AI agents."""

async def get_schedule(self) -> Dict
    """Get current schedule status."""

async def add_task(self, task_id: str, func: Callable, interval: int) -> str
    """Add custom scheduled task."""

async def remove_task(self, task_id: str) -> bool
    """Remove scheduled task."""

async def run_task_now(self, task_id: str) -> Dict
    """Run task immediately."""
```

### Scheduled Tasks

| Task | Interval | Description |
|------|----------|-------------|
| `cve_update` | 6 hours | Download NVD CVE feed |
| `embedding_update` | 12 hours | Refresh vector embeddings |
| `network_scan` | 6 hours | Scan default targets |
| `threat_intel_update` | 6 hours | Full ingestion pipeline |
| `agent_run` | 6 hours | Execute all agents |

### Schedule Configuration

Configure intervals via environment:

```bash
CVE_UPDATE_INTERVAL_HOURS=6
EMBEDDING_UPDATE_INTERVAL_HOURS=12
NETWORK_SCAN_INTERVAL_HOURS=6
THREAT_INTEL_UPDATE_INTERVAL_HOURS=6
```

### Task Execution Flow

```
Scheduler Start
    ↓
Register Tasks
    ↓
Start APScheduler
    ↓
┌─────────────────────────────────┐
│         Task Loop                │
│                                  │
│  Every 6 hours:                  │
│  - CVE Update                    │
│  - Network Scan                  │
│  - Threat Intel Update           │
│  - Agent Execution               │
│                                  │
│  Every 12 hours:                 │
│  - Embedding Refresh             │
│                                  │
└─────────────────────────────────┘
    ↓
Scheduler Stop (on shutdown)
```

### Example Usage

```python
from scheduler.scheduler import IntelligenceScheduler

scheduler = IntelligenceScheduler(
    ingestion_service=ingestion,
    rag_engine=rag,
    network_analyzer=network,
    agent_orchestrator=agents
)

# Start scheduler
await scheduler.start()

# Get schedule status
status = await scheduler.get_schedule()
print(status)

# Run task manually
await scheduler.run_task_now("cve_update")

# Add custom task
await scheduler.add_task(
    task_id="custom_task",
    func=my_function,
    interval=3600  # 1 hour
)

# Stop scheduler
await scheduler.stop()
```

### Schedule Status

```json
{
  "status": "running",
  "tasks": [
    {
      "id": "cve_update",
      "next_run": "2024-01-01T18:00:00Z",
      "interval_hours": 6,
      "last_run": "2024-01-01T12:00:00Z",
      "last_status": "success"
    }
  ],
  "timezone": "UTC"
}
```

---

## Integration Guide

### Module Dependencies

```
main.py (FastAPI)
    │
    ├── config.py (Settings)
    │
    ├── threat_ingestion → schema.py
    │
    ├── rag → chromadb, sentence-transformers, ollama
    │
    ├── intelligence_engine → threat_ingestion.schema
    │
    ├── network_analysis → nmap (optional)
    │
    ├── ioc_correlation → threat_ingestion.schema
    │
    ├── attack_simulation
    │
    ├── threat_graph → networkx
    │
    ├── scheduler → apscheduler
    │
    └── agents → orchestrates all modules
```

### Service Initialization Order

1. Configuration (config.py)
2. Threat Ingestion (load datasets)
3. RAG Engine (initialize vector store)
4. Intelligence Engine (load processed data)
5. Network Analyzer (initialize scanner)
6. IOC Correlator (load IOC database)
7. Threat Graph (build relationships)
8. Agent Orchestrator (register agents)
9. Scheduler (start background tasks)

### Cross-Module Communication

Modules communicate through:
- **Direct method calls** (synchronous)
- **Shared state** (app.state in FastAPI)
- **Event broadcasting** (WebSocket logs)

### Best Practices

1. **Error Handling**: All modules use structured logging
2. **Async/Await**: Use async for I/O operations
3. **Type Hints**: All functions have type annotations
4. **Documentation**: Docstrings for all public methods
5. **Testing**: Mock external dependencies in tests

---

## API Reference Summary

For complete API documentation, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Quick Reference

```bash
# Health
GET /api/health

# Threat Intel
GET /api/threat-intel/summary
GET /api/threat-intel/cves
GET /api/threat-intel/zero-days
GET /api/threat-intel/threat-actors

# RAG
POST /api/rag/query
POST /api/chat

# Network
POST /api/network/scan
GET /api/network/results

# IOC
POST /api/ioc/check
POST /api/ioc/bulk-check

# Simulation
POST /api/simulation/run
GET /api/simulation/scenarios

# Graph
POST /api/graph/query
GET /api/graph/entities

# Agents
GET /api/agents/status
POST /api/agents/{id}/trigger

# WebSocket
/ws/logs
```
