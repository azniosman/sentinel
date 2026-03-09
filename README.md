# Sentinel AI-SOC

**Autonomous AI-Powered Security Operations Center**

A comprehensive, local-first cybersecurity intelligence platform that combines threat intelligence, network analysis, AI-powered analysis, and autonomous agents into a unified security operations center. All processing happens **100% locally** using local LLMs (Ollama), local vector databases (ChromaDB), and local embedding models.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Sentinel AI-SOC Platform                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    SOC Dashboard (Port 3000)                      │  │
│  │  - Threat Landscape Monitoring                                   │  │
│  │  - Network Exposure Map                                          │  │
│  │  - Zero-Day Alerts                                               │  │
│  │  - AI Threat Intelligence Assistant                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                           │
│                              ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   AI Security Backend (Port 8000)                 │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │   RAG    │ │    AI    │ │  Zero-   │ │ Network  │            │  │
│  │  │ Pipeline │ │  Agents  │ │   Day    │ │ Analysis │            │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │  │
│  │  │  Threat  │ │  Attack  │ │  Threat  │ │   SOC    │            │  │
│  │  │  Intel   │ │ Simulate │ │  Graph   │ │  Logger  │            │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                           │
│                              ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   Local AI Services (Port 11434)                  │  │
│  │  - Ollama LLM (Llama 3, Mistral, etc.)                           │  │
│  │  - Sentence Transformers (Embeddings)                            │  │
│  │  - ChromaDB (Vector Store)                                       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Clone and navigate to project
cd sentinel/aisoc

# 2. Start all services
docker-compose up -d

# 3. Pull LLM models
docker exec -it aisoc-ollama ollama pull llama3
docker exec -it aisoc-ollama ollama pull nomic-embed-text

# 4. Access the platform
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Local Installation

```bash
# 1. Install Ollama and pull models
ollama pull llama3
ollama pull nomic-embed-text

# 2. Install Python dependencies
cd backend
pip install -r requirements.txt

# 3. Start the backend
python main.py

# 4. Open frontend/index.html in your browser
```

---

## Key Features

### 🛡️ Threat Intelligence

| Capability | Description |
|------------|-------------|
| **CVE Database** | Automated NVD feed ingestion with CVSS scoring |
| **Zero-Day Detection** | Heuristic risk scoring for emerging vulnerabilities |
| **Threat Actors** | APT and cybercriminal group profiles |
| **Malware Families** | Ransomware, trojans, and malware tracking |
| **MITRE ATT&CK** | Technique and tactic mapping |
| **CISA KEV** | Known exploited vulnerabilities |

### 🤖 AI-Powered Analysis

| Capability | Description |
|------------|-------------|
| **RAG Pipeline** | Semantic search across threat intelligence using ChromaDB + local embeddings |
| **AI Assistant** | Chat interface powered by local LLM (Llama 3, Mistral, etc.) |
| **Autonomous Agents** | Threat hunting, vulnerability analysis, network monitoring |
| **Natural Language Queries** | Ask questions like "What are the latest critical CVEs?" |

### 🌐 Network Analysis

| Capability | Description |
|------------|-------------|
| **Network Scanning** | Integration with nmap or fallback socket scanner |
| **Service Detection** | Identify running services and versions |
| **Vulnerability Matching** | Correlate services to known vulnerabilities |
| **Exposure Assessment** | Identify open ports and insecure services |

### 🔍 IOC Correlation

| Capability | Description |
|------------|-------------|
| **IOC Checking** | Check IPs, domains, hashes against threat intel |
| **Bulk Analysis** | Process multiple IOCs simultaneously |
| **Pattern Detection** | Identify DGA domains, campaign indicators |
| **Risk Scoring** | Automatic risk level calculation |

### 🕸️ Threat Graph

| Capability | Description |
|------------|-------------|
| **Relationship Mapping** | Visualize connections between threats |
| **Graph Queries** | Traverse relationships (threat actor → malware → CVE) |
| **Path Analysis** | Find attack paths and connections |
| **Entity Exploration** | Interactive threat intelligence exploration |

### 🎯 Attack Simulation

| Capability | Description |
|------------|-------------|
| **Educational Scenarios** | Phishing, web exploit, insider threat, ransomware |
| **Detection Validation** | Test your security controls |
| **MITRE ATT&CK Mapping** | Map simulations to real-world techniques |
| **Gap Analysis** | Identify detection blind spots |

### 🤖 Autonomous AI Agents

| Agent | Purpose | Interval |
|-------|---------|----------|
| **Threat Hunter** | Analyze emerging threats | 6 hours |
| **Vulnerability Analyst** | Prioritize CVEs | 6 hours |
| **Network Monitor** | Detect anomalies | 6 hours |
| **IOC Correlation** | Match indicators | 6 hours |
| **Attack Simulation** | Run scenarios | On-demand |

---

## Architecture

### System Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend  │────▶│   Backend   │────▶│   Ollama    │
│  Dashboard  │     │   API       │     │   LLM       │
│  (3000)     │     │  (8000)     │     │  (11434)    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  ChromaDB   │
                    │  Vector DB  │
                    └─────────────┘
```

### Backend Modules

| Module | Purpose | Key Technologies |
|--------|---------|------------------|
| **Threat Ingestion** | Download and process threat feeds | httpx, feedparser, BeautifulSoup |
| **RAG Engine** | Semantic search and AI queries | ChromaDB, sentence-transformers, Ollama |
| **Intelligence Engine** | Zero-day detection, risk scoring | Custom algorithms, CVSS, EPSS |
| **Network Analysis** | Network scanning, vuln detection | nmap, socket, scapy |
| **IOC Correlation** | Indicator matching | Pattern matching, risk scoring |
| **AI Security Agents** | Autonomous threat hunting | Async agents, orchestration |
| **Threat Graph** | Relationship mapping | NetworkX MultiDiGraph |
| **Attack Simulation** | Educational scenarios | MITRE ATT&CK mapping |
| **Scheduler** | Automated tasks | APScheduler |

### Data Flow

#### Threat Intelligence Ingestion

```
External APIs (NVD, MITRE, CISA)
    ↓
ThreatIngestionService
    ↓
Raw JSON Files (data/raw_feeds)
    ↓
Schema Validation (Pydantic)
    ↓
Transformation
    ↓
Processed JSON (data/threat_intel)
    ↓
RAG Engine (embeddings)
    ↓
ChromaDB (vector store)
```

#### RAG Query Flow

```
User Query (Frontend)
    ↓
FastAPI Endpoint (/api/rag/query)
    ↓
RAG Engine
    ↓
Embedding Generation (sentence-transformers)
    ↓
ChromaDB Search (cosine similarity)
    ↓
Top-K Documents Retrieved
    ↓
Context Builder
    ↓
LLM Prompt (Ollama - Llama 3)
    ↓
Response + Sources
    ↓
Frontend Display
```

#### Network Scan Flow

```
User Request (Frontend)
    ↓
FastAPI Endpoint (/api/network/scan)
    ↓
NetworkAnalyzer
    ↓
nmap / socket scan
    ↓
Raw Results
    ↓
Vulnerability Matching (CVE database)
    ↓
Risk Assessment
    ↓
Results Storage
    ↓
Frontend Display
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Frontend** | Vanilla JavaScript, CSS Grid | SOC dashboard UI |
| **Backend API** | Python FastAPI, uvicorn | REST API, WebSocket |
| **Local LLM** | Ollama (Llama 3, Mistral) | AI inference |
| **Embeddings** | sentence-transformers | Vector embeddings |
| **Vector DB** | ChromaDB | Semantic search |
| **Network** | nmap, asyncio socket | Network scanning |
| **Graph** | NetworkX | Threat relationships |
| **Scheduling** | APScheduler | Automated tasks |
| **Deployment** | Docker Compose | Container orchestration |

---

## API Reference

### Threat Intelligence

```bash
# Get threat summary
curl http://localhost:8000/api/threat-intel/summary

# Get CVEs with filtering
curl "http://localhost:8000/api/threat-intel/cves?severity=CRITICAL&limit=10"

# Get zero-day alerts
curl http://localhost:8000/api/threat-intel/zero-days

# Get threat actors
curl http://localhost:8000/api/threat-intel/threat-actors

# Get MITRE ATT&CK data
curl http://localhost:8000/api/threat-intel/mitre-attack
```

### RAG-Powered Queries

```bash
# Query threat intelligence
curl -X POST http://localhost:8000/api/rag/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What are the most critical CVEs exploited by ransomware?",
    "top_k": 5
  }'

# AI chat interface
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Explain the Log4Shell vulnerability"
  }'
```

### Network Analysis

```bash
# Scan network
curl -X POST http://localhost:8000/api/network/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "scan_type": "basic"
  }'

# Get scan results
curl http://localhost:8000/api/network/results
```

### IOC Correlation

```bash
# Check single IOC
curl -X POST http://localhost:8000/api/ioc/check \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_type": "ip",
    "value": "192.168.1.100"
  }'

# Bulk check IOCs
curl -X POST http://localhost:8000/api/ioc/bulk-check \
  -H "Content-Type: application/json" \
  -d '{
    "iocs": [
      {"ioc_type": "ip", "value": "1.2.3.4"},
      {"ioc_type": "domain", "value": "malicious.com"}
    ]
  }'
```

### Threat Graph

```bash
# Query graph
curl -X POST http://localhost:8000/api/graph/query \
  -H "Content-Type: application/json" \
  -d '{
    "entity_type": "threat_actor",
    "depth": 2
  }'

# Get entity types
curl http://localhost:8000/api/graph/entities
```

### Attack Simulation

```bash
# Get scenarios
curl http://localhost:8000/api/simulation/scenarios

# Run simulation
curl -X POST http://localhost:8000/api/simulation/run \
  -H "Content-Type: application/json" \
  -d '{
    "scenario": "phishing_campaign",
    "target_type": "workstation"
  }'
```

### AI Agents

```bash
# Get agent status
curl http://localhost:8000/api/agents/status

# Trigger agent
curl -X POST http://localhost:8000/api/agents/threat_hunter/trigger
```

### Health & Status

```bash
# Health check
curl http://localhost:8000/api/health

# Root endpoint
curl http://localhost:8000/
```

---

## Configuration

### Environment Variables

Create `backend/.env` file (copy from `backend/.env.example`):

```bash
# Server
HOST=127.0.0.1
PORT=8000
DEBUG=false
LOG_LEVEL=INFO

# LLM
OLLAMA_HOST=http://127.0.0.1:11434
LLM_MODEL=llama3
EMBEDDING_MODEL=all-MiniLM-L6-v2

# Vector Store
VECTOR_STORE_PATH=./vector_store/chroma_db
VECTOR_STORE_COLLECTION=threat_intelligence

# Security
API_KEY=your-secure-api-key  # Optional

# Scheduler
SCHEDULER_ENABLED=true
CVE_UPDATE_INTERVAL_HOURS=6
EMBEDDING_UPDATE_INTERVAL_HOURS=12
NETWORK_SCAN_INTERVAL_HOURS=6
```

### Key Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama endpoint |
| `LLM_MODEL` | `llama3` | LLM for analysis |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Sentence transformer |
| `VECTOR_STORE_PATH` | `./vector_store/chroma_db` | Vector DB location |
| `DEFAULT_SCAN_TARGETS` | `192.168.1.0/24` | Network scan targets |
| `SCHEDULER_ENABLED` | `true` | Enable background tasks |
| `API_KEY` | `None` | Optional API authentication |

---

## Security Model

### Privacy & Security Guarantees

| Principle | Implementation |
|-----------|----------------|
| **100% Local** | All AI processing on-device, no cloud dependencies |
| **No Telemetry** | No analytics, no tracking, no external calls |
| **Air-Gappable** | Can run completely offline after initial setup |
| **Input Sanitization** | XSS prevention, URL validation, SSRF protection |
| **Optional Auth** | API key authentication available |
| **Encrypted Storage** | Optional encryption for stored datasets |

### Network Security

- Binds to `127.0.0.1` by default (configurable)
- CORS configured for allowed origins only
- Optional API key authentication
- Rate limiting available

### Data Sources

| Source | URL | Purpose |
|--------|-----|---------|
| **NVD** | https://services.nvd.nist.gov | CVE database |
| **MITRE ATT&CK** | GitHub | Attack techniques |
| **CISA KEV** | https://www.cisa.gov | Known exploited vulns |

---

## System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|---------------|
| **CPU** | 4 cores |
| **RAM** | 8GB |
| **Storage** | 20GB SSD |
| **OS** | Linux, macOS, Windows 10+ |

### Recommended Requirements

| Component | Specification |
|-----------|---------------|
| **CPU** | 8+ cores (Ryzen 7 / i7) |
| **RAM** | 16-32GB |
| **Storage** | 50GB+ NVMe SSD |
| **GPU** | NVIDIA 8GB+ VRAM (optional) |

### LLM Model Requirements

| Model | VRAM Required | Speed | Quality |
|-------|---------------|-------|---------|
| `phi3:mini` | 2GB | Fast | Good |
| `mistral:7b` | 4GB | Medium | Very Good |
| `llama3:8b` | 6GB | Medium | Excellent |
| `llama3:70b` | 40GB | Slow | Best |

---

## Project Structure

```
sentinel/aisoc/
├── backend/                      # Python FastAPI backend
│   ├── __init__.py
│   ├── main.py                   # FastAPI application
│   ├── config.py                 # Configuration management
│   ├── requirements.txt          # Python dependencies
│   ├── .env.example              # Environment template
│   │
│   ├── threat_ingestion/         # Threat feed ingestion
│   │   ├── __init__.py
│   │   ├── schema.py             # Pydantic data models
│   │   └── ingestion.py          # Feed download & processing
│   │
│   ├── rag/                      # RAG pipeline
│   │   ├── __init__.py
│   │   └── rag_engine.py         # Embeddings + ChromaDB + Ollama
│   │
│   ├── intelligence_engine/      # Intelligence analysis
│   │   ├── __init__.py
│   │   └── analyzer.py           # Zero-day detection, CVE analysis
│   │
│   ├── network_analysis/         # Network scanning
│   │   ├── __init__.py
│   │   └── scanner.py            # nmap integration, vuln matching
│   │
│   ├── ioc_correlation/          # IOC matching
│   │   ├── __init__.py
│   │   └── correlator.py         # IP/domain/hash correlation
│   │
│   ├── agents/                   # AI security agents
│   │   ├── __init__.py
│   │   └── agent_orchestrator.py # 5 autonomous agents
│   │
│   ├── threat_graph/             # Graph database
│   │   ├── __init__.py
│   │   └── graph.py              # NetworkX threat relationships
│   │
│   ├── attack_simulation/        # Attack simulation
│   │   ├── __init__.py
│   │   └── simulator.py          # Educational scenarios
│   │
│   └── scheduler/                # Task scheduling
│       ├── __init__.py
│       └── scheduler.py          # APScheduler tasks
│
├── frontend/                     # SOC dashboard
│   └── index.html                # Single-page application
│
├── docker/                       # Docker deployment
│   ├── docker-compose.yml        # Multi-container setup
│   ├── Dockerfile.backend        # Backend container
│   └── nginx.conf                # Frontend web server
│
├── docs/                         # Documentation
│   ├── MODULES.md                # Module-level documentation
│   ├── DEPLOYMENT.md             # Deployment guide
│   └── ARCHITECTURE.md           # System architecture
│
├── data/                         # Data storage
│   ├── raw_feeds/                # Raw threat feeds
│   └── threat_intel/             # Processed threat intel
│
├── vector_store/                 # Vector database
│   └── chroma_db/                # ChromaDB storage
│
├── scripts/                      # Utility scripts
│
├── README.md                     # This file
├── QUICKSTART.md                 # Quick start guide
└── quickstart.sh                 # Setup script
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[MODULES.md](docs/MODULES.md)** | Detailed module documentation with API reference |
| **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** | Complete deployment and operations guide |
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** | System architecture details |
| **[QUICKSTART.md](QUICKSTART.md)** | Quick start guide |

---

## Troubleshooting

### Ollama Connection Issues

```bash
# Check Ollama is running
docker exec -it aisoc-ollama ollama list

# Restart Ollama
docker-compose restart ollama

# Pull models
docker exec -it aisoc-ollama ollama pull llama3
docker exec -it aisoc-ollama ollama pull nomic-embed-text
```

### Backend Won't Start

```bash
# Check logs
docker-compose logs aisoc-backend

# Common issues:
# - Port 8000 already in use
# - Ollama not accessible
# - Missing Python dependencies
```

### Vector Database Errors

```bash
# Reset vector store (WARNING: deletes embeddings)
docker-compose down
docker volume rm aisoc_aisoc_vector_store
docker-compose up -d

# Trigger re-ingestion
curl -X POST http://localhost:8000/api/ingestion/update
```

### High Memory Usage

```bash
# Use smaller models
docker exec -it aisoc-ollama ollama pull phi3:mini
docker exec -it aisoc-ollama ollama pull mistral:7b

# Update backend/.env
LLM_MODEL=mistral:7b
```

---

## Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Lint code
ruff check .
```

### Adding Custom Agents

1. Create new agent class in `backend/agents/`
2. Inherit from `BaseAgent`
3. Implement `execute()` method
4. Register in `AgentOrchestrator`

### Adding Threat Feeds

1. Add download method in `backend/threat_ingestion/ingestion.py`
2. Define schema in `backend/threat_ingestion/schema.py`
3. Add to ingestion pipeline in `run_full_ingestion()`

---

## Common Commands

```bash
# View logs
docker-compose logs -f aisoc-backend
docker-compose logs -f ollama

# Restart services
docker-compose restart

# Stop all services
docker-compose down

# Reset everything (WARNING: deletes all data)
docker-compose down -v

# Check service health
docker-compose ps

# Trigger manual update
curl -X POST http://localhost:8000/api/ingestion/update
```

---

## Contributing

### Code Style

- Follow PEP 8 for Python code
- Use type hints for all functions
- Add docstrings to all public methods
- Write tests for new features

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run linting
6. Submit PR

---

## License

AGPL-3.0 License

---

## Support

For issues, questions, or contributions:

- **Documentation**: See `docs/` directory
- **API Reference**: http://localhost:8000/docs
- **GitHub Issues**: Report bugs and feature requests

---

**Sentinel AI-SOC** — Autonomous Security Intelligence, 100% Local

Built for security researchers, SOC analysts, and organizations that prioritize privacy and local-first security operations.
