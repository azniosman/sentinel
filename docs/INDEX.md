# AI-SOC Documentation Index

Welcome to the Sentinel AI-SOC documentation. This index provides quick access to all documentation resources.

---

## Quick Navigation

### Getting Started

| Document | Description | For |
|----------|-------------|-----|
| **[README.md](../README.md)** | Platform overview and quick start | Everyone |
| **[QUICKSTART.md](../QUICKSTART.md)** | 5-minute setup guide | New users |
| **[DEPLOYMENT.md](DEPLOYMENT.md)** | Complete deployment guide | DevOps/Admins |

### Technical Documentation

| Document | Description | For |
|----------|-------------|-----|
| **[MODULES.md](MODULES.md)** | Complete module reference | Developers |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | System architecture | Architects |
| **[CLEANUP_REPORT.md](CLEANUP_REPORT.md)** | Documentation audit report | Maintainers |

### API Reference

| Resource | URL | Description |
|----------|-----|-------------|
| **Swagger UI** | http://localhost:8000/docs | Interactive API documentation |
| **ReDoc** | http://localhost:8000/redoc | Alternative API documentation |
| **Health Check** | http://localhost:8000/api/health | Service health status |

---

## Documentation by Role

### For New Users

1. Start with **[README.md](../README.md)** - Platform overview
2. Follow **[QUICKSTART.md](../QUICKSTART.md)** - Get running in 5 minutes
3. Explore the dashboard at http://localhost:3000

### For Developers

1. Read **[MODULES.md](MODULES.md)** - Understand all modules
2. Review **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design
3. Check **[API Docs](http://localhost:8000/docs)** - API reference

### For DevOps/Admins

1. Follow **[DEPLOYMENT.md](DEPLOYMENT.md)** - Deployment guide
2. Review **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture
3. Check **[CLEANUP_REPORT.md](CLEANUP_REPORT.md)** - System status

### For Security Researchers

1. Review **[MODULES.md](MODULES.md)** - Module capabilities
2. Check **[ARCHITECTURE.md](ARCHITECTURE.md)** - Security model
3. Explore **[API Docs](http://localhost:8000/docs)** - Available endpoints

---

## Documentation Structure

```
sentinel/aisoc/
├── README.md                          # Main documentation
├── QUICKSTART.md                      # Quick start guide
├── quickstart.sh                      # Setup script
│
├── docs/
│   ├── INDEX.md                       # This file
│   ├── MODULES.md                     # Module documentation
│   ├── DEPLOYMENT.md                  # Deployment guide
│   ├── ARCHITECTURE.md                # System architecture
│   └── CLEANUP_REPORT.md              # Documentation audit
│
├── data/
│   └── README.md                      # Data directory docs
│
├── vector_store/
│   └── README.md                      # Vector store docs
│
├── scripts/
│   └── README.md                      # Scripts directory docs
│
└── docker/
    └── docker-compose.yml             # Docker orchestration
```

---

## Module Documentation

Complete module reference in **[MODULES.md](MODULES.md)**:

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| **[Main API](MODULES.md#main-api)** | FastAPI application | FastAPI app, endpoints |
| **[Configuration](MODULES.md#configuration)** | Settings management | Settings |
| **[Threat Ingestion](MODULES.md#threat-ingestion)** | Feed ingestion | ThreatIngestionService |
| **[RAG Engine](MODULES.md#rag-engine)** | AI queries | RAGEngine |
| **[Intelligence Engine](MODULES.md#intelligence-engine)** | Analysis | IntelligenceEngine |
| **[Network Analysis](MODULES.md#network-analysis)** | Scanning | NetworkAnalyzer |
| **[IOC Correlation](MODULES.md#ioc-correlation)** | IOC matching | IOCCorrelator |
| **[AI Security Agents](MODULES.md#ai-security-agents)** | Autonomous agents | AgentOrchestrator |
| **[Threat Graph](MODULES.md#threat-graph)** | Graph database | ThreatGraph |
| **[Attack Simulation](MODULES.md#attack-simulation)** | Simulations | AttackSimulator |
| **[Scheduler](MODULES.md#scheduler)** | Automation | IntelligenceScheduler |

---

## API Endpoints

### Health & Status

```bash
GET  /                          # Root endpoint
GET  /api/health                # Health check
```

### Threat Intelligence

```bash
GET  /api/threat-intel/summary          # Threat summary
GET  /api/threat-intel/cves             # CVE database
GET  /api/threat-intel/zero-days        # Zero-day alerts
GET  /api/threat-intel/threat-actors    # Threat actors
GET  /api/threat-intel/mitre-attack     # MITRE ATT&CK
```

### AI & RAG

```bash
POST /api/rag/query             # RAG query
POST /api/chat                  # AI chat
```

### Network Analysis

```bash
POST /api/network/scan          # Network scan
GET  /api/network/results       # Scan results
```

### IOC Correlation

```bash
POST /api/ioc/check             # Check IOC
POST /api/ioc/bulk-check        # Bulk check
```

### Attack Simulation

```bash
POST /api/simulation/run        # Run simulation
GET  /api/simulation/scenarios  # Get scenarios
```

### Threat Graph

```bash
POST /api/graph/query           # Query graph
GET  /api/graph/entities        # Get entities
```

### AI Agents

```bash
GET  /api/agents/status         # Agent status
POST /api/agents/{id}/trigger   # Trigger agent
```

### Maintenance

```bash
POST /api/ingestion/update      # Trigger ingestion
```

### WebSocket

```bash
WS   /ws/logs                   # Real-time logs
```

---

## Common Tasks

### Quick Start

```bash
# Start with Docker
cd docker
docker-compose up -d

# Pull models
docker exec -it aisoc-ollama ollama pull llama3
docker exec -it aisoc-ollama ollama pull nomic-embed-text

# Access dashboard
open http://localhost:3000
```

### Health Check

```bash
curl http://localhost:8000/api/health
```

### View Logs

```bash
docker-compose logs -f aisoc-backend
```

### Trigger Ingestion

```bash
curl -X POST http://localhost:8000/api/ingestion/update
```

### Run Network Scan

```bash
curl -X POST http://localhost:8000/api/network/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "basic"}'
```

### Query with AI

```bash
curl -X POST http://localhost:8000/api/rag/query \
  -H "Content-Type: application/json" \
  -d '{"query": "latest critical CVEs", "top_k": 5}'
```

---

## Troubleshooting

| Issue | Solution | Reference |
|-------|----------|-----------|
| Backend won't start | Check logs, verify Ollama | [DEPLOYMENT.md](DEPLOYMENT.md#troubleshooting) |
| Ollama connection error | Restart Ollama, pull models | [DEPLOYMENT.md](DEPLOYMENT.md#ollama-connection-issues) |
| Vector database errors | Reset vector store | [DEPLOYMENT.md](DEPLOYMENT.md#vector-database-errors) |
| High memory usage | Use smaller models | [DEPLOYMENT.md](DEPLOYMENT.md#high-memory-usage) |
| Network scan fails | Install nmap or use fallback | [MODULES.md](MODULES.md#network-analysis) |

---

## Configuration Reference

### Environment Variables

Complete list in **[DEPLOYMENT.md](DEPLOYMENT.md#configuration)**:

| Category | Variables |
|----------|-----------|
| Application | APP_NAME, APP_VERSION, DEBUG, LOG_LEVEL |
| Server | HOST, PORT, ALLOWED_ORIGINS |
| LLM | OLLAMA_HOST, LLM_MODEL, EMBEDDING_MODEL |
| Vector Store | VECTOR_STORE_PATH, VECTOR_STORE_COLLECTION |
| Network | DEFAULT_SCAN_TARGETS, SCAN_TIMEOUT |
| Scheduler | SCHEDULER_ENABLED, *_INTERVAL_HOURS |
| Security | API_KEY, ENCRYPT_DATA_AT_REST |

---

## External Resources

| Resource | URL |
|----------|-----|
| **Ollama** | https://ollama.ai |
| **NVD CVE Database** | https://services.nvd.nist.gov |
| **MITRE ATT&CK** | https://attack.mitre.org |
| **CISA KEV** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **ChromaDB** | https://docs.trychroma.com |
| **FastAPI** | https://fastapi.tiangolo.com |

---

## Documentation Maintenance

### Update Schedule

| Task | Frequency | Owner |
|------|-----------|-------|
| Review external links | Monthly | Maintainers |
| Verify API accuracy | Monthly | Developers |
| Update deployment guide | Quarterly | DevOps |
| Review module docs | Per release | Developers |
| Update version numbers | Per release | Maintainers |

### Contributing

To contribute documentation:

1. Follow existing formatting
2. Add examples for all new features
3. Update MODULES.md for new modules
4. Update DEPLOYMENT.md for new configuration
5. Test all examples before committing

---

## Support

| Need | Resource |
|------|----------|
| General questions | See [README.md](../README.md) |
| Setup help | See [QUICKSTART.md](../QUICKSTART.md) |
| Deployment help | See [DEPLOYMENT.md](DEPLOYMENT.md) |
| API reference | http://localhost:8000/docs |
| Bug reports | GitHub Issues |

---

**Sentinel AI-SOC Documentation** — Last updated: 2026-03-09

**100% Local** · **No Cloud Dependencies** · **Privacy-First**
