# AI-SOC: Local AI Security Operations Center

## Quick Start

### Using Docker Compose (Recommended)

```bash
# 1. Start all services
./quickstart.sh

# OR manually:
docker-compose up -d

# 2. Pull LLM models
docker exec -it aisoc-ollama ollama pull llama3
docker exec -it aisoc-ollama ollama pull nomic-embed-text

# 3. Access the dashboard
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

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8GB | 16-32GB |
| **Storage** | 20GB | 50GB+ SSD |
| **GPU** | Integrated | NVIDIA 8GB+ VRAM (optional) |

---

## What's Included

### Backend Services

- **Threat Intelligence Engine** - CVE database, zero-day detection, threat actors
- **RAG Pipeline** - Semantic search with ChromaDB + sentence-transformers
- **AI Security Agents** - Autonomous threat hunting, vulnerability analysis
- **Network Analysis** - nmap integration, service detection, vulnerability matching
- **IOC Correlation** - Check IPs, domains, hashes against threat intel
- **Threat Graph** - Relationship mapping between threats
- **Attack Simulation** - Educational scenarios for detection validation
- **Scheduler** - Automated feed updates and scans every 6 hours

### Frontend Dashboard

- **Threat Landscape** - Real-time threat statistics
- **Recent Threats** - Latest critical CVEs
- **AI Assistant** - Chat interface for threat intelligence queries
- **Network Exposure** - Network visualization
- **SOC Logs** - Real-time system activity via WebSocket

---

## API Endpoints

```bash
# Health check
curl http://localhost:8000/api/health

# Threat summary
curl http://localhost:8000/api/threat-intel/summary

# Query with AI
curl -X POST http://localhost:8000/api/rag/query \
  -H "Content-Type: application/json" \
  -d '{"query": "latest critical CVEs", "top_k": 5}'

# Network scan
curl -X POST http://localhost:8000/api/network/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"]}'
```

Full API documentation: http://localhost:8000/docs

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Frontend   │────▶│  Backend    │────▶│   Ollama    │
│  (3000)     │     │  (8000)     │     │   (11434)   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  ChromaDB   │
                    │  Vector DB  │
                    └─────────────┘
```

**100% Local** - No cloud dependencies, works offline

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
```

---

## Troubleshooting

**Backend won't start:**
```bash
docker-compose logs aisoc-backend
```

**Ollama connection error:**
```bash
docker-compose restart ollama
docker exec -it aisoc-ollama ollama list
```

**Model not found:**
```bash
docker exec -it aisoc-ollama ollama pull llama3
```

---

## Documentation

- **Full README**: `README.md`
- **API Docs**: http://localhost:8000/docs
- **Security Model**: See `README.md` Security section

---

**AI-SOC** — Autonomous Security Intelligence, 100% Local
