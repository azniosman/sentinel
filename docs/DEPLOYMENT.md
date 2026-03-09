# AI-SOC Deployment Guide

Complete guide for deploying and operating the AI-SOC platform.

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Deployment Options](#deployment-options)
3. [Docker Compose Deployment](#docker-compose-deployment)
4. [Local Installation](#local-installation)
5. [Configuration](#configuration)
6. [Post-Installation](#post-installation)
7. [Operations](#operations)
8. [Troubleshooting](#troubleshooting)
9. [Security Hardening](#security-hardening)
10. [Backup and Recovery](#backup-and-recovery)

---

## System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|---------------|
| **CPU** | 4 cores (8+ recommended) |
| **RAM** | 8GB (16GB recommended) |
| **Storage** | 20GB SSD (50GB+ recommended) |
| **OS** | Linux, macOS, Windows 10+ |
| **Network** | Local network access for scanning |

### Recommended Requirements

| Component | Specification |
|-----------|---------------|
| **CPU** | 8+ cores (Ryzen 7 / i7 or better) |
| **RAM** | 16-32GB |
| **Storage** | 50GB+ NVMe SSD |
| **GPU** | NVIDIA 8GB+ VRAM (optional, for faster LLM) |
| **Network** | Gigabit Ethernet |

### Software Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| **Docker** | 20.10+ | Container runtime |
| **Docker Compose** | 2.0+ | Orchestration |
| **OR Python** | 3.10+ | Local installation |
| **Ollama** | Latest | Local LLM runtime |

---

## Deployment Options

### Option 1: Docker Compose (Recommended)

**Pros:**
- ✅ Easy setup and deployment
- ✅ Service isolation
- ✅ Automatic dependency management
- ✅ Persistent volumes for data
- ✅ Health checks and restart policies
- ✅ GPU support (optional)

**Cons:**
- ❌ Requires Docker
- ❌ Slight overhead vs native

### Option 2: Local Installation

**Pros:**
- ✅ No Docker required
- ✅ Direct hardware access
- ✅ Easier debugging

**Cons:**
- ❌ Manual dependency management
- ❌ More complex setup
- ❌ No service isolation

---

## Docker Compose Deployment

### Step 1: Prerequisites

Install Docker and Docker Compose:

**Ubuntu/Debian:**
```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt-get install docker-compose-plugin
```

**macOS:**
```bash
# Install Docker Desktop
brew install --cask docker
```

**Windows:**
```bash
# Install Docker Desktop
# Download from https://docker.com/products/docker-desktop
```

### Step 2: Clone Repository

```bash
git clone <repository-url> sentinel
cd sentinel/aisoc
```

### Step 3: Configure Environment

Create backend `.env` file:

```bash
cd backend
cp .env.example .env
nano .env
```

Recommended production settings:

```bash
# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false
LOG_LEVEL=INFO

# LLM
OLLAMA_HOST=http://ollama:11434
LLM_MODEL=llama3
EMBEDDING_MODEL=all-MiniLM-L6-v2

# Security
API_KEY=your-secure-random-key-here
ENCRYPT_DATA_AT_REST=true

# Scheduler
SCHEDULER_ENABLED=true
CVE_UPDATE_INTERVAL_HOURS=6
```

### Step 4: Start Services

```bash
cd docker
docker-compose up -d
```

### Step 5: Pull LLM Models

```bash
# Wait for Ollama to start
sleep 10

# Pull required models
docker exec -it aisoc-ollama ollama pull llama3
docker exec -it aisoc-ollama ollama pull nomic-embed-text

# Optional: Pull smaller model for faster inference
docker exec -it aisoc-ollama ollama pull mistral:7b
docker exec -it aisoc-ollama ollama pull phi3:mini
```

### Step 6: Verify Deployment

```bash
# Check service status
docker-compose ps

# Expected output:
# NAME              STATUS                    PORTS
# aisoc-backend     Up (healthy)              0.0.0.0:8000->8000/tcp
# aisoc-frontend    Up                        0.0.0.0:3000->80/tcp
# aisoc-ollama      Up (healthy)              0.0.0.0:11434->11434/tcp

# Check backend health
curl http://localhost:8000/api/health

# Check frontend
curl http://localhost:3000
```

### Step 7: Access Dashboard

Open browser and navigate to:
- **Frontend**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Backend Health**: http://localhost:8000/api/health

---

## Local Installation

### Step 1: Install Ollama

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

**Windows:**
Download from https://ollama.ai/download

### Step 2: Pull Models

```bash
ollama pull llama3
ollama pull nomic-embed-text
```

### Step 3: Install Python Dependencies

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

### Step 4: Configure Environment

```bash
cp .env.example .env
nano .env
```

Set for local installation:

```bash
OLLAMA_HOST=http://127.0.0.1:11434
HOST=127.0.0.1
PORT=8000
```

### Step 5: Create Directories

```bash
mkdir -p data/threat_intel data/raw_feeds vector_store/chroma_db
```

### Step 6: Start Backend

```bash
python main.py
```

### Step 7: Serve Frontend

Option A - Python HTTP server:
```bash
cd frontend
python3 -m http.server 3000
```

Option B - Open directly:
```bash
# Open frontend/index.html in browser
open frontend/index.html  # macOS
xdg-open frontend/index.html  # Linux
```

---

## Configuration

### Environment Variables

Complete list of configuration options:

#### Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `AI-SOC Backend` | Application name |
| `APP_VERSION` | `1.0.0` | Version |
| `DEBUG` | `true` | Debug mode |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |

#### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8000` | Port number |
| `ALLOWED_ORIGINS` | `[localhost:3000, ...]` | CORS origins (comma-separated) |

#### LLM

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama endpoint |
| `LLM_MODEL` | `llama3` | LLM model name |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | Embedding model |
| `LLM_TEMPERATURE` | `0.1` | Response creativity (0-1) |
| `LLM_MAX_TOKENS` | `2048` | Max response length |

#### Vector Store

| Variable | Default | Description |
|----------|---------|-------------|
| `VECTOR_STORE_PATH` | `./vector_store/chroma_db` | ChromaDB path |
| `VECTOR_STORE_COLLECTION` | `threat_intelligence` | Collection name |

#### Network Analysis

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_SCAN_TARGETS` | `192.168.1.0/24,10.0.0.0/24` | Scan targets |
| `SCAN_TIMEOUT` | `300` | Scan timeout (seconds) |
| `MAX_CONCURRENT_SCANS` | `5` | Max concurrent scans |

#### Scheduler

| Variable | Default | Description |
|----------|---------|-------------|
| `SCHEDULER_ENABLED` | `true` | Enable scheduler |
| `CVE_UPDATE_INTERVAL_HOURS` | `6` | CVE update interval |
| `EMBEDDING_UPDATE_INTERVAL_HOURS` | `12` | Embedding refresh |
| `NETWORK_SCAN_INTERVAL_HOURS` | `6` | Network scan interval |
| `THREAT_INTEL_UPDATE_INTERVAL_HOURS` | `6` | Intel update interval |

#### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `None` | API key for authentication |
| `ENCRYPT_DATA_AT_REST` | `false` | Enable data encryption |
| `ENCRYPTION_KEY` | `None` | Encryption key |

### Configuration Examples

#### Development

```bash
DEBUG=true
LOG_LEVEL=DEBUG
HOST=127.0.0.1
PORT=8000
SCHEDULER_ENABLED=false
```

#### Production

```bash
DEBUG=false
LOG_LEVEL=INFO
HOST=0.0.0.0
PORT=8000
API_KEY=your-secure-key
SCHEDULER_ENABLED=true
ENCRYPT_DATA_AT_REST=true
```

#### Air-Gapped (Offline)

```bash
SCHEDULER_ENABLED=false
OLLAMA_HOST=http://127.0.0.1:11434
# Pre-download all models and data before disconnecting
```

#### GPU-Accelerated

```bash
# Docker Compose: Enable GPU in docker-compose.yml
# See docker-compose.yml for GPU configuration

OLLAMA_HOST=http://ollama:11434
LLM_MODEL=llama3
```

---

## Post-Installation

### Initial Setup

1. **Verify all services are healthy:**
   ```bash
   docker-compose ps
   curl http://localhost:8000/api/health
   ```

2. **Pull LLM models:**
   ```bash
   docker exec -it aisoc-ollama ollama pull llama3
   docker exec -it aisoc-ollama ollama pull nomic-embed-text
   ```

3. **Trigger initial threat intel ingestion:**
   ```bash
   curl -X POST http://localhost:8000/api/ingestion/update
   ```

4. **Run initial network scan:**
   ```bash
   curl -X POST http://localhost:8000/api/network/scan \
     -H "Content-Type: application/json" \
     -d '{"targets": ["192.168.1.0/24"], "scan_type": "basic"}'
   ```

5. **Check agent status:**
   ```bash
   curl http://localhost:8000/api/agents/status
   ```

### Model Optimization

For systems with limited RAM:

```bash
# Use smaller LLM
docker exec -it aisoc-ollama ollama pull mistral:7b
docker exec -it aisoc-ollama ollama pull phi3:mini

# Update configuration
# Edit backend/.env
LLM_MODEL=mistral:7b
```

### Custom Threat Feeds

To add custom threat intelligence:

1. Format data according to schema in `backend/threat_ingestion/schema.py`
2. Place JSON files in `data/threat_intel/`
3. Restart backend: `docker-compose restart aisoc-backend`

---

## Operations

### Starting Services

```bash
# Docker Compose
cd docker
docker-compose up -d

# Local
cd backend
source venv/bin/activate
python main.py
```

### Stopping Services

```bash
# Docker Compose
docker-compose down

# Local
# Press Ctrl+C in terminal
```

### Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f aisoc-backend
docker-compose logs -f ollama

# Last 100 lines
docker-compose logs --tail=100 aisoc-backend
```

### Restarting Services

```bash
# Restart all
docker-compose restart

# Restart specific
docker-compose restart aisoc-backend
```

### Health Checks

```bash
# Backend health
curl http://localhost:8000/api/health

# Ollama health
curl http://localhost:11434/api/tags

# Frontend
curl http://localhost:3000
```

### Manual Tasks

```bash
# Trigger threat intel update
curl -X POST http://localhost:8000/api/ingestion/update

# Run network scan
curl -X POST http://localhost:8000/api/network/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"]}'

# Trigger AI agents
curl -X POST http://localhost:8000/api/agents/threat_hunter/trigger
```

---

## Troubleshooting

### Backend Won't Start

**Check logs:**
```bash
docker-compose logs aisoc-backend
```

**Common issues:**

1. **Port already in use:**
   ```bash
   # Change PORT in .env
   PORT=8001
   ```

2. **Ollama not accessible:**
   ```bash
   # Check Ollama is running
   docker-compose ps ollama
   
   # Restart Ollama
   docker-compose restart ollama
   ```

3. **Missing dependencies:**
   ```bash
   # Rebuild container
   docker-compose build --no-cache aisoc-backend
   docker-compose up -d
   ```

### Ollama Connection Issues

**Check Ollama status:**
```bash
docker exec -it aisoc-ollama ollama list
```

**Pull models:**
```bash
docker exec -it aisoc-ollama ollama pull llama3
```

**Restart Ollama:**
```bash
docker-compose restart ollama
```

### Vector Database Errors

**Reset vector store:**
```bash
# WARNING: Deletes all embeddings
docker-compose down
docker volume rm aisoc_aisoc_vector_store
docker-compose up -d

# Trigger re-ingestion
curl -X POST http://localhost:8000/api/ingestion/update
```

### Network Scanning Issues

**nmap not available:**
```bash
# Install nmap in container
docker exec -it aisoc-backend apt-get install -y nmap

# Or use fallback scanner (automatic)
```

**Permission denied:**
```bash
# Run as root (not recommended for production)
# Or add capabilities in docker-compose.yml
```

### High Memory Usage

**Reduce model size:**
```bash
# Use smaller models
docker exec -it aisoc-ollama ollama pull phi3:mini

# Update configuration
LLM_MODEL=phi3:mini
```

**Limit concurrent operations:**
```bash
MAX_CONCURRENT_SCANS=2
```

### Slow Performance

**Enable GPU (NVIDIA):**
1. Install NVIDIA Container Toolkit
2. Uncomment GPU section in `docker-compose.yml`
3. Restart services

**Use faster models:**
```bash
LLM_MODEL=mistral:7b
EMBEDDING_MODEL=all-MiniLM-L6-v2
```

---

## Security Hardening

### Enable API Authentication

```bash
# Generate secure API key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Add to .env
API_KEY=your-generated-key
```

### Configure Firewall

**Linux (ufw):**
```bash
sudo ufw allow 3000/tcp  # Frontend
sudo ufw allow 8000/tcp  # Backend
sudo ufw enable
```

**Linux (iptables):**
```bash
sudo iptables -A INPUT -p tcp --dport 8000 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8000 -j DROP
```

### HTTPS Configuration

For production, use reverse proxy with HTTPS:

**Nginx example:**
```nginx
server {
    listen 443 ssl;
    server_name aisoc.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
    }
}
```

### Enable Data Encryption

```bash
# Generate encryption key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Add to .env
ENCRYPT_DATA_AT_REST=true
ENCRYPTION_KEY=your-generated-key
```

### Network Isolation

For Docker deployment, services are already isolated. For additional security:

```yaml
# docker-compose.yml
networks:
  aisoc-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

---

## Backup and Recovery

### Backup Data

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup threat intelligence
tar -czf "$BACKUP_DIR/threat_intel_$DATE.tar.gz" data/threat_intel/

# Backup vector store
tar -czf "$BACKUP_DIR/vector_store_$DATE.tar.gz" vector_store/chroma_db/

# Backup configuration
cp backend/.env "$BACKUP_DIR/env_$DATE"

echo "Backup completed: $BACKUP_DIR"
```

### Restore Data

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE=$1

# Stop services
docker-compose down

# Restore data
tar -xzf "$BACKUP_FILE" -C /

# Start services
docker-compose up -d

echo "Restore completed"
```

### Scheduled Backups

```bash
# Add to crontab
0 2 * * * /path/to/backup.sh
```

---

## Performance Tuning

### LLM Optimization

| Model | VRAM Required | Speed | Quality |
|-------|---------------|-------|---------|
| `phi3:mini` | 2GB | Fast | Good |
| `mistral:7b` | 4GB | Medium | Very Good |
| `llama3:8b` | 6GB | Medium | Excellent |
| `llama3:70b` | 40GB | Slow | Best |

### Embedding Optimization

```bash
# Batch size for ingestion
# Edit rag_engine.py: Increase batch_size parameter

# Use GPU for embeddings
# Requires CUDA-enabled sentence-transformers
```

### Database Optimization

For large deployments:

```python
# ChromaDB settings
# Edit rag_engine.py
client_settings = chromadb.Settings(
    anonymized_telemetry=False,
    allow_reset=True,
    is_persistent=True,
)
```

---

## Monitoring

### Health Check Script

```bash
#!/bin/bash
# health_check.sh

echo "=== AI-SOC Health Check ==="

# Backend
echo -n "Backend: "
curl -s http://localhost:8000/api/health | jq -r '.status'

# Ollama
echo -n "Ollama: "
curl -s http://localhost:11434/api/tags | jq -r 'if .models then "healthy" else "error" end'

# Frontend
echo -n "Frontend: "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000
echo ""

# Disk usage
echo "=== Disk Usage ==="
du -sh data/ vector_store/
```

### Metrics to Monitor

| Metric | Threshold | Action |
|--------|-----------|--------|
| Memory Usage | >90% | Reduce model size |
| Disk Usage | >80% | Clean old data |
| Response Time | >10s | Check LLM status |
| Error Rate | >5% | Check logs |

---

## Support

For additional help:

1. Check logs: `docker-compose logs -f`
2. Review documentation: `docs/` directory
3. API documentation: http://localhost:8000/docs
4. Check GitHub issues for known problems

---

**AI-SOC** — Autonomous Security Intelligence, 100% Local
