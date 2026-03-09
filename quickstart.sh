#!/bin/bash
# AI-SOC Quick Start Script
# Local AI-Powered Security Operations Center

set -e

echo "🛡️  AI-SOC - Local AI Security Operations Center"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is available
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo -e "${GREEN}✓${NC} Docker and Docker Compose found"
    USE_DOCKER=true
elif command -v python3 &> /dev/null; then
    echo -e "${YELLOW}!${NC} Docker not found, using local Python installation"
    USE_DOCKER=false
else
    echo -e "${RED}✗${NC} Neither Docker nor Python3 found"
    echo "Please install Docker (recommended) or Python 3.10+"
    exit 1
fi

if [ "$USE_DOCKER" = true ]; then
    echo ""
    echo "📦 Starting Docker Compose services..."
    
    # Start services
    docker-compose up -d
    
    echo ""
    echo "⏳ Waiting for services to start..."
    sleep 15
    
    # Check service health
    echo ""
    echo "🔍 Checking service health..."
    docker-compose ps
    
    echo ""
    echo "🤖 Pulling Ollama models (this may take a few minutes)..."
    docker exec aisoc-ollama ollama pull llama3 || echo "⚠️  Model pull failed, you can pull manually later"
    docker exec aisoc-ollama ollama pull nomic-embed-text || echo "⚠️  Embedding model pull failed, you can pull manually later"
    
    echo ""
    echo -e "${GREEN}✓${NC} Services started successfully!"
    echo ""
    echo "📍 Access Points:"
    echo "   Frontend:  http://localhost:3000"
    echo "   Backend:   http://localhost:8000"
    echo "   API Docs:  http://localhost:8000/docs"
    echo ""
    echo "📊 Service Status:"
    docker-compose ps
    echo ""
    echo "📝 View Logs:"
    echo "   docker-compose logs -f aisoc-backend"
    echo "   docker-compose logs -f ollama"
    echo ""
    echo "⏹️  To Stop:"
    echo "   docker-compose down"
    
else
    echo ""
    echo "📦 Setting up local Python environment..."
    
    cd backend
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
    
    # Create directories
    mkdir -p data/threat_intel data/raw_feeds vector_store/chroma_db
    
    echo ""
    echo -e "${GREEN}✓${NC} Setup completed!"
    echo ""
    echo "🚀 Next Steps:"
    echo "   1. Make sure Ollama is running: ollama serve"
    echo "   2. Pull models: ollama pull llama3"
    echo "   3. Start backend: python main.py"
    echo "   4. Open frontend/index.html in your browser"
    echo ""
fi

echo ""
echo "📖 Documentation: See README.md"
echo ""
