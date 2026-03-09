"""
AI-SOC Backend API Server
Local AI-Powered Security Operations Center

This server provides:
- Threat intelligence APIs
- RAG-powered AI assistant
- Network analysis endpoints
- IOC correlation
- Attack simulation (educational)
- Real-time SOC logs
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import logging
import structlog
import uvicorn
from contextlib import asynccontextmanager

from config import settings
from threat_ingestion.ingestion import ThreatIngestionService
from rag.rag_engine import RAGEngine
from intelligence_engine.analyzer import IntelligenceEngine
from network_analysis.scanner import NetworkAnalyzer
from ioc_correlation.correlator import IOCCorrelator
from attack_simulation.simulator import AttackSimulator
from threat_graph.graph import ThreatGraph
from scheduler.scheduler import IntelligenceScheduler
from agents.agent_orchestrator import AgentOrchestrator
from attack_map.api import router as attack_map_router
from observability.api import router as observability_router
from detection_engine.api import router as detection_router
from threat_hunting.api import router as threat_hunting_router
from extended.api import router as extended_router
from phase4.api import router as phase4_router

# Configure structured logging
log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(log_level),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Security scheme (optional API key)
security = HTTPBearer(auto_error=False)


async def verify_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
) -> Optional[str]:
    """Verify API key if configured."""
    if not settings.API_KEY:
        return None
    
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if credentials.credentials != settings.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return credentials.credentials


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting AI-SOC backend services")
    
    try:
        # Initialize services
        app.state.ingestion_service = ThreatIngestionService()
        app.state.rag_engine = RAGEngine()
        app.state.intelligence_engine = IntelligenceEngine()
        app.state.network_analyzer = NetworkAnalyzer()
        app.state.ioc_correlator = IOCCorrelator()
        app.state.attack_simulator = AttackSimulator()
        app.state.threat_graph = ThreatGraph()
        app.state.agent_orchestrator = AgentOrchestrator()
        
        # Initialize scheduler (runs in background)
        app.state.scheduler = IntelligenceScheduler(
            ingestion_service=app.state.ingestion_service,
            rag_engine=app.state.rag_engine,
            network_analyzer=app.state.network_analyzer,
            agent_orchestrator=app.state.agent_orchestrator,
        )
        
        if settings.SCHEDULER_ENABLED:
            await app.state.scheduler.start()
            logger.info("Intelligence scheduler started")
        
        # Load existing threat intelligence into graph
        await app.state.threat_graph.load_from_datasets()
        
        logger.info("All AI-SOC services initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    if hasattr(app.state, 'scheduler') and app.state.scheduler:
        await app.state.scheduler.stop()
        logger.info("Intelligence scheduler stopped")
    
    logger.info("AI-SOC backend shutdown complete")


# Initialize FastAPI app
app = FastAPI(
    title="AI-SOC Backend",
    description="Local AI-Powered Security Operations Center API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Include attack map router
app.include_router(attack_map_router)

# Include observability router
app.include_router(observability_router)

# Include detection engine router
app.include_router(detection_router)

# Include threat hunting and SOAR router
app.include_router(threat_hunting_router)

# Include extended APIs (zero-day, endpoint, risk)
app.include_router(extended_router)

# Include Phase 4 APIs (anomaly detection, UBA)
app.include_router(phase4_router)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connections for real-time logs
websocket_connections: List[WebSocket] = []


# ==============
# Pydantic Models
# ==============

class LogMessage(BaseModel):
    """Log message structure."""
    level: str
    timestamp: str
    message: str
    source: str
    data: Optional[Dict[str, Any]] = None


class ChatRequest(BaseModel):
    """Chat request structure."""
    query: str
    context: Optional[Dict[str, Any]] = None


class NetworkScanRequest(BaseModel):
    """Network scan request structure."""
    targets: Optional[List[str]] = None
    scan_type: str = "basic"  # basic, full, aggressive
    ports: Optional[str] = None


class AttackSimulationRequest(BaseModel):
    """Attack simulation request structure."""
    scenario: str
    target_type: str
    educational_mode: bool = True


class IOCQuery(BaseModel):
    """IOC query structure."""
    ioc_type: str  # ip, domain, hash, url
    value: str


class ThreatGraphQuery(BaseModel):
    """Threat graph query structure."""
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    relationship_type: Optional[str] = None
    depth: int = 2


class RAGQuery(BaseModel):
    """RAG query structure."""
    query: str
    top_k: int = 5
    include_sources: bool = True


# ==============
# API Endpoints
# ==============

@app.get("/")
async def root():
    """Root endpoint - API health check."""
    return {
        "service": "AI-SOC Backend",
        "version": settings.APP_VERSION,
        "status": "running",
        "mode": "local-only",
    }


@app.get("/api/health")
async def health_check():
    """Detailed health check endpoint."""
    services_status = {
        "ingestion": hasattr(app.state, 'ingestion_service') and app.state.ingestion_service is not None,
        "rag_engine": hasattr(app.state, 'rag_engine') and app.state.rag_engine is not None,
        "intelligence": hasattr(app.state, 'intelligence_engine') and app.state.intelligence_engine is not None,
        "network_analysis": hasattr(app.state, 'network_analyzer') and app.state.network_analyzer is not None,
        "ioc_correlation": hasattr(app.state, 'ioc_correlator') and app.state.ioc_correlator is not None,
        "attack_simulation": hasattr(app.state, 'attack_simulator') and app.state.attack_simulator is not None,
        "threat_graph": hasattr(app.state, 'threat_graph') and app.state.threat_graph is not None,
        "scheduler": hasattr(app.state, 'scheduler') and app.state.scheduler is not None,
        "agents": hasattr(app.state, 'agent_orchestrator') and app.state.agent_orchestrator is not None,
    }
    
    return {
        "status": "healthy",
        "services": services_status,
        "local_mode": True,
        "cloud_dependencies": False,
    }


@app.get("/api/threat-intel/summary")
async def get_threat_intel_summary(_: Optional[str] = Depends(verify_api_key)):
    """Get summary of threat intelligence data."""
    try:
        summary = await app.state.intelligence_engine.get_threat_summary()
        return {"status": "success", "data": summary}
    except Exception as e:
        logger.error(f"Failed to get threat intel summary: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-intel/cves")
async def get_cves(
    severity: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    _: Optional[str] = Depends(verify_api_key),
):
    """Get CVE database entries with optional filtering."""
    try:
        cves = await app.state.intelligence_engine.get_cves(
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"status": "success", "data": cves}
    except Exception as e:
        logger.error(f"Failed to get CVEs: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-intel/zero-days")
async def get_zero_days(_: Optional[str] = Depends(verify_api_key)):
    """Get zero-day vulnerability alerts."""
    try:
        zero_days = await app.state.intelligence_engine.get_zero_day_alerts()
        return {"status": "success", "data": zero_days}
    except Exception as e:
        logger.error(f"Failed to get zero-days: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-intel/threat-actors")
async def get_threat_actors(_: Optional[str] = Depends(verify_api_key)):
    """Get threat actor database."""
    try:
        actors = await app.state.intelligence_engine.get_threat_actors()
        return {"status": "success", "data": actors}
    except Exception as e:
        logger.error(f"Failed to get threat actors: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-intel/mitre-attack")
async def get_mitre_attack(_: Optional[str] = Depends(verify_api_key)):
    """Get MITRE ATT&CK framework data."""
    try:
        mitre_data = await app.state.intelligence_engine.get_mitre_attack_data()
        return {"status": "success", "data": mitre_data}
    except Exception as e:
        logger.error(f"Failed to get MITRE ATT&CK data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rag/query")
async def rag_query(request: RAGQuery, _: Optional[str] = Depends(verify_api_key)):
    """Query threat intelligence using RAG."""
    try:
        response = await app.state.rag_engine.query(
            query=request.query,
            top_k=request.top_k,
            include_sources=request.include_sources,
        )
        return {"status": "success", "data": response}
    except Exception as e:
        logger.error(f"RAG query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/chat")
async def chat(request: ChatRequest, _: Optional[str] = Depends(verify_api_key)):
    """AI-powered threat intelligence chat using RAG."""
    try:
        response = await app.state.rag_engine.query(
            query=request.query,
            context=request.context,
        )
        return {"status": "success", "data": response}
    except Exception as e:
        logger.error(f"Chat query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/network/scan")
async def scan_network(
    request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    _: Optional[str] = Depends(verify_api_key),
):
    """Initiate network scan."""
    try:
        targets = request.targets or settings.DEFAULT_SCAN_TARGETS
        scan_result = await app.state.network_analyzer.scan(
            targets=targets,
            scan_type=request.scan_type,
            ports=request.ports,
        )
        return {"status": "success", "data": scan_result}
    except Exception as e:
        logger.error(f"Network scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/network/results")
async def get_network_scan_results(_: Optional[str] = Depends(verify_api_key)):
    """Get latest network scan results."""
    try:
        results = await app.state.network_analyzer.get_latest_results()
        return {"status": "success", "data": results}
    except Exception as e:
        logger.error(f"Failed to get scan results: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ioc/check")
async def check_ioc(request: IOCQuery, _: Optional[str] = Depends(verify_api_key)):
    """Check an IOC against threat intelligence."""
    try:
        result = await app.state.ioc_correlator.check_ioc(
            ioc_type=request.ioc_type,
            value=request.value,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"IOC check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ioc/bulk-check")
async def bulk_check_ioc(
    iocs: List[IOCQuery],
    _: Optional[str] = Depends(verify_api_key),
):
    """Bulk check multiple IOCs."""
    try:
        results = await app.state.ioc_correlator.bulk_check(iocs)
        return {"status": "success", "data": results}
    except Exception as e:
        logger.error(f"Bulk IOC check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/simulation/run")
async def run_simulation(
    request: AttackSimulationRequest,
    _: Optional[str] = Depends(verify_api_key),
):
    """Run educational attack simulation."""
    try:
        if not request.educational_mode:
            raise HTTPException(
                status_code=400,
                detail="Only educational mode simulations are allowed",
            )
        
        result = await app.state.attack_simulator.run_simulation(
            scenario=request.scenario,
            target_type=request.target_type,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Simulation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/simulation/scenarios")
async def get_simulation_scenarios(_: Optional[str] = Depends(verify_api_key)):
    """Get available attack simulation scenarios."""
    try:
        scenarios = await app.state.attack_simulator.get_scenarios()
        return {"status": "success", "data": scenarios}
    except Exception as e:
        logger.error(f"Failed to get scenarios: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/graph/query")
async def query_threat_graph(
    request: ThreatGraphQuery,
    _: Optional[str] = Depends(verify_api_key),
):
    """Query the threat intelligence graph."""
    try:
        result = await app.state.threat_graph.query(
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            relationship_type=request.relationship_type,
            depth=request.depth,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Graph query failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graph/entities")
async def get_graph_entities(_: Optional[str] = Depends(verify_api_key)):
    """Get all entity types in the threat graph."""
    try:
        entities = await app.state.threat_graph.get_entity_types()
        return {"status": "success", "data": entities}
    except Exception as e:
        logger.error(f"Failed to get entities: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agents/status")
async def get_agents_status(_: Optional[str] = Depends(verify_api_key)):
    """Get status of autonomous AI agents."""
    try:
        status = await app.state.agent_orchestrator.get_status()
        return {"status": "success", "data": status}
    except Exception as e:
        logger.error(f"Failed to get agent status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agents/{agent_id}/trigger")
async def trigger_agent(
    agent_id: str,
    parameters: Optional[Dict[str, Any]] = None,
    _: Optional[str] = Depends(verify_api_key),
):
    """Trigger a specific AI agent."""
    try:
        result = await app.state.agent_orchestrator.trigger_agent(
            agent_id=agent_id,
            parameters=parameters,
        )
        return {"status": "success", "data": result}
    except Exception as e:
        logger.error(f"Failed to trigger agent: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ingestion/update")
async def trigger_ingestion(
    background_tasks: BackgroundTasks,
    _: Optional[str] = Depends(verify_api_key),
):
    """Manually trigger threat feed ingestion."""
    try:
        background_tasks.add_task(app.state.ingestion_service.run_full_ingestion)
        return {"status": "success", "message": "Ingestion started in background"}
    except Exception as e:
        logger.error(f"Failed to trigger ingestion: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for real-time SOC logs."""
    await websocket.accept()
    websocket_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive, receive messages if any
            data = await websocket.receive_text()
            # Could handle commands from client
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)


async def broadcast_log(log_data: Dict[str, Any]):
    """Broadcast log message to all connected WebSocket clients."""
    for connection in websocket_connections:
        try:
            await connection.send_json(log_data)
        except Exception:
            pass  # Client disconnected


# Custom log handler to broadcast to WebSocket clients
class WebSocketLogHandler:
    async def __call__(self, _, method_name, event_dict):
        log_data = {
            "level": method_name,
            "timestamp": event_dict.get("timestamp", ""),
            "message": event_dict.get("event", ""),
            "source": "aisoc",
            "data": {k: v for k, v in event_dict.items() if k not in ["event", "timestamp"]},
        }
        await broadcast_log(log_data)
        return structlog.dev.ConsoleRenderer()(method_name, event_dict)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
