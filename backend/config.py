"""
AI-SOC Configuration
Local AI-Powered Security Operations Center
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
from pathlib import Path
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # ============================================
    # Application Settings
    # ============================================
    APP_NAME: str = "AI-SOC Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    
    # ============================================
    # Server Settings
    # ============================================
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    
    # ============================================
    # Local LLM Settings (Ollama)
    # ============================================
    OLLAMA_HOST: str = "http://127.0.0.1:11434"
    LLM_MODEL: str = "llama3"
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048
    
    # ============================================
    # Vector Database Settings
    # ============================================
    VECTOR_STORE_PATH: str = "./vector_store/chroma_db"
    VECTOR_STORE_COLLECTION: str = "threat_intelligence"
    
    # ============================================
    # Data Paths
    # ============================================
    DATA_DIR: str = "./data"
    THREAT_INTEL_DIR: str = "./data/threat_intel"
    RAW_FEEDS_DIR: str = "./data/raw_feeds"
    
    # ============================================
    # Network Analysis Settings
    # ============================================
    DEFAULT_SCAN_TARGETS: List[str] = ["192.168.1.0/24", "10.0.0.0/24"]
    SCAN_TIMEOUT: int = 300
    MAX_CONCURRENT_SCANS: int = 5
    
    # ============================================
    # Scheduler Settings
    # ============================================
    SCHEDULER_ENABLED: bool = True
    CVE_UPDATE_INTERVAL_HOURS: int = 6
    EMBEDDING_UPDATE_INTERVAL_HOURS: int = 12
    NETWORK_SCAN_INTERVAL_HOURS: int = 6
    THREAT_INTEL_UPDATE_INTERVAL_HOURS: int = 6
    
    # ============================================
    # Security Settings
    # ============================================
    API_KEY: Optional[str] = None  # Optional API key for authentication
    ENCRYPT_DATA_AT_REST: bool = False
    ENCRYPTION_KEY: Optional[str] = None
    
    # ============================================
    # Threat Intelligence Sources
    # ============================================
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MITRE_ATTACK_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    CISA_KNOWN_EXPLOITED_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    # ============================================
    # Rate Limiting
    # ============================================
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    
    # ============================================
    # WebSocket Settings
    # ============================================
    WS_HEARTBEAT_INTERVAL: int = 30
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Create settings instance
settings = Settings()

# Ensure directories exist
def ensure_directories():
    """Create necessary directories if they don't exist."""
    directories = [
        settings.DATA_DIR,
        settings.THREAT_INTEL_DIR,
        settings.RAW_FEEDS_DIR,
        settings.VECTOR_STORE_PATH,
    ]
    
    for dir_path in directories:
        path = Path(dir_path)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            print(f"Created directory: {dir_path}")


# Initialize directories on import
ensure_directories()
