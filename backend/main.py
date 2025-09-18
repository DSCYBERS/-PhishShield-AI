"""
PhishShield AI Backend - Main FastAPI Application
Provides cloud-based URL analysis for layers 6-7 of the detection pipeline
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import uvicorn
import logging
from datetime import datetime
import asyncio

from app.core.config import settings
from app.core.logging import setup_logging
from app.api.routes import analysis, health, threat_intel
from app.core.database import init_db
from app.core.redis import init_redis
from app.services.ml_service import MLService
from app.services.sandbox_service import SandboxService

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("PhishShield AI Backend starting up...")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Initialize Redis
    await init_redis()
    logger.info("Redis initialized")
    
    # Initialize ML models
    ml_service = MLService()
    await ml_service.load_models()
    logger.info("ML models loaded")
    
    # Initialize sandbox service
    sandbox_service = SandboxService()
    await sandbox_service.initialize()
    logger.info("Sandbox service initialized")
    
    logger.info("PhishShield AI Backend startup complete")
    
    yield
    
    # Shutdown
    logger.info("PhishShield AI Backend shutting down...")

# Create FastAPI application
app = FastAPI(
    title="PhishShield AI Backend",
    description="Cloud-based URL analysis and threat detection service",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_HOSTS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["analysis"])
app.include_router(threat_intel.router, prefix="/api/v1/threat-intel", tags=["threat-intelligence"])

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "PhishShield AI Backend",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "documentation": "/docs"
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    # TODO: Implement Prometheus metrics
    return {"metrics": "not_implemented"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
