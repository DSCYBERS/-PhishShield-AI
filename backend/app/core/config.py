"""
Configuration settings for PhishShield AI Backend
"""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "PhishShield AI Backend"
    DEBUG: bool = False
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    
    # Database
    DATABASE_URL: str = "postgresql://phishshield:phishshield123@localhost:5432/phishshield_db"
    DATABASE_ECHO: bool = False
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_EXPIRE_TIME: int = 3600  # 1 hour
    
    # Neo4j (Network Graph)
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "phishshield123"
    
    # Security
    ALLOWED_HOSTS: List[str] = ["*"]
    API_KEY_HEADER: str = "X-API-Key"
    
    # ML Models
    ML_MODEL_PATH: str = "./models"
    MODEL_UPDATE_INTERVAL: int = 86400  # 24 hours
    
    # Sandbox
    SANDBOX_ENABLED: bool = True
    SANDBOX_TIMEOUT: int = 30  # seconds
    SANDBOX_MAX_CONCURRENT: int = 10
    SANDBOX_SCREENSHOTS: bool = True
    
    # External APIs
    VIRUSTOTAL_API_KEY: Optional[str] = None
    URLVOID_API_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 3600  # 1 hour
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Feature Flags
    ENABLE_THREAT_INTEL_SYNC: bool = True
    ENABLE_ML_INFERENCE: bool = True
    ENABLE_NETWORK_ANALYSIS: bool = True
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Create settings instance
settings = Settings()
