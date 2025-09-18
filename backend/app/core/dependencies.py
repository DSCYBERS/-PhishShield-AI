"""
Dependency injection for FastAPI
"""

from app.services.sandbox_service import sandbox_service
from app.services.ml_service import MLService

def get_sandbox_service():
    """Get sandbox service instance"""
    return sandbox_service

def get_ml_service():
    """Get ML service instance"""
    return MLService()
