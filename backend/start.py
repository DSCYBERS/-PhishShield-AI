#!/usr/bin/env python3
"""
Quick Start Script for PhishShield AI Backend
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

async def main():
    print("🛡️  Starting PhishShield AI Backend...")
    
    # Check environment file
    env_file = current_dir / ".env"
    if not env_file.exists():
        print("❌ .env file not found! Please create one from .env.example")
        return
    
    try:
        # Import and start the application
        import uvicorn
        from main import app
        
        print("✅ Environment loaded")
        print("✅ FastAPI app imported")
        print("🚀 Starting server on http://localhost:8000")
        print("📚 API documentation: http://localhost:8000/docs")
        
        # Start the server
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()
        
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("💡 Run: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Error starting server: {e}")

if __name__ == "__main__":
    asyncio.run(main())
