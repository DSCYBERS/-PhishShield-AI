"""
Threat Intelligence API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

from app.services.threat_intelligence_service import threat_intelligence

logger = logging.getLogger(__name__)
router = APIRouter()

class ThreatIntelResponse(BaseModel):
    """Threat intelligence response model"""
    url: str
    is_malicious: bool
    threat_score: float
    reputation: str
    threat_sources: List[Dict[str, Any]]
    categories: List[str]
    detailed_results: Dict[str, Any]
    timestamp: datetime

class ThreatReportRequest(BaseModel):
    """Threat report request model"""
    url: HttpUrl
    threat_type: str
    confidence: float
    source: str
    description: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

class FeedStatusResponse(BaseModel):
    """Threat feed status response"""
    feeds: Dict[str, Dict[str, Any]]
    last_updated: datetime
    total_configured: int
    active_feeds: int

@router.get("/analyze/{url:path}", response_model=ThreatIntelResponse)
async def analyze_url_threats(url: str):
    """
    Get comprehensive threat intelligence analysis for a URL
    """
    try:
        logger.info(f"Analyzing threats for URL: {url}")
        
        # Ensure threat intelligence service is initialized
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        # Perform threat analysis
        result = await threat_intelligence.analyze_url_threats(url)
        
        return ThreatIntelResponse(
            url=result['url'],
            is_malicious=result['is_malicious'],
            threat_score=result['threat_score'],
            reputation=result['reputation'],
            threat_sources=result['threat_sources'],
            categories=result['categories'],
            detailed_results=result['detailed_results'],
            timestamp=datetime.fromisoformat(result['timestamp'])
        )
        
    except Exception as e:
        logger.error(f"Threat analysis failed for {url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Threat analysis failed: {str(e)}")

@router.get("/domain/{domain}", response_model=ThreatIntelResponse)
async def get_domain_intelligence(domain: str):
    """Get threat intelligence for a specific domain"""
    try:
        # Convert domain to URL format for analysis
        url = f"http://{domain}"
        
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        result = await threat_intelligence.analyze_url_threats(url)
        
        return ThreatIntelResponse(
            url=result['url'],
            is_malicious=result['is_malicious'],
            threat_score=result['threat_score'],
            reputation=result['reputation'],
            threat_sources=result['threat_sources'],
            categories=result['categories'],
            detailed_results=result['detailed_results'],
            timestamp=datetime.fromisoformat(result['timestamp'])
        )
        
    except Exception as e:
        logger.error(f"Domain intelligence lookup failed for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Domain intelligence lookup failed: {str(e)}")

@router.post("/report")
async def report_threat(
    threat_data: ThreatReportRequest,
    background_tasks: BackgroundTasks
):
    """
    Report a new threat to the threat intelligence system
    """
    try:
        logger.info(f"Receiving threat report for URL: {threat_data.url}")
        
        # Store threat report
        report_data = {
            "url": str(threat_data.url),
            "threat_type": threat_data.threat_type,
            "confidence": threat_data.confidence,
            "source": threat_data.source,
            "description": threat_data.description,
            "evidence": threat_data.evidence,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "reported"
        }
        
        # TODO: Store in database
        
        # Update threat intelligence cache in background
        background_tasks.add_task(
            invalidate_threat_cache,
            str(threat_data.url)
        )
        
        return {
            "status": "reported",
            "id": f"threat_{datetime.utcnow().timestamp()}",
            "url": str(threat_data.url),
            "threat_type": threat_data.threat_type
        }
        
    except Exception as e:
        logger.error(f"Threat reporting failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Threat reporting failed: {str(e)}")

@router.get("/feeds/status", response_model=FeedStatusResponse)
async def get_feeds_status():
    """
    Get status of all threat intelligence feeds
    """
    try:
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        feeds_status = await threat_intelligence.get_threat_feeds_status()
        
        total_configured = sum(1 for feed in feeds_status.values() if feed['configured'])
        active_feeds = sum(1 for feed in feeds_status.values() if feed['available'])
        
        return FeedStatusResponse(
            feeds=feeds_status,
            last_updated=datetime.utcnow(),
            total_configured=total_configured,
            active_feeds=active_feeds
        )
        
    except Exception as e:
        logger.error(f"Failed to get feeds status: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get feeds status: {str(e)}")

@router.post("/feeds/update")
async def update_threat_feeds(background_tasks: BackgroundTasks):
    """
    Manually trigger threat feeds update
    """
    try:
        logger.info("Manual threat feeds update triggered")
        
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        # Update feeds in background
        background_tasks.add_task(threat_intelligence.update_threat_feeds)
        
        return {
            "status": "updating",
            "message": "Threat feeds update started in background",
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Failed to trigger feeds update: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger feeds update: {str(e)}")

@router.get("/reputation/{domain}")
async def check_domain_reputation(domain: str):
    """
    Quick domain reputation check
    """
    try:
        url = f"http://{domain}"
        
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        result = await threat_intelligence.analyze_url_threats(url)
        
        return {
            "domain": domain,
            "reputation": result['reputation'],
            "threat_score": result['threat_score'],
            "is_malicious": result['is_malicious'],
            "quick_summary": f"Domain {domain} is {result['reputation']} with {result['threat_score']:.1%} threat score"
        }
        
    except Exception as e:
        logger.error(f"Reputation check failed for {domain}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Reputation check failed: {str(e)}")

async def invalidate_threat_cache(url: str):
    """Invalidate threat intelligence cache for a URL"""
    try:
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()
        cache_key = f"threat_analysis:{url_hash}"
        
        if threat_intelligence.redis_client:
            await threat_intelligence.redis_client.delete(cache_key)
            logger.info(f"Invalidated threat cache for {url}")
            
    except Exception as e:
        logger.error(f"Failed to invalidate cache for {url}: {e}")
