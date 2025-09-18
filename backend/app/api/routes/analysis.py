"""
URL Analysis API Routes - Layer 6 & 7 Cloud Analysis
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime
import asyncio
import logging

from app.services.sandbox_service import SandboxService
from app.services.ml_service import MLService
from app.services.threat_intelligence_service import threat_intelligence
from app.services.network_analysis_service import NetworkAnalysisService
from app.core.dependencies import get_sandbox_service, get_ml_service

logger = logging.getLogger(__name__)
router = APIRouter()

class URLAnalysisRequest(BaseModel):
    """URL analysis request model"""
    url: HttpUrl
    client_id: Optional[str] = None
    previous_layers: Optional[Dict[str, Any]] = None
    priority: Optional[str] = "normal"  # normal, high, urgent

class URLAnalysisResponse(BaseModel):
    """URL analysis response model"""
    url: str
    is_malicious: bool
    threat_level: str  # low, medium, high, critical
    confidence: float
    analysis_layers: List[str]
    scan_time: float
    details: Dict[str, Any]
    timestamp: datetime

class SandboxAnalysisResult(BaseModel):
    """Sandbox analysis result model"""
    url: str
    page_title: Optional[str]
    final_url: str
    redirects: List[str]
    forms_detected: List[Dict[str, Any]]
    javascript_behavior: Dict[str, Any]
    network_requests: List[str]
    screenshots: List[str]
    risk_indicators: List[str]
    execution_time: float

@router.post("/scan", response_model=URLAnalysisResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    background_tasks: BackgroundTasks,
    sandbox_service: SandboxService = Depends(get_sandbox_service),
    ml_service: MLService = Depends(get_ml_service)
):
    """
    Perform deep URL analysis using layers 6-7:
    - Layer 6: Dynamic Behavioral Sandbox
    - Layer 7: Network Graph Analysis
    """
    start_time = datetime.utcnow()
    analysis_layers = []
    details = {}
    
    try:
        logger.info(f"Starting deep analysis for URL: {request.url}")
        
        # Initialize threat intelligence service
        if not threat_intelligence.redis_client:
            await threat_intelligence.initialize()
        
        # Layer 0: Threat Intelligence Check (Pre-analysis)
        logger.info("Running Layer 0: Threat Intelligence Check")
        threat_intel_result = await threat_intelligence.analyze_url_threats(str(request.url))
        analysis_layers.append("ThreatIntelligence")
        details["threat_intelligence"] = threat_intel_result
        
        # If already confirmed malicious with high confidence, skip expensive analysis
        if threat_intel_result["is_malicious"] and threat_intel_result["threat_score"] > 0.8:
            logger.info("URL confirmed malicious by threat intelligence, skipping sandbox analysis")
            
            scan_time = (datetime.utcnow() - start_time).total_seconds()
            
            return URLAnalysisResponse(
                url=str(request.url),
                is_malicious=True,
                threat_level="critical",
                confidence=threat_intel_result["threat_score"],
                analysis_layers=analysis_layers,
                scan_time=scan_time,
                details=details,
                timestamp=datetime.utcnow()
            )
        
        # Layer 6: Dynamic Behavioral Sandbox
        logger.info("Running Layer 6: Dynamic Behavioral Sandbox")
        sandbox_result = await sandbox_service.analyze_url(str(request.url))
        analysis_layers.append("Sandbox")
        details["sandbox"] = sandbox_result
        
        # Calculate sandbox risk score
        sandbox_risk = calculate_sandbox_risk(sandbox_result)
        
        # Layer 7: Network Graph Analysis
        logger.info("Running Layer 7: Network Graph Analysis")
        network_service = NetworkAnalysisService()
        network_result = await network_service.analyze_url_network(str(request.url))
        analysis_layers.append("NetworkGraph")
        details["network"] = network_result
        
        # Calculate network risk score
        network_risk = calculate_network_risk(network_result)
        
        # Advanced ML analysis using cloud models
        ml_result = await ml_service.analyze_advanced(
            url=str(request.url),
            sandbox_data=sandbox_result,
            network_data=network_result,
            previous_layers=request.previous_layers or {}
        )
        analysis_layers.append("AdvancedML")
        details["ml_analysis"] = ml_result
        
        # Calculate final threat assessment (including threat intelligence)
        final_score = calculate_final_threat_score(
            threat_intel_result["threat_score"],
            sandbox_risk, 
            network_risk, 
            ml_result["confidence"]
        )
        
        threat_level = determine_threat_level(final_score)
        is_malicious = threat_level in ["high", "critical"]
        
        # Calculate scan time
        scan_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Store analysis result for future reference
        background_tasks.add_task(
            store_analysis_result,
            str(request.url),
            is_malicious,
            threat_level,
            final_score,
            details
        )
        
        # Update threat intelligence if malicious
        if is_malicious:
            background_tasks.add_task(
                update_threat_intelligence,
                str(request.url),
                threat_level,
                details
            )
        
        response = URLAnalysisResponse(
            url=str(request.url),
            is_malicious=is_malicious,
            threat_level=threat_level,
            confidence=final_score,
            analysis_layers=analysis_layers,
            scan_time=scan_time,
            details=details,
            timestamp=datetime.utcnow()
        )
        
        logger.info(f"Analysis complete for {request.url}: {threat_level} ({final_score:.2f})")
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/sandbox", response_model=SandboxAnalysisResult)
async def sandbox_analysis(
    request: URLAnalysisRequest,
    sandbox_service: SandboxService = Depends(get_sandbox_service)
):
    """
    Perform isolated sandbox analysis (Layer 6 only)
    """
    try:
        logger.info(f"Starting sandbox analysis for URL: {request.url}")
        
        result = await sandbox_service.analyze_url(str(request.url))
        
        return SandboxAnalysisResult(
            url=str(request.url),
            page_title=result.get("page_title"),
            final_url=result.get("final_url", str(request.url)),
            redirects=result.get("redirects", []),
            forms_detected=result.get("forms", []),
            javascript_behavior=result.get("javascript", {}),
            network_requests=result.get("network_requests", []),
            screenshots=result.get("screenshots", []),
            risk_indicators=result.get("risk_indicators", []),
            execution_time=result.get("execution_time", 0.0)
        )
        
    except Exception as e:
        logger.error(f"Sandbox analysis failed for {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sandbox analysis failed: {str(e)}")

@router.get("/batch")
async def batch_analysis(
    urls: List[str],
    background_tasks: BackgroundTasks,
    sandbox_service: SandboxService = Depends(get_sandbox_service)
):
    """
    Perform batch analysis of multiple URLs
    """
    if len(urls) > 50:  # Limit batch size
        raise HTTPException(status_code=400, detail="Maximum 50 URLs per batch")
    
    # Start batch analysis in background
    batch_id = f"batch_{datetime.utcnow().timestamp()}"
    background_tasks.add_task(process_batch_analysis, batch_id, urls)
    
    return {
        "batch_id": batch_id,
        "status": "processing",
        "url_count": len(urls),
        "estimated_completion": "2-5 minutes"
    }

def calculate_sandbox_risk(sandbox_result: Dict[str, Any]) -> float:
    """Calculate risk score from sandbox analysis"""
    risk_score = 0.0
    
    # Check for suspicious forms
    forms = sandbox_result.get("forms", [])
    for form in forms:
        if any(field in form.get("fields", []) for field in ["password", "ssn", "credit_card"]):
            risk_score += 0.3
    
    # Check for suspicious JavaScript behavior
    js_behavior = sandbox_result.get("javascript", {})
    if js_behavior.get("keylogger_detected"):
        risk_score += 0.4
    if js_behavior.get("obfuscated_code"):
        risk_score += 0.2
    
    # Check for suspicious redirects
    redirects = sandbox_result.get("redirects", [])
    if len(redirects) > 3:
        risk_score += 0.2
    
    # Check for suspicious network requests
    network_requests = sandbox_result.get("network_requests", [])
    suspicious_domains = ["bit.ly", "tinyurl.com", "t.co"]
    for request in network_requests:
        if any(domain in request for domain in suspicious_domains):
            risk_score += 0.1
    
    return min(risk_score, 1.0)

def calculate_network_risk(network_result: Dict[str, Any]) -> float:
    """Calculate risk score from network analysis"""
    risk_score = 0.0
    
    # Check campaign association
    if network_result.get("campaign_detected"):
        risk_score += 0.5
    
    # Check domain clustering
    cluster_risk = network_result.get("cluster_risk_score", 0.0)
    risk_score += cluster_risk * 0.3
    
    # Check IP reputation
    ip_reputation = network_result.get("ip_reputation", {})
    if ip_reputation.get("malicious"):
        risk_score += 0.4
    
    return min(risk_score, 1.0)

def calculate_final_threat_score(threat_intel_score: float, sandbox_risk: float, network_risk: float, ml_confidence: float) -> float:
    """Calculate final threat score combining all analyses"""
    # Weighted combination of all risk factors
    weights = {
        "threat_intel": 0.35,  # High weight for confirmed threat intelligence
        "sandbox": 0.25,
        "network": 0.20,
        "ml": 0.20
    }
    
    final_score = (
        threat_intel_score * weights["threat_intel"] +
        sandbox_risk * weights["sandbox"] +
        network_risk * weights["network"] +
        ml_confidence * weights["ml"]
    )
    
    return min(final_score, 1.0)

def determine_threat_level(score: float) -> str:
    """Determine threat level from score"""
    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.4:
        return "medium"
    else:
        return "low"

async def store_analysis_result(url: str, is_malicious: bool, threat_level: str, confidence: float, details: Dict[str, Any]):
    """Store analysis result in database"""
    # TODO: Implement database storage
    logger.info(f"Storing analysis result for {url}: {threat_level}")

async def update_threat_intelligence(url: str, threat_level: str, details: Dict[str, Any]):
    """Update threat intelligence database"""
    # TODO: Implement threat intelligence update
    logger.info(f"Updating threat intelligence for {url}: {threat_level}")

async def process_batch_analysis(batch_id: str, urls: List[str]):
    """Process batch analysis in background"""
    # TODO: Implement batch processing
    logger.info(f"Processing batch {batch_id} with {len(urls)} URLs")
