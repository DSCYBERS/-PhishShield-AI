package com.phishshieldai.android.network

import com.phishshieldai.android.data.model.*
import com.phishshieldai.android.services.ThreatIntelligenceService
import retrofit2.Response
import retrofit2.http.*

/**
 * API service for PhishShield backend communication
 */
interface ApiService {
    
    /**
     * Threat Intelligence Endpoints
     */
    @GET("api/threat-intel/analyze/{url}")
    suspend fun analyzeThreatIntelligence(@Path("url") url: String): Response<ThreatIntelligenceResult>
    
    @GET("api/threat-intel/domain/{domain}")
    suspend fun getDomainIntelligence(@Path("domain") domain: String): Response<ThreatIntelligenceResult>
    
    @GET("api/threat-intel/reputation/{domain}")
    suspend fun checkDomainReputation(@Path("domain") domain: String): Response<DomainReputationResult>
    
    @POST("api/threat-intel/report")
    suspend fun reportThreat(@Body request: ThreatIntelligenceService.ThreatReportRequest): Response<ThreatReportResponse>
    
    @GET("api/threat-intel/feeds/status")
    suspend fun getThreatFeedsStatus(): Response<ThreatFeedsStatus>
    
    @POST("api/threat-intel/feeds/update")
    suspend fun updateThreatFeeds(): Response<Map<String, Any>>
    
    /**
     * URL Analysis Endpoints
     */
    @POST("api/analysis/scan")
    suspend fun analyzeUrl(@Body request: URLAnalysisRequest): Response<URLAnalysisResponse>
    
    @POST("api/analysis/sandbox")
    suspend fun sandboxAnalysis(@Body request: URLAnalysisRequest): Response<SandboxAnalysisResult>
    
    @GET("api/analysis/batch")
    suspend fun batchAnalysis(@Query("urls") urls: List<String>): Response<BatchAnalysisResponse>
    
    /**
     * Health Check
     */
    @GET("api/health")
    suspend fun healthCheck(): Response<HealthResponse>
}

/**
 * Request/Response models for API communication
 */
data class URLAnalysisRequest(
    val url: String,
    val client_id: String? = null,
    val previous_layers: Map<String, Any>? = null,
    val priority: String = "normal"
)

data class URLAnalysisResponse(
    val url: String,
    val is_malicious: Boolean,
    val threat_level: String,
    val confidence: Float,
    val analysis_layers: List<String>,
    val scan_time: Float,
    val details: Map<String, Any>,
    val timestamp: String
)

data class SandboxAnalysisResult(
    val url: String,
    val page_title: String?,
    val final_url: String,
    val redirects: List<String>,
    val forms_detected: List<Map<String, Any>>,
    val javascript_behavior: Map<String, Any>,
    val network_requests: List<String>,
    val screenshots: List<String>,
    val risk_indicators: List<String>,
    val execution_time: Float
)

data class BatchAnalysisResponse(
    val batch_id: String,
    val status: String,
    val url_count: Int,
    val estimated_completion: String
)

data class HealthResponse(
    val status: String,
    val version: String,
    val timestamp: String,
    val services: Map<String, Boolean>
)
