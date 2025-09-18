package com.phishshieldai.android.services

import android.content.Context
import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatIntelligenceResult
import com.phishshieldai.android.data.model.ThreatLevel
import com.phishshieldai.android.network.ApiService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.Response
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ThreatIntelligenceService @Inject constructor(
    @ApplicationContext private val context: Context,
    private val apiService: ApiService
) {
    
    companion object {
        private const val TAG = "ThreatIntelligenceService"
        private const val CACHE_EXPIRY_MS = 3600000L // 1 hour
    }
    
    private val threatCache = mutableMapOf<String, CachedThreatResult>()
    
    data class CachedThreatResult(
        val result: ThreatIntelligenceResult,
        val timestamp: Long
    )
    
    /**
     * Analyze URL using threat intelligence sources
     */
    suspend fun analyzeThreat(url: String): AnalysisResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Analyzing threat intelligence for: $url")
            
            // Check cache first
            val cachedResult = getCachedResult(url)
            if (cachedResult != null) {
                Log.d(TAG, "Using cached threat intelligence result")
                return@withContext convertToAnalysisResult(cachedResult)
            }
            
            // Query threat intelligence API
            val response = queryThreatIntelligenceAPI(url)
            
            if (response.isSuccessful && response.body() != null) {
                val threatResult = response.body()!!
                
                // Cache the result
                cacheResult(url, threatResult)
                
                Log.d(TAG, "Threat intelligence analysis complete: ${threatResult.reputation}")
                return@withContext convertToAnalysisResult(threatResult)
            } else {
                Log.w(TAG, "Threat intelligence API failed: ${response.code()}")
                return@withContext getFallbackThreatAnalysis(url)
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Threat intelligence analysis failed", e)
            return@withContext getFallbackThreatAnalysis(url)
        }
    }
    
    /**
     * Quick reputation check for domain
     */
    suspend fun checkDomainReputation(domain: String): AnalysisResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Checking domain reputation for: $domain")
            
            val response = apiService.checkDomainReputation(domain)
            
            if (response.isSuccessful && response.body() != null) {
                val reputationData = response.body()!!
                
                val threatLevel = when (reputationData.reputation) {
                    "malicious" -> ThreatLevel.CRITICAL
                    "suspicious" -> ThreatLevel.HIGH
                    "questionable" -> ThreatLevel.MEDIUM
                    else -> ThreatLevel.LOW
                }
                
                return@withContext AnalysisResult(
                    isMalicious = reputationData.is_malicious,
                    threatLevel = threatLevel,
                    confidence = reputationData.threat_score,
                    details = mapOf(
                        "reputation" to reputationData.reputation,
                        "quick_summary" to reputationData.quick_summary
                    )
                )
            } else {
                Log.w(TAG, "Domain reputation check failed: ${response.code()}")
                return@withContext AnalysisResult(
                    isMalicious = false,
                    threatLevel = ThreatLevel.LOW,
                    confidence = 0.0f,
                    details = mapOf("error" to "API unavailable")
                )
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Domain reputation check failed", e)
            return@withContext AnalysisResult(
                isMalicious = false,
                threatLevel = ThreatLevel.LOW,
                confidence = 0.0f,
                details = mapOf("error" to e.message.orEmpty())
            )
        }
    }
    
    /**
     * Report a threat to the threat intelligence system
     */
    suspend fun reportThreat(
        url: String,
        threatType: String,
        confidence: Float,
        description: String? = null
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Reporting threat: $url")
            
            val reportRequest = ThreatReportRequest(
                url = url,
                threat_type = threatType,
                confidence = confidence,
                source = "PhishShield_Android",
                description = description
            )
            
            val response = apiService.reportThreat(reportRequest)
            
            if (response.isSuccessful) {
                Log.d(TAG, "Threat reported successfully")
                // Invalidate cache for this URL
                invalidateCache(url)
                return@withContext true
            } else {
                Log.w(TAG, "Threat reporting failed: ${response.code()}")
                return@withContext false
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Threat reporting failed", e)
            return@withContext false
        }
    }
    
    /**
     * Get threat feeds status
     */
    suspend fun getThreatFeedsStatus(): Map<String, Any> = withContext(Dispatchers.IO) {
        try {
            val response = apiService.getThreatFeedsStatus()
            
            if (response.isSuccessful && response.body() != null) {
                val status = response.body()!!
                return@withContext mapOf(
                    "total_configured" to status.total_configured,
                    "active_feeds" to status.active_feeds,
                    "last_updated" to status.last_updated,
                    "feeds" to status.feeds
                )
            } else {
                return@withContext mapOf("error" to "API unavailable")
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get threat feeds status", e)
            return@withContext mapOf("error" to e.message.orEmpty())
        }
    }
    
    private suspend fun queryThreatIntelligenceAPI(url: String): Response<ThreatIntelligenceResult> {
        return apiService.analyzeThreatIntelligence(url)
    }
    
    private fun convertToAnalysisResult(threatResult: ThreatIntelligenceResult): AnalysisResult {
        val threatLevel = when (threatResult.reputation) {
            "malicious" -> ThreatLevel.CRITICAL
            "suspicious" -> ThreatLevel.HIGH
            "questionable" -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            isMalicious = threatResult.is_malicious,
            threatLevel = threatLevel,
            confidence = threatResult.threat_score,
            details = mapOf(
                "reputation" to threatResult.reputation,
                "threat_sources" to threatResult.threat_sources,
                "categories" to threatResult.categories,
                "detailed_results" to threatResult.detailed_results
            )
        )
    }
    
    private fun getCachedResult(url: String): ThreatIntelligenceResult? {
        val cached = threatCache[url]
        if (cached != null) {
            val age = System.currentTimeMillis() - cached.timestamp
            if (age < CACHE_EXPIRY_MS) {
                return cached.result
            } else {
                // Remove expired cache
                threatCache.remove(url)
            }
        }
        return null
    }
    
    private fun cacheResult(url: String, result: ThreatIntelligenceResult) {
        threatCache[url] = CachedThreatResult(result, System.currentTimeMillis())
        
        // Clean old cache entries (keep only last 100)
        if (threatCache.size > 100) {
            val oldestEntry = threatCache.minByOrNull { it.value.timestamp }
            oldestEntry?.let { threatCache.remove(it.key) }
        }
    }
    
    private fun invalidateCache(url: String) {
        threatCache.remove(url)
    }
    
    private fun getFallbackThreatAnalysis(url: String): AnalysisResult {
        // Basic heuristic analysis when threat intelligence is unavailable
        val domain = try {
            URL(url).host.lowercase()
        } catch (e: Exception) {
            url.lowercase()
        }
        
        var suspiciousScore = 0.0f
        val details = mutableMapOf<String, Any>()
        
        // Check for suspicious patterns
        if (domain.contains("bit.ly") || domain.contains("tinyurl") || domain.contains("t.co")) {
            suspiciousScore += 0.3f
            details["url_shortener"] = true
        }
        
        if (domain.matches(Regex(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*"))) {
            suspiciousScore += 0.4f
            details["ip_address_domain"] = true
        }
        
        if (domain.count { it == '-' } > 3) {
            suspiciousScore += 0.2f
            details["excessive_hyphens"] = true
        }
        
        if (domain.length > 50) {
            suspiciousScore += 0.2f
            details["long_domain"] = true
        }
        
        details["fallback_analysis"] = true
        details["threat_intel_unavailable"] = true
        
        val threatLevel = when {
            suspiciousScore >= 0.7f -> ThreatLevel.HIGH
            suspiciousScore >= 0.4f -> ThreatLevel.MEDIUM
            suspiciousScore >= 0.2f -> ThreatLevel.LOW
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            isMalicious = suspiciousScore >= 0.5f,
            threatLevel = threatLevel,
            confidence = suspiciousScore,
            details = details
        )
    }
    
    // Data classes for API communication
    data class ThreatReportRequest(
        val url: String,
        val threat_type: String,
        val confidence: Float,
        val source: String,
        val description: String? = null
    )
}
