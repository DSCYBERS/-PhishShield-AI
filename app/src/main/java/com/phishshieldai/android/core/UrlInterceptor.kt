package com.phishshieldai.android.core

import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import kotlinx.coroutines.*
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class UrlInterceptor @Inject constructor(
    private val detectionEngine: PhishingDetectionEngine,
    private val reputationChecker: ReputationChecker
) {
    
    companion object {
        private const val TAG = "UrlInterceptor"
        private const val CACHE_EXPIRY_MS = 5 * 60 * 1000L // 5 minutes
    }
    
    private val urlCache = ConcurrentHashMap<String, CachedResult>()
    private val interceptorScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    data class CachedResult(
        val result: AnalysisResult,
        val timestamp: Long,
        val blocked: Boolean
    )
    
    /**
     * Intercept and analyze URL for threats
     * @param url The URL to intercept and analyze
     * @param sourceApp The app that initiated the request
     * @return true if URL should be blocked, false if safe to proceed
     */
    fun interceptUrl(url: String, sourceApp: String): Boolean {
        return try {
            Log.d(TAG, "Intercepting URL: $url from app: $sourceApp")
            
            // Normalize URL
            val normalizedUrl = normalizeUrl(url)
            
            // Check cache first
            getCachedResult(normalizedUrl)?.let { cachedResult ->
                Log.d(TAG, "Using cached result for $normalizedUrl: blocked=${cachedResult.blocked}")
                return cachedResult.blocked
            }
            
            // Perform quick analysis for immediate blocking decision
            val quickAnalysis = performQuickAnalysis(normalizedUrl, sourceApp)
            val shouldBlock = shouldBlockUrl(quickAnalysis)
            
            // Cache result
            cacheResult(normalizedUrl, quickAnalysis, shouldBlock)
            
            // Trigger background full analysis for learning
            triggerBackgroundAnalysis(normalizedUrl, sourceApp)
            
            Log.d(TAG, "URL interception result for $normalizedUrl: blocked=$shouldBlock")
            shouldBlock
            
        } catch (e: Exception) {
            Log.e(TAG, "Error intercepting URL: $url", e)
            // Fail safe - allow URL but log for investigation
            false
        }
    }
    
    /**
     * Perform asynchronous full analysis without blocking
     */
    suspend fun interceptUrlAsync(url: String, sourceApp: String): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Async intercepting URL: $url from app: $sourceApp")
            
            val normalizedUrl = normalizeUrl(url)
            
            // Check cache
            getCachedResult(normalizedUrl)?.let { cachedResult ->
                return@withContext cachedResult.blocked
            }
            
            // Perform full analysis
            val fullAnalysis = detectionEngine.analyzeUrlComplete(normalizedUrl)
            val shouldBlock = shouldBlockUrl(fullAnalysis)
            
            // Cache result
            cacheResult(normalizedUrl, fullAnalysis, shouldBlock)
            
            Log.d(TAG, "Async URL interception result for $normalizedUrl: blocked=$shouldBlock")
            shouldBlock
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in async URL interception: $url", e)
            false
        }
    }
    
    private fun normalizeUrl(url: String): String {
        return try {
            val urlObj = URL(url.lowercase().trim())
            "${urlObj.protocol}://${urlObj.host}${urlObj.path}${if (urlObj.query != null) "?${urlObj.query}" else ""}"
        } catch (e: Exception) {
            url.lowercase().trim()
        }
    }
    
    private fun getCachedResult(url: String): CachedResult? {
        val cached = urlCache[url]
        return if (cached != null && (System.currentTimeMillis() - cached.timestamp) < CACHE_EXPIRY_MS) {
            cached
        } else {
            // Remove expired cache entry
            urlCache.remove(url)
            null
        }
    }
    
    private fun performQuickAnalysis(url: String, sourceApp: String): AnalysisResult {
        // Quick lexical analysis for immediate decisions
        val lexicalResult = LexicalAnalyzer().analyzeQuick(url)
        
        // Quick reputation check
        val domain = extractDomain(url)
        val reputationResult = reputationChecker.checkCached(domain)
        
        // Combine results with weighted scoring
        val combinedThreatLevel = when {
            lexicalResult.threatLevel == ThreatLevel.CRITICAL || reputationResult.threatLevel == ThreatLevel.CRITICAL -> ThreatLevel.CRITICAL
            lexicalResult.threatLevel == ThreatLevel.HIGH || reputationResult.threatLevel == ThreatLevel.HIGH -> ThreatLevel.HIGH
            lexicalResult.threatLevel == ThreatLevel.MEDIUM || reputationResult.threatLevel == ThreatLevel.MEDIUM -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        val combinedConfidence = (lexicalResult.confidence + reputationResult.confidence) / 2
        val combinedDetails = "${lexicalResult.details}; ${reputationResult.details}"
        
        return AnalysisResult(
            threatLevel = combinedThreatLevel,
            confidence = combinedConfidence,
            details = combinedDetails
        )
    }
    
    private fun shouldBlockUrl(analysis: AnalysisResult): Boolean {
        return when (analysis.threatLevel) {
            ThreatLevel.CRITICAL -> true
            ThreatLevel.HIGH -> analysis.confidence > 0.7f
            ThreatLevel.MEDIUM -> analysis.confidence > 0.85f
            ThreatLevel.LOW -> false
        }
    }
    
    private fun cacheResult(url: String, analysis: AnalysisResult, blocked: Boolean) {
        urlCache[url] = CachedResult(
            result = analysis,
            timestamp = System.currentTimeMillis(),
            blocked = blocked
        )
        
        // Limit cache size
        if (urlCache.size > 1000) {
            cleanupCache()
        }
    }
    
    private fun cleanupCache() {
        val currentTime = System.currentTimeMillis()
        val iterator = urlCache.entries.iterator()
        
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if ((currentTime - entry.value.timestamp) > CACHE_EXPIRY_MS) {
                iterator.remove()
            }
        }
    }
    
    private fun triggerBackgroundAnalysis(url: String, sourceApp: String) {
        interceptorScope.launch {
            try {
                // Perform full analysis in background for learning and cache warming
                val fullAnalysis = detectionEngine.analyzeUrlComplete(url)
                val shouldBlock = shouldBlockUrl(fullAnalysis)
                
                // Update cache with full analysis result
                cacheResult(url, fullAnalysis, shouldBlock)
                
                Log.d(TAG, "Background analysis completed for $url: ${fullAnalysis.threatLevel}")
                
            } catch (e: Exception) {
                Log.e(TAG, "Background analysis failed for $url", e)
            }
        }
    }
    
    private fun extractDomain(url: String): String {
        return try {
            URL(url).host
        } catch (e: Exception) {
            url
        }
    }
    
    /**
     * Get analysis result for a URL (for UI display)
     */
    suspend fun getUrlAnalysis(url: String): AnalysisResult? {
        val normalizedUrl = normalizeUrl(url)
        return getCachedResult(normalizedUrl)?.result
            ?: detectionEngine.analyzeUrlComplete(normalizedUrl)
    }
    
    /**
     * Clear URL cache
     */
    fun clearCache() {
        urlCache.clear()
        Log.d(TAG, "URL cache cleared")
    }
    
    /**
     * Get cache statistics
     */
    fun getCacheStats(): Map<String, Any> {
        val currentTime = System.currentTimeMillis()
        val validEntries = urlCache.values.count { (currentTime - it.timestamp) < CACHE_EXPIRY_MS }
        val blockedCount = urlCache.values.count { it.blocked && (currentTime - it.timestamp) < CACHE_EXPIRY_MS }
        
        return mapOf(
            "total_entries" to urlCache.size,
            "valid_entries" to validEntries,
            "blocked_urls" to blockedCount,
            "cache_hit_ratio" to if (validEntries > 0) (validEntries.toFloat() / urlCache.size) else 0.0f
        )
    }
}
