package com.phishshieldai.android.core

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import com.phishshieldai.android.network.ApiService
import com.phishshieldai.android.services.ThreatIntelligenceService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReputationChecker @Inject constructor(
    @ApplicationContext private val context: Context,
    private val threatIntelligenceService: ThreatIntelligenceService
) {
    
    companion object {
        private const val TAG = "ReputationChecker"
        private const val PREFS_NAME = "reputation_cache"
        private const val CACHE_EXPIRY_MS = 24 * 60 * 60 * 1000L // 24 hours
        private const val MAX_CACHE_SIZE = 10000
    }
    
    @Serializable
    data class CachedReputation(
        val domain: String,
        val threatLevel: String,
        val confidence: Float,
        val details: String,
        val categories: List<String> = emptyList(),
        val sources: List<String> = emptyList(),
        val timestamp: Long
    )
    
    private val memoryCache = ConcurrentHashMap<String, CachedReputation>()
    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    private val json = Json { ignoreUnknownKeys = true }
    
    // Known malicious domains (basic blacklist)
    private val knownMaliciousDomains = setOf(
        "phishing-example.com",
        "fake-paypal.net",
        "secure-bank-login.suspicious.com",
        "amazon-security-verify.phish.net",
        "microsoft-account-verify.fake.com"
    )
    
    // Known safe domains (basic whitelist)
    private val knownSafeDomains = setOf(
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "microsoft.com", "apple.com", "twitter.com", "instagram.com",
        "linkedin.com", "github.com", "stackoverflow.com", "wikipedia.org",
        "reddit.com", "netflix.com", "paypal.com", "ebay.com"
    )
    
    init {
        loadCacheFromPrefs()
    }
    
    /**
     * Quick reputation check using local cache and basic lists
     */
    fun checkCached(domain: String): AnalysisResult {
        return try {
            Log.d(TAG, "Checking cached reputation for domain: $domain")
            
            val normalizedDomain = normalizeDomain(domain)
            
            // Check memory cache first
            memoryCache[normalizedDomain]?.let { cached ->
                if (isCacheValid(cached)) {
                    Log.d(TAG, "Found valid cached reputation for $normalizedDomain")
                    return cached.toAnalysisResult()
                } else {
                    // Remove expired cache
                    memoryCache.remove(normalizedDomain)
                }
            }
            
            // Check basic blacklist/whitelist
            val basicCheck = performBasicReputationCheck(normalizedDomain)
            
            // Cache the basic result
            cacheReputation(normalizedDomain, basicCheck)
            
            basicCheck
            
        } catch (e: Exception) {
            Log.e(TAG, "Error checking cached reputation for $domain", e)
            AnalysisResult(
                threatLevel = ThreatLevel.MEDIUM,
                confidence = 0.5f,
                details = "Reputation check error: ${e.message}"
            )
        }
    }
    
    /**
     * Full reputation check including cloud lookup
     */
    suspend fun checkFull(domain: String): AnalysisResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Performing full reputation check for domain: $domain")
            
            val normalizedDomain = normalizeDomain(domain)
            
            // Check cache first
            memoryCache[normalizedDomain]?.let { cached ->
                if (isCacheValid(cached)) {
                    Log.d(TAG, "Using cached full reputation for $normalizedDomain")
                    return@withContext cached.toAnalysisResult()
                }
            }
            
            // Perform cloud-based reputation check
            val cloudResult = performCloudReputationCheck(normalizedDomain)
            
            // Cache the result
            cacheReputation(normalizedDomain, cloudResult)
            
            Log.d(TAG, "Full reputation check completed for $normalizedDomain: ${cloudResult.threatLevel}")
            cloudResult
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in full reputation check for $domain", e)
            // Fallback to cached/basic check
            checkCached(domain)
        }
    }
    
    private fun normalizeDomain(domain: String): String {
        return domain.lowercase()
            .removePrefix("www.")
            .removePrefix("http://")
            .removePrefix("https://")
            .split("/")[0]
            .split("?")[0]
            .trim()
    }
    
    private fun performBasicReputationCheck(domain: String): AnalysisResult {
        return when {
            isKnownMalicious(domain) -> AnalysisResult(
                threatLevel = ThreatLevel.CRITICAL,
                confidence = 0.95f,
                details = "Domain found in known malicious list"
            )
            
            isKnownSafe(domain) -> AnalysisResult(
                threatLevel = ThreatLevel.LOW,
                confidence = 0.98f,
                details = "Domain found in known safe list"
            )
            
            isSuspiciousDomain(domain) -> AnalysisResult(
                threatLevel = ThreatLevel.HIGH,
                confidence = 0.8f,
                details = "Domain has suspicious characteristics"
            )
            
            else -> AnalysisResult(
                threatLevel = ThreatLevel.MEDIUM,
                confidence = 0.5f,
                details = "Unknown domain - neutral reputation"
            )
        }
    }
    
    private suspend fun performCloudReputationCheck(domain: String): AnalysisResult {
        return try {
            // Use threat intelligence service for cloud lookup
            val threatResult = threatIntelligenceService.checkDomainReputation(domain)
            
            Log.d(TAG, "Cloud reputation check result for $domain: ${threatResult.threatLevel}")
            threatResult
            
        } catch (e: Exception) {
            Log.w(TAG, "Cloud reputation check failed for $domain, using fallback", e)
            // Fallback to basic check
            performBasicReputationCheck(domain)
        }
    }
    
    private fun isKnownMalicious(domain: String): Boolean {
        return knownMaliciousDomains.any { malicious ->
            domain == malicious || domain.endsWith(".$malicious")
        }
    }
    
    private fun isKnownSafe(domain: String): Boolean {
        return knownSafeDomains.any { safe ->
            domain == safe || domain.endsWith(".$safe")
        }
    }
    
    private fun isSuspiciousDomain(domain: String): Boolean {
        val suspiciousPatterns = listOf(
            "phish", "fake", "secure-", "verify-", "account-",
            "login-", "bank-", "paypal-", "amazon-", "microsoft-",
            "apple-", "google-", "facebook-", "twitter-"
        )
        
        return suspiciousPatterns.any { pattern ->
            domain.contains(pattern, ignoreCase = true)
        } || domain.count { it == '-' } > 3 // Too many hyphens
            || domain.length > 50 // Unusually long domain
            || domain.matches(Regex(".*\\d{4,}.*")) // Contains 4+ consecutive digits
    }
    
    private fun cacheReputation(domain: String, result: AnalysisResult) {
        val cached = CachedReputation(
            domain = domain,
            threatLevel = result.threatLevel.name,
            confidence = result.confidence,
            details = result.details,
            timestamp = System.currentTimeMillis()
        )
        
        // Add to memory cache
        memoryCache[domain] = cached
        
        // Persist to shared preferences (async)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val jsonString = json.encodeToString(cached)
                prefs.edit().putString(domain, jsonString).apply()
                
                // Cleanup old cache entries
                cleanupCache()
                
            } catch (e: Exception) {
                Log.e(TAG, "Error caching reputation for $domain", e)
            }
        }
    }
    
    private fun isCacheValid(cached: CachedReputation): Boolean {
        return (System.currentTimeMillis() - cached.timestamp) < CACHE_EXPIRY_MS
    }
    
    private fun loadCacheFromPrefs() {
        try {
            val allEntries = prefs.all
            for ((domain, jsonString) in allEntries) {
                try {
                    if (jsonString is String) {
                        val cached = json.decodeFromString<CachedReputation>(jsonString)
                        if (isCacheValid(cached)) {
                            memoryCache[domain] = cached
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error loading cached reputation for $domain", e)
                    // Remove corrupted entry
                    prefs.edit().remove(domain).apply()
                }
            }
            
            Log.d(TAG, "Loaded ${memoryCache.size} reputation entries from cache")
            
        } catch (e: Exception) {
            Log.e(TAG, "Error loading reputation cache", e)
        }
    }
    
    private fun cleanupCache() {
        try {
            if (memoryCache.size > MAX_CACHE_SIZE) {
                val currentTime = System.currentTimeMillis()
                val toRemove = mutableListOf<String>()
                
                // Find expired entries
                for ((domain, cached) in memoryCache) {
                    if ((currentTime - cached.timestamp) > CACHE_EXPIRY_MS) {
                        toRemove.add(domain)
                    }
                }
                
                // Remove expired entries
                val editor = prefs.edit()
                for (domain in toRemove) {
                    memoryCache.remove(domain)
                    editor.remove(domain)
                }
                editor.apply()
                
                Log.d(TAG, "Cleaned up ${toRemove.size} expired reputation entries")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error during cache cleanup", e)
        }
    }
    
    private fun CachedReputation.toAnalysisResult(): AnalysisResult {
        val threatLevel = try {
            ThreatLevel.valueOf(this.threatLevel)
        } catch (e: Exception) {
            ThreatLevel.MEDIUM
        }
        
        return AnalysisResult(
            threatLevel = threatLevel,
            confidence = this.confidence,
            details = this.details
        )
    }
    
    /**
     * Add domain to local blacklist
     */
    fun addToBlacklist(domain: String) {
        val normalizedDomain = normalizeDomain(domain)
        val result = AnalysisResult(
            threatLevel = ThreatLevel.CRITICAL,
            confidence = 1.0f,
            details = "Manually added to blacklist"
        )
        cacheReputation(normalizedDomain, result)
        Log.d(TAG, "Added $normalizedDomain to blacklist")
    }
    
    /**
     * Add domain to local whitelist
     */
    fun addToWhitelist(domain: String) {
        val normalizedDomain = normalizeDomain(domain)
        val result = AnalysisResult(
            threatLevel = ThreatLevel.LOW,
            confidence = 1.0f,
            details = "Manually added to whitelist"
        )
        cacheReputation(normalizedDomain, result)
        Log.d(TAG, "Added $normalizedDomain to whitelist")
    }
    
    /**
     * Clear reputation cache
     */
    fun clearCache() {
        memoryCache.clear()
        prefs.edit().clear().apply()
        Log.d(TAG, "Reputation cache cleared")
    }
    
    /**
     * Get cache statistics
     */
    fun getCacheStats(): Map<String, Any> {
        val currentTime = System.currentTimeMillis()
        val validEntries = memoryCache.values.count { isCacheValid(it) }
        val maliciousCount = memoryCache.values.count { 
            it.threatLevel in listOf("HIGH", "CRITICAL") && isCacheValid(it) 
        }
        
        return mapOf(
            "total_entries" to memoryCache.size,
            "valid_entries" to validEntries,
            "malicious_domains" to maliciousCount,
            "cache_size_mb" to (memoryCache.size * 100 / 1024 / 1024) // rough estimate
        )
    }
}
