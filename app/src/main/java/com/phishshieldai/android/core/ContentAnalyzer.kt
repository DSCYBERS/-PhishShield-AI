package com.phishshieldai.android.core

import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.util.regex.Pattern
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ContentAnalyzer @Inject constructor() {
    
    companion object {
        private const val TAG = "ContentAnalyzer"
        
        // Suspicious form patterns
        private val FORM_PATTERNS = listOf(
            Pattern.compile("password", Pattern.CASE_INSENSITIVE),
            Pattern.compile("credit.?card", Pattern.CASE_INSENSITIVE),
            Pattern.compile("social.?security", Pattern.CASE_INSENSITIVE),
            Pattern.compile("bank.?account", Pattern.CASE_INSENSITIVE),
            Pattern.compile("pin.?code", Pattern.CASE_INSENSITIVE)
        )
        
        // Phishing keywords
        private val PHISHING_KEYWORDS = listOf(
            "verify", "suspend", "urgent", "immediate", "expire", "update",
            "confirm", "secure", "validate", "restricted", "limited",
            "click here", "act now", "winner", "congratulations"
        )
        
        // Legitimate domain indicators
        private val LEGITIMATE_INDICATORS = listOf(
            "https://", "ssl", "secure", "official", "verified"
        )
    }
    
    suspend fun analyzeStatic(url: String): AnalysisResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Analyzing static content for: $url")
            
            var riskScore = 0.0f
            val riskFactors = mutableListOf<String>()
            
            // Parse URL components
            val parsedUrl = URL(url)
            val domain = parsedUrl.host?.lowercase() ?: ""
            val path = parsedUrl.path?.lowercase() ?: ""
            val query = parsedUrl.query?.lowercase() ?: ""
            val fullUrl = url.lowercase()
            
            // 1. SSL/HTTPS Analysis
            if (!url.startsWith("https://")) {
                riskScore += 0.3f
                riskFactors.add("Non-HTTPS connection")
            }
            
            // 2. Domain Analysis
            if (isIPAddress(domain)) {
                riskScore += 0.4f
                riskFactors.add("IP address instead of domain")
            }
            
            if (hasSuspiciousTLD(domain)) {
                riskScore += 0.2f
                riskFactors.add("Suspicious top-level domain")
            }
            
            // 3. URL Structure Analysis
            if (hasExcessiveSubdomains(domain)) {
                riskScore += 0.2f
                riskFactors.add("Excessive subdomains")
            }
            
            if (hasObfuscatedDomain(domain)) {
                riskScore += 0.3f
                riskFactors.add("Obfuscated domain name")
            }
            
            // 4. Path Analysis
            val pathRisk = analyzeUrlPath(path)
            riskScore += pathRisk
            if (pathRisk > 0.1f) {
                riskFactors.add("Suspicious URL path structure")
            }
            
            // 5. Query Parameter Analysis
            val queryRisk = analyzeQueryParameters(query)
            riskScore += queryRisk
            if (queryRisk > 0.1f) {
                riskFactors.add("Suspicious query parameters")
            }
            
            // 6. Phishing Keyword Detection
            val keywordRisk = detectPhishingKeywords(fullUrl)
            riskScore += keywordRisk
            if (keywordRisk > 0.1f) {
                riskFactors.add("Phishing keywords detected")
            }
            
            // 7. Form Analysis (simulated - would require actual content)
            val formRisk = simulateFormAnalysis(fullUrl)
            riskScore += formRisk
            if (formRisk > 0.1f) {
                riskFactors.add("Suspicious form patterns")
            }
            
            // 8. Brand Impersonation Check
            val brandRisk = checkBrandImpersonation(domain, fullUrl)
            riskScore += brandRisk
            if (brandRisk > 0.1f) {
                riskFactors.add("Potential brand impersonation")
            }
            
            // Normalize risk score
            riskScore = minOf(riskScore, 1.0f)
            
            // Determine threat level
            val threatLevel = when {
                riskScore >= 0.7f -> ThreatLevel.HIGH
                riskScore >= 0.4f -> ThreatLevel.MEDIUM
                riskScore >= 0.2f -> ThreatLevel.LOW
                else -> ThreatLevel.LOW
            }
            
            Log.d(TAG, "Static analysis complete. Risk score: $riskScore, Factors: $riskFactors")
            
            AnalysisResult(
                isMalicious = riskScore >= 0.5f,
                threatLevel = threatLevel,
                confidence = riskScore,
                details = mapOf(
                    "risk_factors" to riskFactors,
                    "analysis_type" to "static_content",
                    "ssl_secure" to url.startsWith("https://"),
                    "domain_type" to if (isIPAddress(domain)) "ip" else "domain"
                )
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in static content analysis", e)
            AnalysisResult(
                isMalicious = false,
                threatLevel = ThreatLevel.UNKNOWN,
                confidence = 0.0f,
                details = mapOf("error" to e.message)
            )
        }
    }
    
    private fun isIPAddress(domain: String): Boolean {
        return domain.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))
    }
    
    private fun hasSuspiciousTLD(domain: String): Boolean {
        val suspiciousTLDs = listOf(".tk", ".ml", ".ga", ".cf", ".icu", ".top", ".click", ".download")
        return suspiciousTLDs.any { domain.endsWith(it) }
    }
    
    private fun hasExcessiveSubdomains(domain: String): Boolean {
        val parts = domain.split(".")
        return parts.size > 4 // More than 3 dots suggests excessive subdomains
    }
    
    private fun hasObfuscatedDomain(domain: String): Boolean {
        // Check for homograph attacks, excessive hyphens, mixed scripts
        val excessiveHyphens = domain.count { it == '-' } > 3
        val hasNumbers = domain.any { it.isDigit() }
        val suspiciousLength = domain.length > 50
        
        return excessiveHyphens || (hasNumbers && suspiciousLength)
    }
    
    private fun analyzeUrlPath(path: String): Float {
        var risk = 0.0f
        
        // Excessive path depth
        val pathDepth = path.count { it == '/' }
        if (pathDepth > 5) risk += 0.1f
        
        // Suspicious path patterns
        val suspiciousPatterns = listOf("secure", "verify", "update", "login", "signin")
        if (suspiciousPatterns.any { path.contains(it) }) risk += 0.1f
        
        // File extensions that shouldn't be in URLs
        val suspiciousExtensions = listOf(".exe", ".zip", ".rar", ".bat", ".scr")
        if (suspiciousExtensions.any { path.endsWith(it) }) risk += 0.3f
        
        return risk
    }
    
    private fun analyzeQueryParameters(query: String): Float {
        var risk = 0.0f
        
        if (query.isBlank()) return 0.0f
        
        // Excessive parameters
        val paramCount = query.split("&").size
        if (paramCount > 10) risk += 0.1f
        
        // Suspicious parameter names
        val suspiciousParams = listOf("redirect", "goto", "url", "link", "continue", "target")
        if (suspiciousParams.any { query.contains(it) }) risk += 0.2f
        
        // URL encoding (potential obfuscation)
        val encodedChars = query.count { it == '%' }
        if (encodedChars > 5) risk += 0.1f
        
        return risk
    }
    
    private fun detectPhishingKeywords(url: String): Float {
        var risk = 0.0f
        val lowerUrl = url.lowercase()
        
        var keywordCount = 0
        PHISHING_KEYWORDS.forEach { keyword ->
            if (lowerUrl.contains(keyword)) {
                keywordCount++
            }
        }
        
        // More keywords = higher risk
        risk = when (keywordCount) {
            0 -> 0.0f
            1 -> 0.1f
            2 -> 0.2f
            else -> 0.3f
        }
        
        return risk
    }
    
    private fun simulateFormAnalysis(url: String): Float {
        // In a real implementation, this would analyze actual page content
        // For now, simulate based on URL patterns
        var risk = 0.0f
        
        val loginPatterns = listOf("login", "signin", "auth", "account")
        if (loginPatterns.any { url.contains(it, ignoreCase = true) }) {
            risk += 0.1f
        }
        
        val paymentPatterns = listOf("payment", "billing", "checkout", "pay")
        if (paymentPatterns.any { url.contains(it, ignoreCase = true) }) {
            risk += 0.2f
        }
        
        return risk
    }
    
    private fun checkBrandImpersonation(domain: String, fullUrl: String): Float {
        var risk = 0.0f
        
        val popularBrands = listOf(
            "paypal", "amazon", "google", "microsoft", "apple", "facebook",
            "twitter", "instagram", "linkedin", "netflix", "spotify", "github"
        )
        
        popularBrands.forEach { brand ->
            if (domain.contains(brand) && !isLegitimateServiceDomain(domain, brand)) {
                risk += 0.3f
            }
        }
        
        return minOf(risk, 0.5f)
    }
    
    private fun isLegitimateServiceDomain(domain: String, brand: String): Boolean {
        // Check if it's actually the legitimate domain
        val legitimateDomains = mapOf(
            "paypal" to listOf("paypal.com", "paypalobjects.com"),
            "amazon" to listOf("amazon.com", "amazonaws.com", "awsstatic.com"),
            "google" to listOf("google.com", "googleapis.com", "googleusercontent.com"),
            "microsoft" to listOf("microsoft.com", "microsoftonline.com", "live.com"),
            "apple" to listOf("apple.com", "icloud.com", "me.com"),
            "facebook" to listOf("facebook.com", "fbcdn.net", "instagram.com")
        )
        
        val legitDomains = legitimateDomains[brand] ?: return false
        return legitDomains.any { domain.endsWith(it) }
    }
}
