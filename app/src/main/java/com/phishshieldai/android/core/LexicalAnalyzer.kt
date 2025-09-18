package com.phishshieldai.android.core

import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import java.net.URL
import java.util.regex.Pattern
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class LexicalAnalyzer @Inject constructor() {
    
    companion object {
        // Common phishing URL patterns
        private val SUSPICIOUS_KEYWORDS = arrayOf(
            "secure", "verify", "update", "suspend", "limited", "expired",
            "confirm", "validate", "urgent", "immediate", "action", "required"
        )
        
        private val SUSPICIOUS_DOMAINS = arrayOf(
            "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl", "short.link"
        )
        
        private val HOMOGRAPH_PATTERNS = mapOf(
            "paypal" to arrayOf("paypa1", "paypaI", "рaypal"),
            "amazon" to arrayOf("amazοn", "am4zon", "аmazon"),
            "google" to arrayOf("goog1e", "goοgle", "gооgle"),
            "microsoft" to arrayOf("microsοft", "micrοsoft", "microsooft")
        )
    }
    
    fun analyzeQuick(url: String): AnalysisResult {
        var suspiciousScore = 0f
        val findings = mutableListOf<String>()
        
        try {
            val urlObj = URL(url)
            val domain = urlObj.host.lowercase()
            val path = urlObj.path.lowercase()
            val query = urlObj.query?.lowercase() ?: ""
            
            // Check for suspicious keywords in domain
            SUSPICIOUS_KEYWORDS.forEach { keyword ->
                if (domain.contains(keyword)) {
                    suspiciousScore += 0.3f
                    findings.add("Suspicious keyword in domain: $keyword")
                }
            }
            
            // Check for URL shorteners
            SUSPICIOUS_DOMAINS.forEach { shortener ->
                if (domain.contains(shortener)) {
                    suspiciousScore += 0.5f
                    findings.add("URL shortener detected: $shortener")
                }
            }
            
            // Check for excessive subdomains
            val subdomains = domain.split(".")
            if (subdomains.size > 4) {
                suspiciousScore += 0.4f
                findings.add("Excessive subdomains: ${subdomains.size}")
            }
            
            // Check for homograph attacks
            checkHomographAttacks(domain)?.let { attack ->
                suspiciousScore += 0.8f
                findings.add("Homograph attack detected: $attack")
            }
            
        } catch (e: Exception) {
            suspiciousScore += 0.2f
            findings.add("Malformed URL")
        }
        
        val threatLevel = when {
            suspiciousScore >= 0.8f -> ThreatLevel.HIGH
            suspiciousScore >= 0.4f -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            threatLevel = threatLevel,
            confidence = minOf(suspiciousScore, 1.0f),
            details = findings.joinToString("; ")
        )
    }
    
    fun analyzeFull(url: String): AnalysisResult {
        var suspiciousScore = 0f
        val findings = mutableListOf<String>()
        
        // Start with quick analysis
        val quickResult = analyzeQuick(url)
        suspiciousScore += quickResult.confidence
        findings.addAll(quickResult.details.split("; ").filter { it.isNotEmpty() })
        
        try {
            val urlObj = URL(url)
            val domain = urlObj.host.lowercase()
            val path = urlObj.path.lowercase()
            val query = urlObj.query?.lowercase() ?: ""
            
            // Advanced lexical checks
            
            // Check for suspicious characters
            if (domain.contains("-") && domain.count { it == '-' } > 2) {
                suspiciousScore += 0.2f
                findings.add("Excessive hyphens in domain")
            }
            
            // Check for mixed scripts (potential IDN homograph)
            if (containsMixedScripts(domain)) {
                suspiciousScore += 0.7f
                findings.add("Mixed character scripts detected")
            }
            
            // Check path for suspicious patterns
            if (path.contains("login") || path.contains("signin") || path.contains("account")) {
                suspiciousScore += 0.3f
                findings.add("Login-related path detected")
            }
            
            // Check for data collection parameters
            if (query.contains("email") || query.contains("password") || query.contains("ssn")) {
                suspiciousScore += 0.5f
                findings.add("Sensitive parameter collection detected")
            }
            
            // Check domain entropy (randomness)
            val domainEntropy = calculateEntropy(domain.replace(".", ""))
            if (domainEntropy > 4.0) {
                suspiciousScore += 0.3f
                findings.add("High domain entropy: ${"%.2f".format(domainEntropy)}")
            }
            
        } catch (e: Exception) {
            suspiciousScore += 0.1f
            findings.add("Analysis error: ${e.message}")
        }
        
        val threatLevel = when {
            suspiciousScore >= 0.8f -> ThreatLevel.HIGH
            suspiciousScore >= 0.5f -> ThreatLevel.MEDIUM
            else -> ThreatLevel.LOW
        }
        
        return AnalysisResult(
            threatLevel = threatLevel,
            confidence = minOf(suspiciousScore, 1.0f),
            details = findings.joinToString("; ")
        )
    }
    
    private fun checkHomographAttacks(domain: String): String? {
        HOMOGRAPH_PATTERNS.forEach { (legitimate, variants) ->
            variants.forEach { variant ->
                if (domain.contains(variant)) {
                    return "$variant (mimics $legitimate)"
                }
            }
        }
        return null
    }
    
    private fun containsMixedScripts(text: String): Boolean {
        val scripts = mutableSetOf<Character.UnicodeScript>()
        text.forEach { char ->
            val script = Character.UnicodeScript.of(char.code)
            if (script != Character.UnicodeScript.COMMON && script != Character.UnicodeScript.INHERITED) {
                scripts.add(script)
            }
        }
        return scripts.size > 1
    }
    
    private fun calculateEntropy(text: String): Double {
        val frequencies = text.groupingBy { it }.eachCount()
        val length = text.length.toDouble()
        
        return frequencies.values.sumOf { count ->
            val probability = count / length
            -probability * (kotlin.math.ln(probability) / kotlin.math.ln(2.0))
        }
    }
}
