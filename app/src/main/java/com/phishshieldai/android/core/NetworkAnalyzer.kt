package com.phishshieldai.android.core

import android.util.Log
import com.phishshieldai.android.data.model.AnalysisResult
import com.phishshieldai.android.data.model.ThreatLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NetworkAnalyzer @Inject constructor() {
    
    companion object {
        private const val TAG = "NetworkAnalyzer"
        
        // Known malicious IP ranges (simplified)
        private val SUSPICIOUS_IP_RANGES = listOf(
            "10.0.0.0/8",     // Private networks being used publicly
            "172.16.0.0/12",  // Private networks
            "192.168.0.0/16", // Private networks
            "127.0.0.0/8",    // Localhost
            "169.254.0.0/16"  // Link-local
        )
        
        // Known malicious ASNs or hosting providers
        private val SUSPICIOUS_HOSTING = listOf(
            "bulletproof", "offshore", "anonymous", "privacy"
        )
    }
    
    suspend fun analyzeNetwork(url: String): AnalysisResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Analyzing network characteristics for: $url")
            
            var riskScore = 0.0f
            val riskFactors = mutableListOf<String>()
            
            val parsedUrl = URL(url)
            val domain = parsedUrl.host
            
            if (domain == null) {
                return@withContext AnalysisResult(
                    isMalicious = false,
                    threatLevel = ThreatLevel.UNKNOWN,
                    confidence = 0.0f,
                    details = mapOf("error" to "Invalid domain")
                )
            }
            
            // 1. DNS Resolution Analysis
            val ipAddresses = resolveDomainToIPs(domain)
            val ipAnalysis = analyzeIPAddresses(ipAddresses)
            riskScore += ipAnalysis.first
            riskFactors.addAll(ipAnalysis.second)
            
            // 2. Port Analysis
            val portAnalysis = analyzePort(parsedUrl.port, parsedUrl.protocol)
            riskScore += portAnalysis.first
            if (portAnalysis.second.isNotEmpty()) {
                riskFactors.addAll(portAnalysis.second)
            }
            
            // 3. Geolocation Analysis
            val geoAnalysis = analyzeGeolocation(ipAddresses)
            riskScore += geoAnalysis.first
            riskFactors.addAll(geoAnalysis.second)
            
            // 4. Domain Age and Registration Analysis
            val domainAnalysis = analyzeDomainCharacteristics(domain)
            riskScore += domainAnalysis.first
            riskFactors.addAll(domainAnalysis.second)
            
            // 5. Network Infrastructure Analysis
            val infraAnalysis = analyzeNetworkInfrastructure(domain)
            riskScore += infraAnalysis.first
            riskFactors.addAll(infraAnalysis.second)
            
            // Normalize risk score
            riskScore = minOf(riskScore, 1.0f)
            
            // Determine threat level
            val threatLevel = when {
                riskScore >= 0.7f -> ThreatLevel.HIGH
                riskScore >= 0.4f -> ThreatLevel.MEDIUM
                riskScore >= 0.2f -> ThreatLevel.LOW
                else -> ThreatLevel.LOW
            }
            
            Log.d(TAG, "Network analysis complete. Risk score: $riskScore, Factors: $riskFactors")
            
            AnalysisResult(
                isMalicious = riskScore >= 0.5f,
                threatLevel = threatLevel,
                confidence = riskScore,
                details = mapOf(
                    "risk_factors" to riskFactors,
                    "analysis_type" to "network_infrastructure",
                    "ip_addresses" to ipAddresses,
                    "domain" to domain
                )
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in network analysis", e)
            AnalysisResult(
                isMalicious = false,
                threatLevel = ThreatLevel.UNKNOWN,
                confidence = 0.0f,
                details = mapOf("error" to e.message)
            )
        }
    }
    
    private suspend fun resolveDomainToIPs(domain: String): List<String> {
        return try {
            val addresses = InetAddress.getAllByName(domain)
            addresses.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to resolve domain: $domain", e)
            emptyList()
        }
    }
    
    private fun analyzeIPAddresses(ipAddresses: List<String>): Pair<Float, List<String>> {
        var risk = 0.0f
        val factors = mutableListOf<String>()
        
        if (ipAddresses.isEmpty()) {
            risk += 0.2f
            factors.add("Domain resolution failed")
            return Pair(risk, factors)
        }
        
        ipAddresses.forEach { ip ->
            // Check for private IP addresses used publicly
            if (isPrivateIPAddress(ip)) {
                risk += 0.4f
                factors.add("Private IP address: $ip")
            }
            
            // Check for localhost/loopback
            if (ip.startsWith("127.")) {
                risk += 0.5f
                factors.add("Localhost IP address: $ip")
            }
            
            // Check for suspicious IP patterns
            if (isSuspiciousIPPattern(ip)) {
                risk += 0.2f
                factors.add("Suspicious IP pattern: $ip")
            }
        }
        
        // Multiple IPs can be suspicious for simple domains
        if (ipAddresses.size > 5) {
            risk += 0.1f
            factors.add("Excessive IP addresses (${ipAddresses.size})")
        }
        
        return Pair(risk, factors)
    }
    
    private fun analyzePort(port: Int, protocol: String): Pair<Float, List<String>> {
        var risk = 0.0f
        val factors = mutableListOf<String>()
        
        when {
            port == -1 -> {
                // Default port, check protocol
                if (protocol == "http") {
                    risk += 0.2f
                    factors.add("Non-encrypted HTTP connection")
                }
            }
            port !in listOf(80, 443, 8080, 8443) -> {
                // Non-standard port
                risk += 0.3f
                factors.add("Non-standard port: $port")
            }
        }
        
        return Pair(risk, factors)
    }
    
    private fun analyzeGeolocation(ipAddresses: List<String>): Pair<Float, List<String>> {
        var risk = 0.0f
        val factors = mutableListOf<String>()
        
        // Simplified geolocation analysis
        // In a real implementation, you'd use a geolocation service
        
        ipAddresses.forEach { ip ->
            // Check for known suspicious IP ranges or countries
            // This is a simplified check
            if (isHighRiskIPRange(ip)) {
                risk += 0.2f
                factors.add("High-risk IP range: $ip")
            }
        }
        
        return Pair(risk, factors)
    }
    
    private fun analyzeDomainCharacteristics(domain: String): Pair<Float, List<String>> {
        var risk = 0.0f
        val factors = mutableListOf<String>()
        
        // Domain length analysis
        if (domain.length > 50) {
            risk += 0.1f
            factors.add("Excessively long domain")
        }
        
        // Subdomain analysis
        val parts = domain.split(".")
        if (parts.size > 4) {
            risk += 0.2f
            factors.add("Excessive subdomains")
        }
        
        // Character analysis
        val hyphenCount = domain.count { it == '-' }
        if (hyphenCount > 3) {
            risk += 0.1f
            factors.add("Excessive hyphens in domain")
        }
        
        // Digit analysis
        val digitCount = domain.count { it.isDigit() }
        if (digitCount > domain.length * 0.3) {
            risk += 0.1f
            factors.add("High digit ratio in domain")
        }
        
        return Pair(risk, factors)
    }
    
    private fun analyzeNetworkInfrastructure(domain: String): Pair<Float, List<String>> {
        var risk = 0.0f
        val factors = mutableListOf<String>()
        
        // Simplified infrastructure analysis
        // In a real implementation, you'd check:
        // - WHOIS data
        // - Domain age
        // - Registrar reputation
        // - DNS configuration
        // - SSL certificate details
        
        // Check for dynamic DNS patterns
        if (isDynamicDNS(domain)) {
            risk += 0.3f
            factors.add("Dynamic DNS service detected")
        }
        
        // Check for URL shortener services
        if (isURLShortener(domain)) {
            risk += 0.2f
            factors.add("URL shortener service")
        }
        
        // Check for free hosting patterns
        if (isFreeHosting(domain)) {
            risk += 0.2f
            factors.add("Free hosting service")
        }
        
        return Pair(risk, factors)
    }
    
    private fun isPrivateIPAddress(ip: String): Boolean {
        return ip.startsWith("10.") ||
               ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
               ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
               ip.startsWith("172.2") || ip.startsWith("172.3") ||
               ip.startsWith("192.168.") ||
               ip.startsWith("169.254.")
    }
    
    private fun isSuspiciousIPPattern(ip: String): Boolean {
        val parts = ip.split(".")
        if (parts.size != 4) return false
        
        try {
            val intParts = parts.map { it.toInt() }
            
            // Check for sequential patterns (might indicate generated IPs)
            val isSequential = intParts.zipWithNext().all { (a, b) -> b == a + 1 }
            if (isSequential) return true
            
            // Check for repeated octets
            val uniqueOctets = intParts.toSet().size
            if (uniqueOctets <= 2) return true
            
        } catch (e: NumberFormatException) {
            return true // Invalid IP format
        }
        
        return false
    }
    
    private fun isHighRiskIPRange(ip: String): Boolean {
        // Simplified check for high-risk IP ranges
        // In a real implementation, you'd use threat intelligence feeds
        return SUSPICIOUS_IP_RANGES.any { range ->
            // Simplified CIDR check (just checking prefixes)
            when (range) {
                "10.0.0.0/8" -> ip.startsWith("10.")
                "172.16.0.0/12" -> ip.startsWith("172.1") || ip.startsWith("172.2") || ip.startsWith("172.3")
                "192.168.0.0/16" -> ip.startsWith("192.168.")
                "127.0.0.0/8" -> ip.startsWith("127.")
                "169.254.0.0/16" -> ip.startsWith("169.254.")
                else -> false
            }
        }
    }
    
    private fun isDynamicDNS(domain: String): Boolean {
        val dynamicDNSProviders = listOf(
            "dyndns.org", "no-ip.org", "changeip.com", "ddns.net",
            "duckdns.org", "ngrok.io", "serveo.net"
        )
        return dynamicDNSProviders.any { provider ->
            domain.endsWith(provider)
        }
    }
    
    private fun isURLShortener(domain: String): Boolean {
        val shorteners = listOf(
            "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl",
            "short.link", "tiny.cc", "is.gd", "buff.ly"
        )
        return shorteners.any { shortener ->
            domain.contains(shortener)
        }
    }
    
    private fun isFreeHosting(domain: String): Boolean {
        val freeHostingProviders = listOf(
            "000webhost.com", "freehostia.com", "x10hosting.com",
            "byethost.com", "awardspace.com", "freewebhostingarea.com",
            "github.io", "herokuapp.com", "netlify.app", "vercel.app"
        )
        return freeHostingProviders.any { provider ->
            domain.endsWith(provider)
        }
    }
}
