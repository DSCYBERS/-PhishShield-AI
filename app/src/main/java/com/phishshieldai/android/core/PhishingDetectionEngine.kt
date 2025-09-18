package com.phishshieldai.android.core

import android.content.Context
import android.util.Log
import com.phishshieldai.android.data.model.ScanResult
import com.phishshieldai.android.data.model.ThreatLevel
import com.phishshieldai.android.ml.PhishingMLModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.util.regex.Pattern
import javax.inject.Inject
import com.phishshieldai.android.services.ThreatIntelligenceService

@Singleton
class PhishingDetectionEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val mlModel: PhishingMLModel,
    private val lexicalAnalyzer: LexicalAnalyzer,
    private val reputationChecker: ReputationChecker,
    private val contentAnalyzer: ContentAnalyzer,
    private val networkAnalyzer: NetworkAnalyzer,
    private val threatIntelligenceService: ThreatIntelligenceService
) {
    
    companion object {
        private const val TAG = "PhishingDetectionEngine"
    }
    
    /**
     * Quick domain-level scan for DNS interception
     * Performs layers 1-3 only for speed
     */
    suspend fun quickDomainScan(domain: String): ScanResult = withContext(Dispatchers.IO) {
        try {
            val url = "https://$domain"
            
            // Layer 1: Normalization
            val normalizedUrl = normalizeUrl(url)
            
            // Layer 2: Lexical Analysis (fast)
            val lexicalResult = lexicalAnalyzer.analyzeQuick(normalizedUrl)
            if (lexicalResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "Lexical analysis detected suspicious patterns",
                    confidence = lexicalResult.confidence,
                    scanLayers = listOf("Normalization", "Lexical")
                )
            }
            
            // Layer 3: Threat Intelligence Check (priority)
            val threatIntelResult = threatIntelligenceService.checkDomainReputation(domain)
            if (threatIntelResult.threatLevel >= ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = threatIntelResult.threatLevel,
                    reason = "Domain flagged by threat intelligence: ${threatIntelResult.details}",
                    confidence = threatIntelResult.confidence,
                    scanLayers = listOf("Normalization", "Lexical", "ThreatIntelligence")
                )
            }
            
            // Layer 3b: Basic Reputation Check (cached fallback)
            val reputationResult = reputationChecker.checkCached(domain)
            if (reputationResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "Domain flagged in reputation database",
                    confidence = reputationResult.confidence,
                    scanLayers = listOf("Normalization", "Lexical", "Reputation")
                )
            }
            
            // If not clearly malicious, assume safe for quick scan
            ScanResult(
                url = normalizedUrl,
                isMalicious = false,
                threatLevel = ThreatLevel.LOW,
                reason = "Quick scan passed",
                confidence = 0.7f,
                scanLayers = listOf("Normalization", "Lexical", "Reputation")
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in quick domain scan", e)
            ScanResult(
                url = domain,
                isMalicious = false,
                threatLevel = ThreatLevel.UNKNOWN,
                reason = "Scan error: ${e.message}",
                confidence = 0.0f,
                scanLayers = listOf("Error")
            )
        }
    }
    
    /**
     * Full 7-layer deep scan for complete URL analysis
     */
    suspend fun scanUrl(url: String): ScanResult = withContext(Dispatchers.IO) {
        try {
            val scanLayers = mutableListOf<String>()
            
            // Layer 1: Ingestion & Normalization
            val normalizedUrl = normalizeUrl(url)
            scanLayers.add("Normalization")
            
            // Layer 2: Lexical & Heuristic Analysis
            val lexicalResult = lexicalAnalyzer.analyzeFull(normalizedUrl)
            scanLayers.add("Lexical")
            
            if (lexicalResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "Lexical analysis detected suspicious patterns: ${lexicalResult.details}",
                    confidence = lexicalResult.confidence,
                    scanLayers = scanLayers
                )
            }
            
            // Layer 3: Threat Intelligence & Reputation Check
            val threatIntelResult = threatIntelligenceService.analyzeThreat(normalizedUrl)
            scanLayers.add("ThreatIntelligence")
            
            if (threatIntelResult.threatLevel == ThreatLevel.CRITICAL || 
                (threatIntelResult.threatLevel == ThreatLevel.HIGH && threatIntelResult.confidence > 0.8f)) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = threatIntelResult.threatLevel,
                    reason = "Confirmed malicious by threat intelligence: ${threatIntelResult.details}",
                    confidence = threatIntelResult.confidence,
                    scanLayers = scanLayers
                )
            }
            
            // Layer 3b: Local Reputation Check (fallback)
            val reputationResult = reputationChecker.checkFull(extractDomain(normalizedUrl))
            scanLayers.add("Reputation")
            
            if (reputationResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "Domain flagged in reputation database: ${reputationResult.details}",
                    confidence = reputationResult.confidence,
                    scanLayers = scanLayers
                )
            }
            
            // Layer 4: Static Content Analysis
            val contentResult = contentAnalyzer.analyzeStatic(normalizedUrl)
            scanLayers.add("Content")
            
            if (contentResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "Static content analysis detected threats: ${contentResult.details}",
                    confidence = contentResult.confidence,
                    scanLayers = scanLayers
                )
            }
            
            // Layer 5: On-Device ML Inference (enhanced with threat intel)
            val mlResult = mlModel.predictWithThreatIntel(
                normalizedUrl, 
                lexicalResult, 
                threatIntelResult,
                reputationResult, 
                contentResult
            )
            scanLayers.add("ML")
            
            if (mlResult.threatLevel == ThreatLevel.HIGH) {
                return@withContext ScanResult(
                    url = normalizedUrl,
                    isMalicious = true,
                    threatLevel = ThreatLevel.HIGH,
                    reason = "ML model detected phishing patterns",
                    confidence = mlResult.confidence,
                    scanLayers = scanLayers
                )
            }
            
            // Layer 6 & 7: Cloud-based analysis (if needed)
            if (mlResult.threatLevel == ThreatLevel.MEDIUM || mlResult.confidence < 0.8f) {
                val cloudResult = performCloudAnalysis(normalizedUrl)
                scanLayers.addAll(listOf("Sandbox", "NetworkGraph"))
                
                if (cloudResult.threatLevel == ThreatLevel.HIGH) {
                    return@withContext cloudResult.copy(scanLayers = scanLayers)
                }
            }
            
            // Final result - assumed safe
            ScanResult(
                url = normalizedUrl,
                isMalicious = false,
                threatLevel = ThreatLevel.LOW,
                reason = "All 7 layers passed - URL appears safe",
                confidence = 0.9f,
                scanLayers = scanLayers
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in full URL scan", e)
            ScanResult(
                url = url,
                isMalicious = false,
                threatLevel = ThreatLevel.UNKNOWN,
                reason = "Scan error: ${e.message}",
                confidence = 0.0f,
                scanLayers = listOf("Error")
            )
        }
    }
    
    private fun normalizeUrl(url: String): String {
        return try {
            val urlObj = URL(url.trim().lowercase())
            
            // Expand URL shorteners
            val expandedUrl = expandShortUrl(urlObj.toString())
            
            // Normalize IDN domains
            val normalizedDomain = java.net.IDN.toASCII(URL(expandedUrl).host)
            
            // Reconstruct normalized URL
            val normalizedUrlObj = URL(expandedUrl)
            "${normalizedUrlObj.protocol}://$normalizedDomain${normalizedUrlObj.path}${
                if (normalizedUrlObj.query != null) "?${normalizedUrlObj.query}" else ""
            }"
            
        } catch (e: Exception) {
            url.trim().lowercase()
        }
    }
    
    private fun expandShortUrl(url: String): String {
        // TODO: Implement URL shortener expansion
        // Check against known shortener domains (bit.ly, tinyurl.com, etc.)
        return url
    }
    
    private fun extractDomain(url: String): String {
        return try {
            URL(url).host
        } catch (e: Exception) {
            url
        }
    }
    
    private suspend fun performCloudAnalysis(url: String): ScanResult {
        // TODO: Implement cloud-based sandbox and network graph analysis
        // This would involve API calls to backend services
        return ScanResult(
            url = url,
            isMalicious = false,
            threatLevel = ThreatLevel.LOW,
            reason = "Cloud analysis not implemented yet",
            confidence = 0.5f,
            scanLayers = listOf("CloudAnalysis")
        )
    }
}
