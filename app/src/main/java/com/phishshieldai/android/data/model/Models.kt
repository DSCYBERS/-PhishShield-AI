package com.phishshieldai.android.data.model

data class ScanResult(
    val url: String,
    val isMalicious: Boolean,
    val threatLevel: ThreatLevel,
    val reason: String,
    val confidence: Float,
    val scanLayers: List<String>,
    val timestamp: Long = System.currentTimeMillis(),
    val details: Map<String, Any> = emptyMap()
)

enum class ThreatLevel {
    LOW,      // Safe URL
    MEDIUM,   // Suspicious, needs further analysis
    HIGH,     // Confirmed malicious
    UNKNOWN   // Unable to determine
}

data class AnalysisResult(
    val threatLevel: ThreatLevel,
    val confidence: Float,
    val details: String = "",
    val features: Map<String, Any> = emptyMap()
)

data class ProtectionStatistics(
    val threatsBlocked: Int,
    val urlsScanned: Int,
    val isProtectionActive: Boolean,
    val lastScanTime: Long
)

data class PhishingCampaign(
    val id: String,
    val urls: List<String>,
    val domains: List<String>,
    val riskScore: Float,
    val firstSeen: Long,
    val lastSeen: Long
)
