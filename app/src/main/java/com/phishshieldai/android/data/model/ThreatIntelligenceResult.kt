package com.phishshieldai.android.data.model

import com.google.gson.annotations.SerializedName

/**
 * Threat intelligence analysis result from backend API
 */
data class ThreatIntelligenceResult(
    @SerializedName("url") val url: String,
    @SerializedName("is_malicious") val is_malicious: Boolean,
    @SerializedName("threat_score") val threat_score: Float,
    @SerializedName("reputation") val reputation: String,
    @SerializedName("threat_sources") val threat_sources: List<ThreatSource>,
    @SerializedName("categories") val categories: List<String>,
    @SerializedName("detailed_results") val detailed_results: Map<String, Any>,
    @SerializedName("timestamp") val timestamp: String
)

/**
 * Individual threat source result
 */
data class ThreatSource(
    @SerializedName("source") val source: String,
    @SerializedName("confidence") val confidence: Float,
    @SerializedName("category") val category: String
)

/**
 * Domain reputation check result
 */
data class DomainReputationResult(
    @SerializedName("domain") val domain: String,
    @SerializedName("reputation") val reputation: String,
    @SerializedName("threat_score") val threat_score: Float,
    @SerializedName("is_malicious") val is_malicious: Boolean,
    @SerializedName("quick_summary") val quick_summary: String
)

/**
 * Threat feeds status result
 */
data class ThreatFeedsStatus(
    @SerializedName("feeds") val feeds: Map<String, FeedStatus>,
    @SerializedName("last_updated") val last_updated: String,
    @SerializedName("total_configured") val total_configured: Int,
    @SerializedName("active_feeds") val active_feeds: Int
)

/**
 * Individual feed status
 */
data class FeedStatus(
    @SerializedName("configured") val configured: Boolean,
    @SerializedName("available") val available: Boolean,
    @SerializedName("last_update") val last_update: String
)

/**
 * Threat report response
 */
data class ThreatReportResponse(
    @SerializedName("status") val status: String,
    @SerializedName("id") val id: String,
    @SerializedName("url") val url: String,
    @SerializedName("threat_type") val threat_type: String
)
