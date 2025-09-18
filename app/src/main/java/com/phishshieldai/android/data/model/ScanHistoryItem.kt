package com.phishshieldai.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scan_history")
data class ScanHistoryItem(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val threatLevel: String,
    val timestamp: Long,
    val blocked: Boolean,
    val threatTypes: List<String>,
    val detectionLayers: List<String>,
    val confidence: Float,
    val responseTimeMs: Int = 0,
    val userAgent: String = "",
    val ipAddress: String = "",
    val geolocation: String = "",
    val malwareFamily: String? = null,
    val threatIntelSources: List<String> = emptyList(),
    val mlModelVersion: String = "",
    val riskScore: Float = 0.0f,
    val additionalMetadata: Map<String, String> = emptyMap()
)
