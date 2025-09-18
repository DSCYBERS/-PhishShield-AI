package com.phishshieldai.android.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.Date

@Entity(tableName = "scan_results")
data class ScanResult(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val isMalicious: Boolean,
    val threatLevel: ThreatLevel,
    val reason: String,
    val confidence: Float,
    val scanLayers: List<String>,
    val timestamp: Date = Date(),
    val source: String = "unknown", // click, input, content, typing
    val blocked: Boolean = false
)

enum class ThreatLevel {
    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

data class AnalysisResult(
    val isMalicious: Boolean = false,
    val threatLevel: ThreatLevel = ThreatLevel.LOW,
    val confidence: Float = 0.0f,
    val details: Any = "No details available"
)
