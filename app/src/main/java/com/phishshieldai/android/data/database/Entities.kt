package com.phishshieldai.android.data.database

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.phishshieldai.android.data.model.ThreatLevel

@Entity(tableName = "scan_history")
@TypeConverters(Converters::class)
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val url: String,
    val domain: String,
    val isMalicious: Boolean,
    val threatLevel: ThreatLevel,
    val reason: String,
    val confidence: Float,
    val scanLayers: List<String>,
    val timestamp: Long,
    val responseTime: Long, // Time taken to scan in milliseconds
    val sourceApp: String? = null // Which app the URL came from
)

@Entity(tableName = "domain_reputation")
data class DomainReputationEntity(
    @PrimaryKey
    val domain: String,
    val riskScore: Float,
    val category: String, // phishing, malware, spam, etc.
    val lastUpdated: Long,
    val source: String, // local, cloud, community
    val isWhitelisted: Boolean = false,
    val isBlacklisted: Boolean = false
)

@Entity(tableName = "phishing_campaigns")
@TypeConverters(Converters::class)
data class PhishingCampaignEntity(
    @PrimaryKey
    val id: String,
    val urls: List<String>,
    val domains: List<String>,
    val riskScore: Float,
    val firstSeen: Long,
    val lastSeen: Long,
    val isActive: Boolean
)

@Entity(tableName = "url_cache")
data class UrlCacheEntity(
    @PrimaryKey
    val urlHash: String, // SHA256 hash of the URL
    val isMalicious: Boolean,
    val threatLevel: ThreatLevel,
    val confidence: Float,
    val lastScanned: Long,
    val expiryTime: Long
)

@Entity(tableName = "app_statistics")
data class AppStatisticsEntity(
    @PrimaryKey
    val date: String, // YYYY-MM-DD format
    val threatsBlocked: Int,
    val urlsScanned: Int,
    val falsePositives: Int,
    val protectionUptime: Long // milliseconds
)

class Converters {
    private val gson = Gson()
    
    @TypeConverter
    fun fromStringList(value: List<String>): String {
        return gson.toJson(value)
    }
    
    @TypeConverter
    fun toStringList(value: String): List<String> {
        val listType = object : TypeToken<List<String>>() {}.type
        return gson.fromJson(value, listType)
    }
    
    @TypeConverter
    fun fromThreatLevel(value: ThreatLevel): String {
        return value.name
    }
    
    @TypeConverter
    fun toThreatLevel(value: String): ThreatLevel {
        return ThreatLevel.valueOf(value)
    }
}
