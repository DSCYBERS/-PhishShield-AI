package com.phishshieldai.android.data.repository

import android.util.Log
import com.phishshieldai.android.data.dao.ScanResultDao
import com.phishshieldai.android.data.model.ProtectionStatistics
import com.phishshieldai.android.data.model.ScanResult
import com.phishshieldai.android.data.model.ThreatLevel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Date
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PhishShieldRepository @Inject constructor(
    private val scanResultDao: ScanResultDao
) {
    
    companion object {
        private const val TAG = "PhishShieldRepository"
    }
    
    /**
     * Get real-time protection statistics
     */
    suspend fun getProtectionStatistics(): ProtectionStatistics = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching protection statistics from database")
            
            val totalScans = scanResultDao.getTotalScanCount()
            val threatsBlocked = scanResultDao.getThreatCount()
            val todayScans = scanResultDao.getScansToday()
            val lastScanTime = scanResultDao.getLastScanTime() ?: 0L
            
            // Calculate protection active status
            val isProtectionActive = isProtectionCurrentlyActive()
            
            // Get recent threat activity
            val recentThreats = scanResultDao.getRecentThreats(limit = 10)
            val threatTrend = calculateThreatTrend()
            
            Log.d(TAG, "Statistics: total=$totalScans, threats=$threatsBlocked, today=$todayScans")
            
            ProtectionStatistics(
                threatsBlocked = threatsBlocked,
                urlsScanned = totalScans,
                isProtectionActive = isProtectionActive,
                lastScanTime = lastScanTime,
                scansToday = todayScans,
                threatTrend = threatTrend,
                recentThreats = recentThreats.size
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching protection statistics", e)
            // Return default statistics on error
            ProtectionStatistics(
                threatsBlocked = 0,
                urlsScanned = 0,
                isProtectionActive = false,
                lastScanTime = System.currentTimeMillis()
            )
        }
    }
    
    /**
     * Get protection statistics as observable Flow
     */
    fun getProtectionStatisticsFlow(): Flow<ProtectionStatistics> {
        return scanResultDao.getAllScanResultsFlow().map { scanResults ->
            try {
                val totalScans = scanResults.size
                val threatsBlocked = scanResults.count { it.isBlocked }
                val todayStart = getTodayStartMillis()
                val todayScans = scanResults.count { it.timestamp >= todayStart }
                val lastScanTime = scanResults.maxOfOrNull { it.timestamp } ?: 0L
                
                ProtectionStatistics(
                    threatsBlocked = threatsBlocked,
                    urlsScanned = totalScans,
                    isProtectionActive = isProtectionCurrentlyActive(),
                    lastScanTime = lastScanTime,
                    scansToday = todayScans,
                    threatTrend = calculateThreatTrendFromResults(scanResults),
                    recentThreats = scanResults.count { 
                        it.isBlocked && (System.currentTimeMillis() - it.timestamp) < 24 * 60 * 60 * 1000 
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error processing scan results flow", e)
                ProtectionStatistics(
                    threatsBlocked = 0,
                    urlsScanned = 0,
                    isProtectionActive = false,
                    lastScanTime = System.currentTimeMillis()
                )
            }
        }
    }
    
    /**
     * Insert new scan result
     */
    suspend fun insertScanResult(scanResult: ScanResult): Long = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Inserting scan result: ${scanResult.url}")
            scanResultDao.insertScanResult(scanResult)
        } catch (e: Exception) {
            Log.e(TAG, "Error inserting scan result", e)
            -1L
        }
    }
    
    /**
     * Get scan history with pagination
     */
    suspend fun getScanHistory(limit: Int = 50, offset: Int = 0): List<ScanResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching scan history: limit=$limit, offset=$offset")
            scanResultDao.getScanHistory(limit, offset)
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching scan history", e)
            emptyList()
        }
    }
    
    /**
     * Get scan history as observable Flow
     */
    fun getScanHistoryFlow(limit: Int = 50): Flow<List<ScanResult>> {
        return scanResultDao.getScanHistoryFlow(limit)
    }
    
    /**
     * Get threats by severity
     */
    suspend fun getThreatsBySeverity(threatLevel: ThreatLevel): List<ScanResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching threats by severity: $threatLevel")
            scanResultDao.getScanResultsByThreatLevel(threatLevel)
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching threats by severity", e)
            emptyList()
        }
    }
    
    /**
     * Get scan result by URL
     */
    suspend fun getScanResultByUrl(url: String): ScanResult? = withContext(Dispatchers.IO) {
        try {
            scanResultDao.getScanResultByUrl(url)
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching scan result for URL: $url", e)
            null
        }
    }
    
    /**
     * Update scan result
     */
    suspend fun updateScanResult(scanResult: ScanResult): Int = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Updating scan result: ${scanResult.url}")
            scanResultDao.updateScanResult(scanResult)
        } catch (e: Exception) {
            Log.e(TAG, "Error updating scan result", e)
            0
        }
    }
    
    /**
     * Delete old scan results to maintain database size
     */
    suspend fun cleanupOldScanResults(olderThanDays: Int = 30): Int = withContext(Dispatchers.IO) {
        try {
            val cutoffTime = System.currentTimeMillis() - (olderThanDays * 24 * 60 * 60 * 1000L)
            val deletedCount = scanResultDao.deleteOldScanResults(cutoffTime)
            Log.d(TAG, "Cleaned up $deletedCount old scan results older than $olderThanDays days")
            deletedCount
        } catch (e: Exception) {
            Log.e(TAG, "Error cleaning up old scan results", e)
            0
        }
    }
    
    /**
     * Get threat statistics by category
     */
    suspend fun getThreatStatistics(): Map<String, Int> = withContext(Dispatchers.IO) {
        try {
            val stats = mutableMapOf<String, Int>()
            
            stats["total_scans"] = scanResultDao.getTotalScanCount()
            stats["total_threats"] = scanResultDao.getThreatCount()
            stats["critical_threats"] = scanResultDao.getThreatCountByLevel(ThreatLevel.CRITICAL)
            stats["high_threats"] = scanResultDao.getThreatCountByLevel(ThreatLevel.HIGH)
            stats["medium_threats"] = scanResultDao.getThreatCountByLevel(ThreatLevel.MEDIUM)
            stats["low_threats"] = scanResultDao.getThreatCountByLevel(ThreatLevel.LOW)
            stats["scans_today"] = scanResultDao.getScansToday()
            stats["threats_today"] = scanResultDao.getThreatsToday()
            
            Log.d(TAG, "Threat statistics generated: $stats")
            stats
            
        } catch (e: Exception) {
            Log.e(TAG, "Error generating threat statistics", e)
            emptyMap()
        }
    }
    
    /**
     * Search scan results by URL pattern
     */
    suspend fun searchScanResults(query: String, limit: Int = 20): List<ScanResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Searching scan results for: $query")
            scanResultDao.searchScanResults("%$query%", limit)
        } catch (e: Exception) {
            Log.e(TAG, "Error searching scan results", e)
            emptyList()
        }
    }
    
    /**
     * Get scan results for a specific domain
     */
    suspend fun getScanResultsForDomain(domain: String): List<ScanResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching scan results for domain: $domain")
            scanResultDao.getScanResultsForDomain("%$domain%")
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching scan results for domain", e)
            emptyList()
        }
    }
    
    private suspend fun isProtectionCurrentlyActive(): Boolean {
        return try {
            // Check if there have been recent scans (within last hour)
            val recentScanCount = scanResultDao.getRecentScanCount(60 * 60 * 1000) // 1 hour
            recentScanCount > 0
        } catch (e: Exception) {
            Log.e(TAG, "Error checking protection status", e)
            false
        }
    }
    
    private suspend fun calculateThreatTrend(): Float {
        return try {
            val yesterdayStart = getTodayStartMillis() - (24 * 60 * 60 * 1000)
            val todayStart = getTodayStartMillis()
            
            val yesterdayThreats = scanResultDao.getThreatCountForPeriod(yesterdayStart, todayStart)
            val todayThreats = scanResultDao.getThreatsToday()
            
            when {
                yesterdayThreats == 0 && todayThreats > 0 -> 1.0f
                yesterdayThreats == 0 -> 0.0f
                else -> (todayThreats - yesterdayThreats).toFloat() / yesterdayThreats
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error calculating threat trend", e)
            0.0f
        }
    }
    
    private fun calculateThreatTrendFromResults(scanResults: List<ScanResult>): Float {
        return try {
            val todayStart = getTodayStartMillis()
            val yesterdayStart = todayStart - (24 * 60 * 60 * 1000)
            
            val todayThreats = scanResults.count { 
                it.isBlocked && it.timestamp >= todayStart 
            }
            val yesterdayThreats = scanResults.count { 
                it.isBlocked && it.timestamp >= yesterdayStart && it.timestamp < todayStart 
            }
            
            when {
                yesterdayThreats == 0 && todayThreats > 0 -> 1.0f
                yesterdayThreats == 0 -> 0.0f
                else -> (todayThreats - yesterdayThreats).toFloat() / yesterdayThreats
            }
        } catch (e: Exception) {
            0.0f
        }
    }
    
    private fun getTodayStartMillis(): Long {
        val calendar = java.util.Calendar.getInstance()
        calendar.set(java.util.Calendar.HOUR_OF_DAY, 0)
        calendar.set(java.util.Calendar.MINUTE, 0)
        calendar.set(java.util.Calendar.SECOND, 0)
        calendar.set(java.util.Calendar.MILLISECOND, 0)
        return calendar.timeInMillis
    }
    
    /**
     * Export scan results for backup/analysis
     */
    suspend fun exportScanResults(): List<ScanResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Exporting all scan results")
            scanResultDao.getAllScanResults()
        } catch (e: Exception) {
            Log.e(TAG, "Error exporting scan results", e)
            emptyList()
        }
    }
    
    /**
     * Import scan results from backup
     */
    suspend fun importScanResults(scanResults: List<ScanResult>): Int = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Importing ${scanResults.size} scan results")
            var importedCount = 0
            
            scanResults.forEach { scanResult ->
                try {
                    scanResultDao.insertScanResult(scanResult)
                    importedCount++
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to import scan result: ${scanResult.url}", e)
                }
            }
            
            Log.d(TAG, "Successfully imported $importedCount scan results")
            importedCount
            
        } catch (e: Exception) {
            Log.e(TAG, "Error importing scan results", e)
            0
        }
    }
}
