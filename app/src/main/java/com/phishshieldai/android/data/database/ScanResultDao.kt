package com.phishshieldai.android.data.database

import androidx.room.*
import com.phishshieldai.android.data.model.ScanResult
import kotlinx.coroutines.flow.Flow
import java.util.Date

@Dao
interface ScanResultDao {
    
    @Query("SELECT * FROM scan_results ORDER BY timestamp DESC")
    fun getAllScanResults(): Flow<List<ScanResult>>
    
    @Query("SELECT * FROM scan_results WHERE isMalicious = 1 ORDER BY timestamp DESC")
    fun getMaliciousResults(): Flow<List<ScanResult>>
    
    @Query("SELECT * FROM scan_results WHERE timestamp >= :since ORDER BY timestamp DESC")
    fun getRecentResults(since: Date): Flow<List<ScanResult>>
    
    @Query("SELECT COUNT(*) FROM scan_results WHERE isMalicious = 1")
    suspend fun getMaliciousCount(): Int
    
    @Query("SELECT COUNT(*) FROM scan_results WHERE timestamp >= :since")
    suspend fun getScansToday(since: Date): Int
    
    @Query("SELECT * FROM scan_results WHERE url = :url ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLatestResultForUrl(url: String): ScanResult?
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScanResult(scanResult: ScanResult): Long
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScanResults(scanResults: List<ScanResult>)
    
    @Update
    suspend fun updateScanResult(scanResult: ScanResult)
    
    @Delete
    suspend fun deleteScanResult(scanResult: ScanResult)
    
    @Query("DELETE FROM scan_results WHERE timestamp < :before")
    suspend fun deleteOldResults(before: Date): Int
    
    @Query("DELETE FROM scan_results")
    suspend fun deleteAllResults()
}
