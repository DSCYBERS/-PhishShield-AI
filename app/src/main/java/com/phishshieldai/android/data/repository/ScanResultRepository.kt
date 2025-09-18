package com.phishshieldai.android.data.repository

import com.phishshieldai.android.data.database.ScanResultDao
import com.phishshieldai.android.data.model.ScanResult
import kotlinx.coroutines.flow.Flow
import java.util.Calendar
import java.util.Date
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanResultRepository @Inject constructor(
    private val scanResultDao: ScanResultDao
) {
    
    fun getAllScanResults(): Flow<List<ScanResult>> {
        return scanResultDao.getAllScanResults()
    }
    
    fun getMaliciousResults(): Flow<List<ScanResult>> {
        return scanResultDao.getMaliciousResults()
    }
    
    fun getRecentResults(days: Int = 7): Flow<List<ScanResult>> {
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -days)
        return scanResultDao.getRecentResults(calendar.time)
    }
    
    suspend fun getMaliciousCount(): Int {
        return scanResultDao.getMaliciousCount()
    }
    
    suspend fun getScansToday(): Int {
        val calendar = Calendar.getInstance()
        calendar.set(Calendar.HOUR_OF_DAY, 0)
        calendar.set(Calendar.MINUTE, 0)
        calendar.set(Calendar.SECOND, 0)
        calendar.set(Calendar.MILLISECOND, 0)
        return scanResultDao.getScansToday(calendar.time)
    }
    
    suspend fun getLatestResultForUrl(url: String): ScanResult? {
        return scanResultDao.getLatestResultForUrl(url)
    }
    
    suspend fun insertScanResult(scanResult: ScanResult): Long {
        return scanResultDao.insertScanResult(scanResult)
    }
    
    suspend fun insertScanResults(scanResults: List<ScanResult>) {
        scanResultDao.insertScanResults(scanResults)
    }
    
    suspend fun updateScanResult(scanResult: ScanResult) {
        scanResultDao.updateScanResult(scanResult)
    }
    
    suspend fun deleteScanResult(scanResult: ScanResult) {
        scanResultDao.deleteScanResult(scanResult)
    }
    
    suspend fun deleteOldResults(days: Int = 30): Int {
        val calendar = Calendar.getInstance()
        calendar.add(Calendar.DAY_OF_YEAR, -days)
        return scanResultDao.deleteOldResults(calendar.time)
    }
    
    suspend fun deleteAllResults() {
        scanResultDao.deleteAllResults()
    }
}
