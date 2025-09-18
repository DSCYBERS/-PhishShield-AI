package com.phishshieldai.android.data.database

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface PhishingReportDao {
    @Query("SELECT * FROM phishing_reports ORDER BY timestamp DESC")
    fun getAllReports(): Flow<List<PhishingReportEntity>>

    @Query("SELECT * FROM phishing_reports WHERE id = :id")
    suspend fun getReportById(id: Long): PhishingReportEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReport(report: PhishingReportEntity): Long

    @Update
    suspend fun updateReport(report: PhishingReportEntity)

    @Delete
    suspend fun deleteReport(report: PhishingReportEntity)

    @Query("DELETE FROM phishing_reports WHERE id = :id")
    suspend fun deleteReportById(id: Long)
}

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY scan_date DESC")
    fun getAllScans(): Flow<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history WHERE id = :id")
    suspend fun getScanById(id: Long): ScanHistoryEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScan(scan: ScanHistoryEntity): Long

    @Update
    suspend fun updateScan(scan: ScanHistoryEntity)

    @Delete
    suspend fun deleteScan(scan: ScanHistoryEntity)

    @Query("DELETE FROM scan_history")
    suspend fun clearAllScans()
}

@Dao
interface UserPreferencesDao {
    @Query("SELECT * FROM user_preferences WHERE id = :id")
    suspend fun getPreferences(id: Long = 1): UserPreferencesEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPreferences(preferences: UserPreferencesEntity)

    @Update
    suspend fun updatePreferences(preferences: UserPreferencesEntity)
}