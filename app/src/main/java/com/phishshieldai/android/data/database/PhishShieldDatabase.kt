package com.phishshieldai.android.data.database

import androidx.room.*
import com.phishshieldai.android.data.model.ScanResult
import com.phishshieldai.android.data.model.ThreatLevel
import java.util.Date

@Database(
    entities = [ScanResult::class],
    version = 1,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class PhishShieldDatabase : RoomDatabase() {
    abstract fun scanResultDao(): ScanResultDao
}

class Converters {
    @TypeConverter
    fun fromThreatLevel(threatLevel: ThreatLevel): String {
        return threatLevel.name
    }
    
    @TypeConverter
    fun toThreatLevel(threatLevel: String): ThreatLevel {
        return ThreatLevel.valueOf(threatLevel)
    }
    
    @TypeConverter
    fun fromStringList(list: List<String>): String {
        return list.joinToString(",")
    }
    
    @TypeConverter
    fun toStringList(data: String): List<String> {
        return if (data.isEmpty()) emptyList() else data.split(",")
    }
    
    @TypeConverter
    fun fromDate(date: Date?): Long? {
        return date?.time
    }
    
    @TypeConverter
    fun toDate(timestamp: Long?): Date? {
        return timestamp?.let { Date(it) }
    }
}
