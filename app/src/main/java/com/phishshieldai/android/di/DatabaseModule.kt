package com.phishshieldai.android.di

import android.content.Context
import androidx.room.Room
import com.phishshieldai.android.data.database.PhishShieldDatabase
import com.phishshieldai.android.data.database.ScanResultDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): PhishShieldDatabase {
        return Room.databaseBuilder(
            context,
            PhishShieldDatabase::class.java,
            "phishshield_database"
        ).build()
    }
    
    @Provides
    fun provideScanResultDao(database: PhishShieldDatabase): ScanResultDao {
        return database.scanResultDao()
    }
}
