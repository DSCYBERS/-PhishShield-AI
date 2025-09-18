package com.phishshieldai.android.ui

import android.app.Application
import android.content.Context
import android.net.VpnService
import android.provider.Settings
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.phishshieldai.android.data.repository.PhishShieldRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    application: Application,
    private val repository: PhishShieldRepository
) : AndroidViewModel(application) {
    
    private val _isProtectionEnabled = MutableLiveData<Boolean>()
    val isProtectionEnabled: LiveData<Boolean> = _isProtectionEnabled
    
    private val _threatsBlocked = MutableLiveData<Int>()
    val threatsBlocked: LiveData<Int> = _threatsBlocked
    
    private val _urlsScanned = MutableLiveData<Int>()
    val urlsScanned: LiveData<Int> = _urlsScanned
    
    private val _isVpnPermissionGranted = MutableLiveData<Boolean>()
    val isVpnPermissionGranted: LiveData<Boolean> = _isVpnPermissionGranted
    
    private val _isAccessibilityServiceEnabled = MutableLiveData<Boolean>()
    val isAccessibilityServiceEnabled: LiveData<Boolean> = _isAccessibilityServiceEnabled
    
    private val _isOverlayPermissionGranted = MutableLiveData<Boolean>()
    val isOverlayPermissionGranted: LiveData<Boolean> = _isOverlayPermissionGranted
    
    init {
        loadStatistics()
    }
    
    fun checkVpnPermission() {
        val intent = VpnService.prepare(getApplication())
        _isVpnPermissionGranted.value = intent == null
    }
    
    fun checkAccessibilityServiceStatus() {
        val context = getApplication<Application>()
        val accessibilityEnabled = try {
            val accessibilityManager = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            accessibilityManager?.contains("com.phishshieldai.android/.service.PhishShieldAccessibilityService") == true
        } catch (e: Exception) {
            false
        }
        _isAccessibilityServiceEnabled.value = accessibilityEnabled
    }
    
    fun checkOverlayPermission() {
        _isOverlayPermissionGranted.value = Settings.canDrawOverlays(getApplication())
    }
    
    private fun loadStatistics() {
        viewModelScope.launch {
            try {
                val stats = repository.getProtectionStatistics()
                _threatsBlocked.value = stats.threatsBlocked
                _urlsScanned.value = stats.urlsScanned
                _isProtectionEnabled.value = stats.isProtectionActive
            } catch (e: Exception) {
                // Handle error
                _threatsBlocked.value = 0
                _urlsScanned.value = 0
                _isProtectionEnabled.value = false
            }
        }
    }
    
    fun refreshStatistics() {
        loadStatistics()
    }
}
