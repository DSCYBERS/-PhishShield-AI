package com.phishshieldai.android.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.provider.Settings
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.ActivityMainBinding
import com.phishshieldai.android.service.PhishShieldVpnService
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: MainViewModel
    
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }
    
    private val accessibilitySettingsLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { 
        // Check if accessibility service is enabled
        viewModel.checkAccessibilityServiceStatus()
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        viewModel = ViewModelProvider(this)[MainViewModel::class.java]
        
        setupUI()
        observeViewModel()
        checkPermissions()
    }
    
    private fun setupUI() {
        binding.apply {
            // Protection Status Card
            btnToggleProtection.setOnClickListener {
                if (viewModel.isProtectionEnabled.value == true) {
                    stopProtection()
                } else {
                    startProtection()
                }
            }
            
            // Settings button
            btnSettings.setOnClickListener {
                // Navigate to settings
                // TODO: Implement settings navigation
            }
            
            // Statistics button
            btnStatistics.setOnClickListener {
                // Navigate to statistics
                // TODO: Implement statistics navigation
            }
            
            // Enable accessibility service
            btnEnableAccessibility.setOnClickListener {
                openAccessibilitySettings()
            }
        }
    }
    
    private fun observeViewModel() {
        viewModel.isProtectionEnabled.observe(this) { isEnabled ->
            updateProtectionStatus(isEnabled)
        }
        
        viewModel.threatsBlocked.observe(this) { count ->
            binding.tvThreatsBlocked.text = count.toString()
        }
        
        viewModel.urlsScanned.observe(this) { count ->
            binding.tvUrlsScanned.text = count.toString()
        }
        
        viewModel.isVpnPermissionGranted.observe(this) { isGranted ->
            binding.btnToggleProtection.isEnabled = isGranted
        }
        
        viewModel.isAccessibilityServiceEnabled.observe(this) { isEnabled ->
            binding.btnEnableAccessibility.isEnabled = !isEnabled
            if (isEnabled) {
                binding.btnEnableAccessibility.text = "Accessibility Service Enabled ✓"
            }
        }
    }
    
    private fun checkPermissions() {
        viewModel.checkVpnPermission()
        viewModel.checkAccessibilityServiceStatus()
        viewModel.checkOverlayPermission()
    }
    
    private fun startProtection() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            startVpnService()
        }
    }
    
    private fun stopProtection() {
        val intent = Intent(this, PhishShieldVpnService::class.java)
        intent.action = PhishShieldVpnService.ACTION_STOP
        startService(intent)
    }
    
    private fun startVpnService() {
        val intent = Intent(this, PhishShieldVpnService::class.java)
        intent.action = PhishShieldVpnService.ACTION_START
        startService(intent)
    }
    
    private fun updateProtectionStatus(isEnabled: Boolean) {
        binding.apply {
            if (isEnabled) {
                tvProtectionStatus.text = "Protection Active"
                tvProtectionStatus.setTextColor(getColor(android.R.color.holo_green_dark))
                btnToggleProtection.text = "Stop Protection"
                btnToggleProtection.setBackgroundColor(getColor(android.R.color.holo_red_dark))
            } else {
                tvProtectionStatus.text = "Protection Disabled"
                tvProtectionStatus.setTextColor(getColor(android.R.color.holo_red_dark))
                btnToggleProtection.text = "Start Protection"
                btnToggleProtection.setBackgroundColor(getColor(android.R.color.holo_green_dark))
            }
        }
    }
    
    private fun openAccessibilitySettings() {
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        accessibilitySettingsLauncher.launch(intent)
    }
}
