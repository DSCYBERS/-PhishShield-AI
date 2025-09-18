package com.phishshieldai.android.ui.settings

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.preference.PreferenceFragmentCompat
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.slider.Slider
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.ActivitySettingsBinding
import com.phishshieldai.android.databinding.DialogApiConfigBinding
import com.phishshieldai.android.databinding.DialogProtectionLevelBinding
import com.phishshieldai.android.ui.adapters.SettingsAdapter
import com.phishshieldai.android.data.model.ProtectionLevel
import com.phishshieldai.android.data.model.SettingsItem
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class SettingsActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivitySettingsBinding
    private val viewModel: SettingsViewModel by viewModels()
    private lateinit var settingsAdapter: SettingsAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        setupObservers()
        setupClickListeners()
    }
    
    private fun setupUI() {
        // Setup toolbar
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Settings"
        
        // Setup settings list
        settingsAdapter = SettingsAdapter { settingsItem ->
            handleSettingsItemClick(settingsItem)
        }
        
        binding.settingsRecyclerView.apply {
            adapter = settingsAdapter
            layoutManager = LinearLayoutManager(this@SettingsActivity)
        }
        
        // Load settings
        viewModel.loadSettings()
    }
    
    private fun setupObservers() {
        lifecycleScope.launch {
            viewModel.settingsItems.collect { items ->
                settingsAdapter.submitList(items)
            }
        }
        
        lifecycleScope.launch {
            viewModel.protectionLevel.collect { level ->
                updateProtectionLevelUI(level)
            }
        }
        
        lifecycleScope.launch {
            viewModel.settingsState.collect { state ->
                updateSettingsStateUI(state)
            }
        }
    }
    
    private fun setupClickListeners() {
        binding.apply {
            // Protection level card
            protectionLevelCard.setOnClickListener {
                showProtectionLevelDialog()
            }
            
            // API configuration card
            apiConfigCard.setOnClickListener {
                showApiConfigDialog()
            }
            
            // Export settings
            btnExportSettings.setOnClickListener {
                exportSettings()
            }
            
            // Import settings
            btnImportSettings.setOnClickListener {
                importSettings()
            }
            
            // Reset to defaults
            btnResetDefaults.setOnClickListener {
                showResetConfirmationDialog()
            }
        }
    }
    
    private fun handleSettingsItemClick(item: SettingsItem) {
        when (item.id) {
            "realtime_protection" -> {
                viewModel.toggleRealtimeProtection()
            }
            "vpn_protection" -> {
                viewModel.toggleVpnProtection()
            }
            "accessibility_monitoring" -> {
                viewModel.toggleAccessibilityMonitoring()
            }
            "threat_intelligence" -> {
                viewModel.toggleThreatIntelligence()
            }
            "ml_detection" -> {
                viewModel.toggleMlDetection()
            }
            "sandbox_analysis" -> {
                viewModel.toggleSandboxAnalysis()
            }
            "network_analysis" -> {
                viewModel.toggleNetworkAnalysis()
            }
            "notifications" -> {
                showNotificationSettings()
            }
            "whitelist_management" -> {
                showWhitelistManagement()
            }
            "scan_history" -> {
                showScanHistorySettings()
            }
            "advanced_settings" -> {
                showAdvancedSettings()
            }
            "about" -> {
                showAboutDialog()
            }
            "privacy_policy" -> {
                openPrivacyPolicy()
            }
            "terms_of_service" -> {
                openTermsOfService()
            }
        }
    }
    
    private fun updateProtectionLevelUI(level: ProtectionLevel) {
        binding.apply {
            when (level) {
                ProtectionLevel.MAXIMUM -> {
                    protectionLevelText.text = "Maximum Protection"
                    protectionLevelDescription.text = "All layers active, real-time cloud analysis"
                    protectionLevelIcon.setImageResource(R.drawable.ic_shield_max)
                }
                ProtectionLevel.HIGH -> {
                    protectionLevelText.text = "High Protection"
                    protectionLevelDescription.text = "Advanced ML and threat intelligence"
                    protectionLevelIcon.setImageResource(R.drawable.ic_shield_high)
                }
                ProtectionLevel.BALANCED -> {
                    protectionLevelText.text = "Balanced Protection"
                    protectionLevelDescription.text = "Good protection with performance balance"
                    protectionLevelIcon.setImageResource(R.drawable.ic_shield_balanced)
                }
                ProtectionLevel.BASIC -> {
                    protectionLevelText.text = "Basic Protection"
                    protectionLevelDescription.text = "Essential protection, minimal resource usage"
                    protectionLevelIcon.setImageResource(R.drawable.ic_shield_basic)
                }
            }
        }
    }
    
    private fun updateSettingsStateUI(state: SettingsViewModel.SettingsState) {
        binding.apply {
            // API Configuration status
            apiConfigStatusText.text = when {
                state.apiKeysConfigured >= 3 -> "Well configured (${state.apiKeysConfigured}/7 APIs)"
                state.apiKeysConfigured >= 1 -> "Partially configured (${state.apiKeysConfigured}/7 APIs)"
                else -> "Not configured"
            }
            
            val statusColor = when {
                state.apiKeysConfigured >= 3 -> R.color.safe
                state.apiKeysConfigured >= 1 -> R.color.threat_medium
                else -> R.color.threat_high
            }
            
            apiConfigStatusIndicator.setCardBackgroundColor(
                resources.getColor(statusColor, theme)
            )
            
            // Storage usage
            storageUsageText.text = "${state.storageUsedMB} MB used"
            storageUsageProgress.progress = ((state.storageUsedMB / 100.0f) * 100).toInt()
            
            // Scan statistics
            totalScansText.text = "${state.totalScans} scans"
            threatsBlockedText.text = "${state.threatsBlocked} threats blocked"
            lastUpdateText.text = "Last updated: ${state.lastUpdate}"
        }
    }
    
    private fun showProtectionLevelDialog() {
        val dialogBinding = DialogProtectionLevelBinding.inflate(layoutInflater)
        
        // Set current protection level
        val currentLevel = viewModel.getCurrentProtectionLevel()
        when (currentLevel) {
            ProtectionLevel.MAXIMUM -> dialogBinding.radioMaximum.isChecked = true
            ProtectionLevel.HIGH -> dialogBinding.radioHigh.isChecked = true
            ProtectionLevel.BALANCED -> dialogBinding.radioBalanced.isChecked = true
            ProtectionLevel.BASIC -> dialogBinding.radioBasic.isChecked = true
        }
        
        MaterialAlertDialogBuilder(this)
            .setTitle("Protection Level")
            .setView(dialogBinding.root)
            .setPositiveButton("Apply") { _, _ ->
                val selectedLevel = when {
                    dialogBinding.radioMaximum.isChecked -> ProtectionLevel.MAXIMUM
                    dialogBinding.radioHigh.isChecked -> ProtectionLevel.HIGH
                    dialogBinding.radioBalanced.isChecked -> ProtectionLevel.BALANCED
                    else -> ProtectionLevel.BASIC
                }
                viewModel.setProtectionLevel(selectedLevel)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showApiConfigDialog() {
        val dialogBinding = DialogApiConfigBinding.inflate(layoutInflater)
        
        // Load current API configuration
        val apiConfig = viewModel.getApiConfiguration()
        dialogBinding.apply {
            virusTotalApiKey.setText(apiConfig.virusTotalKey)
            safeBrowsingApiKey.setText(apiConfig.safeBrowsingKey)
            urlVoidApiKey.setText(apiConfig.urlVoidKey)
            phishTankApiKey.setText(apiConfig.phishTankKey)
            customApiUrl.setText(apiConfig.customApiUrl)
            apiTimeoutSlider.value = apiConfig.timeoutSeconds.toFloat()
            enableRetries.isChecked = apiConfig.enableRetries
        }
        
        MaterialAlertDialogBuilder(this)
            .setTitle("API Configuration")
            .setView(dialogBinding.root)
            .setPositiveButton("Save") { _, _ ->
                val newConfig = SettingsViewModel.ApiConfiguration(
                    virusTotalKey = dialogBinding.virusTotalApiKey.text.toString(),
                    safeBrowsingKey = dialogBinding.safeBrowsingApiKey.text.toString(),
                    urlVoidKey = dialogBinding.urlVoidApiKey.text.toString(),
                    phishTankKey = dialogBinding.phishTankApiKey.text.toString(),
                    customApiUrl = dialogBinding.customApiUrl.text.toString(),
                    timeoutSeconds = dialogBinding.apiTimeoutSlider.value.toInt(),
                    enableRetries = dialogBinding.enableRetries.isChecked
                )
                viewModel.saveApiConfiguration(newConfig)
                Toast.makeText(this, "API configuration saved", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Test APIs") { _, _ ->
                testApiConfiguration(dialogBinding)
            }
            .show()
    }
    
    private fun testApiConfiguration(binding: DialogApiConfigBinding) {
        val testConfig = SettingsViewModel.ApiConfiguration(
            virusTotalKey = binding.virusTotalApiKey.text.toString(),
            safeBrowsingKey = binding.safeBrowsingApiKey.text.toString(),
            urlVoidKey = binding.urlVoidApiKey.text.toString(),
            phishTankKey = binding.phishTankApiKey.text.toString(),
            customApiUrl = binding.customApiUrl.text.toString(),
            timeoutSeconds = binding.apiTimeoutSlider.value.toInt(),
            enableRetries = binding.enableRetries.isChecked
        )
        
        viewModel.testApiConfiguration(testConfig) { results ->
            showApiTestResults(results)
        }
    }
    
    private fun showApiTestResults(results: Map<String, Boolean>) {
        val message = buildString {
            appendLine("API Test Results:")
            appendLine()
            results.forEach { (api, success) ->
                val status = if (success) "✅ Working" else "❌ Failed"
                appendLine("$api: $status")
            }
        }
        
        MaterialAlertDialogBuilder(this)
            .setTitle("API Test Results")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
    
    private fun showNotificationSettings() {
        startActivity(Intent(this, NotificationSettingsActivity::class.java))
    }
    
    private fun showWhitelistManagement() {
        startActivity(Intent(this, WhitelistManagementActivity::class.java))
    }
    
    private fun showScanHistorySettings() {
        startActivity(Intent(this, ScanHistorySettingsActivity::class.java))
    }
    
    private fun showAdvancedSettings() {
        startActivity(Intent(this, AdvancedSettingsActivity::class.java))
    }
    
    private fun exportSettings() {
        viewModel.exportSettings { success, filePath ->
            if (success) {
                Toast.makeText(this, "Settings exported to: $filePath", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this, "Failed to export settings", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun importSettings() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
        }
        
        try {
            startActivityForResult(intent, REQUEST_CODE_IMPORT_SETTINGS)
        } catch (e: Exception) {
            Toast.makeText(this, "File manager not available", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun showResetConfirmationDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Reset Settings")
            .setMessage("This will reset all settings to their default values. This action cannot be undone.\n\nContinue?")
            .setPositiveButton("Reset") { _, _ ->
                viewModel.resetToDefaults()
                Toast.makeText(this, "Settings reset to defaults", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showAboutDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("PhishShield AI")
            .setMessage("""
                Version: 1.0.0
                
                Advanced AI-powered phishing protection with 7-layer defense system.
                
                • Real-time URL analysis
                • Machine learning detection
                • Threat intelligence integration
                • VPN-based network protection
                • Sandbox analysis
                • Network graph analysis
                
                Developed with ❤️ for mobile security.
            """.trimIndent())
            .setPositiveButton("OK", null)
            .setNeutralButton("View Licenses") { _, _ ->
                startActivity(Intent(this, LicensesActivity::class.java))
            }
            .show()
    }
    
    private fun openPrivacyPolicy() {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = android.net.Uri.parse("https://phishshield.ai/privacy")
        }
        startActivity(intent)
    }
    
    private fun openTermsOfService() {
        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = android.net.Uri.parse("https://phishshield.ai/terms")
        }
        startActivity(intent)
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == REQUEST_CODE_IMPORT_SETTINGS && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                viewModel.importSettings(uri) { success ->
                    val message = if (success) {
                        "Settings imported successfully"
                    } else {
                        "Failed to import settings"
                    }
                    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    override fun onSupportNavigateUp(): Boolean {
        onBackPressed()
        return true
    }
    
    companion object {
        private const val REQUEST_CODE_IMPORT_SETTINGS = 100
    }
}
