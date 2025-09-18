package com.phishshieldai.android.ui.main

import android.animation.ObjectAnimator
import android.content.Intent
import android.os.Bundle
import android.view.animation.AccelerateDecelerateInterpolator
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.ActivityMainDashboardBinding
import com.phishshieldai.android.ui.analytics.AnalyticsActivity
import com.phishshieldai.android.ui.monitoring.MonitoringActivity
import com.phishshieldai.android.ui.settings.SettingsActivity
import com.phishshieldai.android.ui.history.ScanHistoryActivity
import com.phishshieldai.android.data.model.ProtectionStatus
import com.phishshieldai.android.data.model.ThreatLevel
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainDashboardActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainDashboardBinding
    private val viewModel: MainDashboardViewModel by viewModels()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainDashboardBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        setupObservers()
        setupClickListeners()
        
        // Initialize protection status
        viewModel.updateProtectionStatus()
    }
    
    private fun setupUI() {
        // Setup toolbar
        setSupportActionBar(binding.toolbar)
        supportActionBar?.title = "PhishShield AI"
        
        // Setup protection shield animation
        setupProtectionShieldAnimation()
        
        // Setup quick action cards
        setupQuickActionCards()
    }
    
    private fun setupObservers() {
        lifecycleScope.launch {
            viewModel.protectionStatus.collect { status ->
                updateProtectionStatusUI(status)
            }
        }
        
        lifecycleScope.launch {
            viewModel.scanStatistics.collect { stats ->
                updateScanStatisticsUI(stats)
            }
        }
        
        lifecycleScope.launch {
            viewModel.threatFeedStatus.collect { feedStatus ->
                updateThreatFeedStatusUI(feedStatus)
            }
        }
        
        lifecycleScope.launch {
            viewModel.recentThreats.collect { threats ->
                updateRecentThreatsUI(threats)
            }
        }
    }
    
    private fun setupClickListeners() {
        binding.apply {
            // Protection toggle
            protectionToggle.setOnCheckedChangeListener { _, isChecked ->
                viewModel.toggleProtection(isChecked)
            }
            
            // Quick actions
            cardQuickScan.setOnClickListener {
                showQuickScanDialog()
            }
            
            cardScanHistory.setOnClickListener {
                startActivity(Intent(this@MainDashboardActivity, ScanHistoryActivity::class.java))
            }
            
            cardSettings.setOnClickListener {
                startActivity(Intent(this@MainDashboardActivity, SettingsActivity::class.java))
            }
            
            cardAnalytics.setOnClickListener {
                startActivity(Intent(this@MainDashboardActivity, AnalyticsActivity::class.java))
            }
            
            // Status monitoring
            cardThreatFeeds.setOnClickListener {
                startActivity(Intent(this@MainDashboardActivity, MonitoringActivity::class.java))
            }
            
            // Recent threats
            cardRecentThreats.setOnClickListener {
                startActivity(Intent(this@MainDashboardActivity, ScanHistoryActivity::class.java).apply {
                    putExtra("filter", "threats_only")
                })
            }
            
            // Manual URL scan
            fabScanUrl.setOnClickListener {
                showManualScanDialog()
            }
        }
    }
    
    private fun setupProtectionShieldAnimation() {
        // Create pulsing animation for protection shield
        val pulseAnimator = ObjectAnimator.ofFloat(binding.protectionShield, "alpha", 1.0f, 0.6f, 1.0f)
        pulseAnimator.duration = 2000
        pulseAnimator.repeatCount = ObjectAnimator.INFINITE
        pulseAnimator.interpolator = AccelerateDecelerateInterpolator()
        pulseAnimator.start()
    }
    
    private fun setupQuickActionCards() {
        val cards = listOf(
            binding.cardQuickScan,
            binding.cardScanHistory,
            binding.cardSettings,
            binding.cardAnalytics
        )
        
        // Add subtle hover effects
        cards.forEach { card ->
            card.setOnTouchListener { view, event ->
                when (event.action) {
                    android.view.MotionEvent.ACTION_DOWN -> {
                        ObjectAnimator.ofFloat(view, "scaleX", 0.95f).apply {
                            duration = 100
                            start()
                        }
                        ObjectAnimator.ofFloat(view, "scaleY", 0.95f).apply {
                            duration = 100
                            start()
                        }
                    }
                    android.view.MotionEvent.ACTION_UP, android.view.MotionEvent.ACTION_CANCEL -> {
                        ObjectAnimator.ofFloat(view, "scaleX", 1.0f).apply {
                            duration = 100
                            start()
                        }
                        ObjectAnimator.ofFloat(view, "scaleY", 1.0f).apply {
                            duration = 100
                            start()
                        }
                    }
                }
                false
            }
        }
    }
    
    private fun updateProtectionStatusUI(status: ProtectionStatus) {
        binding.apply {
            protectionToggle.isChecked = status.isEnabled
            
            when (status.level) {
                ThreatLevel.CRITICAL -> {
                    protectionShield.setImageResource(R.drawable.ic_shield_critical)
                    protectionShield.imageTintList = ContextCompat.getColorStateList(this@MainDashboardActivity, R.color.threat_critical)
                    protectionStatusText.text = "Critical Protection Active"
                    protectionStatusText.setTextColor(ContextCompat.getColor(this@MainDashboardActivity, R.color.threat_critical))
                }
                ThreatLevel.HIGH -> {
                    protectionShield.setImageResource(R.drawable.ic_shield_high)
                    protectionShield.imageTintList = ContextCompat.getColorStateList(this@MainDashboardActivity, R.color.threat_high)
                    protectionStatusText.text = "High Protection Active"
                    protectionStatusText.setTextColor(ContextCompat.getColor(this@MainDashboardActivity, R.color.threat_high))
                }
                ThreatLevel.MEDIUM -> {
                    protectionShield.setImageResource(R.drawable.ic_shield_medium)
                    protectionShield.imageTintList = ContextCompat.getColorStateList(this@MainDashboardActivity, R.color.threat_medium)
                    protectionStatusText.text = "Standard Protection Active"
                    protectionStatusText.setTextColor(ContextCompat.getColor(this@MainDashboardActivity, R.color.threat_medium))
                }
                else -> {
                    protectionShield.setImageResource(R.drawable.ic_shield_safe)
                    protectionShield.imageTintList = ContextCompat.getColorStateList(this@MainDashboardActivity, R.color.safe)
                    protectionStatusText.text = "Protection Active"
                    protectionStatusText.setTextColor(ContextCompat.getColor(this@MainDashboardActivity, R.color.safe))
                }
            }
            
            protectionStatusSubtext.text = status.description
            lastUpdateTime.text = "Last updated: ${status.lastUpdate}"
        }
    }
    
    private fun updateScanStatisticsUI(stats: MainDashboardViewModel.ScanStatistics) {
        binding.apply {
            // URLs scanned today
            todayScansCount.text = stats.urlsScannedToday.toString()
            todayScansLabel.text = "URLs Scanned Today"
            
            // Threats blocked today  
            threatsBlockedCount.text = stats.threatsBlockedToday.toString()
            threatsBlockedLabel.text = "Threats Blocked Today"
            
            // Total protection time
            protectionTimeCount.text = stats.protectionTimeFormatted
            protectionTimeLabel.text = "Protection Time"
            
            // Detection accuracy
            accuracyCount.text = "${stats.accuracyPercentage}%"
            accuracyLabel.text = "Detection Accuracy"
            
            // Update progress bars
            todayScansProgress.progress = (stats.urlsScannedToday / 100.0f).coerceAtMost(1.0f)
            threatsBlockedProgress.progress = (stats.threatsBlockedToday / 50.0f).coerceAtMost(1.0f)
        }
    }
    
    private fun updateThreatFeedStatusUI(feedStatus: MainDashboardViewModel.ThreatFeedStatus) {
        binding.apply {
            threatFeedsActiveCount.text = "${feedStatus.activeFeedsCount}/${feedStatus.totalFeedsCount}"
            threatFeedsStatusText.text = when {
                feedStatus.activeFeedsCount == feedStatus.totalFeedsCount -> "All feeds active"
                feedStatus.activeFeedsCount > feedStatus.totalFeedsCount / 2 -> "Most feeds active"
                feedStatus.activeFeedsCount > 0 -> "Some feeds active"
                else -> "No feeds active"
            }
            
            val statusColor = when {
                feedStatus.activeFeedsCount == feedStatus.totalFeedsCount -> R.color.safe
                feedStatus.activeFeedsCount > 0 -> R.color.threat_medium
                else -> R.color.threat_high
            }
            
            threatFeedsStatusIndicator.setCardBackgroundColor(
                ContextCompat.getColor(this@MainDashboardActivity, statusColor)
            )
        }
    }
    
    private fun updateRecentThreatsUI(threats: List<MainDashboardViewModel.RecentThreat>) {
        binding.apply {
            if (threats.isEmpty()) {
                recentThreatsEmpty.visibility = android.view.View.VISIBLE
                recentThreatsList.visibility = android.view.View.GONE
            } else {
                recentThreatsEmpty.visibility = android.view.View.GONE
                recentThreatsList.visibility = android.view.View.VISIBLE
                
                // Show up to 3 most recent threats
                val recentThreatsAdapter = RecentThreatsAdapter(threats.take(3))
                recentThreatsList.adapter = recentThreatsAdapter
            }
        }
    }
    
    private fun showQuickScanDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Quick Security Scan")
            .setMessage("Perform a quick scan of your device's network connections and recently visited URLs?")
            .setPositiveButton("Start Scan") { _, _ ->
                viewModel.performQuickScan()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showManualScanDialog() {
        val binding = com.phishshieldai.android.databinding.DialogManualScanBinding.inflate(layoutInflater)
        
        MaterialAlertDialogBuilder(this)
            .setTitle("Scan URL")
            .setView(binding.root)
            .setPositiveButton("Scan") { _, _ ->
                val url = binding.urlInput.text.toString().trim()
                if (url.isNotEmpty()) {
                    viewModel.scanUrl(url)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    override fun onResume() {
        super.onResume()
        viewModel.refreshData()
    }
}
