package com.phishshieldai.android.ui.monitoring

import android.animation.ValueAnimator
import android.os.Bundle
import android.view.MenuItem
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.ActivityRealtimeMonitoringBinding
import com.phishshieldai.android.ui.adapters.LiveThreatFeedAdapter
import com.phishshieldai.android.ui.adapters.SystemStatusAdapter
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class RealtimeMonitoringActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityRealtimeMonitoringBinding
    private val viewModel: RealtimeMonitoringViewModel by viewModels()
    private lateinit var threatFeedAdapter: LiveThreatFeedAdapter
    private lateinit var systemStatusAdapter: SystemStatusAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRealtimeMonitoringBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        setupObservers()
        setupAnimations()
        
        viewModel.startRealTimeMonitoring()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        viewModel.stopRealTimeMonitoring()
    }
    
    private fun setupUI() {
        // Setup toolbar
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Real-time Monitoring"
        
        // Setup threat feed list
        threatFeedAdapter = LiveThreatFeedAdapter()
        binding.threatFeedRecyclerView.apply {
            adapter = threatFeedAdapter
            layoutManager = LinearLayoutManager(this@RealtimeMonitoringActivity)
        }
        
        // Setup system status list
        systemStatusAdapter = SystemStatusAdapter()
        binding.systemStatusRecyclerView.apply {
            adapter = systemStatusAdapter
            layoutManager = LinearLayoutManager(this@RealtimeMonitoringActivity)
        }
        
        // Setup refresh button
        binding.refreshButton.setOnClickListener {
            viewModel.refreshMonitoring()
        }
        
        // Setup toggle switches
        binding.autoRefreshSwitch.setOnCheckedChangeListener { _, isChecked ->
            viewModel.setAutoRefresh(isChecked)
        }
        
        binding.notificationsSwitch.setOnCheckedChangeListener { _, isChecked ->
            viewModel.setNotificationsEnabled(isChecked)
        }
    }
    
    private fun setupObservers() {
        lifecycleScope.launch {
            viewModel.systemMetrics.collect { metrics ->
                updateSystemMetrics(metrics)
            }
        }
        
        lifecycleScope.launch {
            viewModel.threatFeed.collect { threats ->
                threatFeedAdapter.submitList(threats)
                updateThreatFeedUI(threats)
            }
        }
        
        lifecycleScope.launch {
            viewModel.systemStatus.collect { status ->
                systemStatusAdapter.submitList(status)
            }
        }
        
        lifecycleScope.launch {
            viewModel.networkHealth.collect { health ->
                updateNetworkHealth(health)
            }
        }
        
        lifecycleScope.launch {
            viewModel.protectionLayers.collect { layers ->
                updateProtectionLayers(layers)
            }
        }
        
        lifecycleScope.launch {
            viewModel.isMonitoring.collect { monitoring ->
                updateMonitoringStatus(monitoring)
            }
        }
    }
    
    private fun setupAnimations() {
        // Pulsing animation for active monitoring indicator
        val pulseAnimator = ValueAnimator.ofFloat(0.7f, 1.0f).apply {
            duration = 1000
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.REVERSE
            addUpdateListener { animator ->
                val scale = animator.animatedValue as Float
                binding.monitoringIndicator.scaleX = scale
                binding.monitoringIndicator.scaleY = scale
            }
        }
        pulseAnimator.start()
    }
    
    private fun updateSystemMetrics(metrics: RealtimeMonitoringViewModel.SystemMetrics) {
        binding.apply {
            // CPU Usage
            cpuUsageText.text = "${String.format("%.1f", metrics.cpuUsage)}%"
            cpuUsageProgress.progress = metrics.cpuUsage.toInt()
            
            // Memory Usage
            memoryUsageText.text = "${String.format("%.1f", metrics.memoryUsage)}%"
            memoryUsageProgress.progress = metrics.memoryUsage.toInt()
            
            // Network Latency
            networkLatencyText.text = "${metrics.networkLatency}ms"
            
            // Active Scans
            activeScansText.text = metrics.activeScans.toString()
            
            // Uptime
            uptimeText.text = formatUptime(metrics.uptimeSeconds)
            
            // Threats per minute
            threatsPerMinuteText.text = String.format("%.1f", metrics.threatsPerMinute)
            
            // API Response time
            apiResponseTimeText.text = "${metrics.apiResponseTime}ms"
            
            // Database queries per second
            dbQueriesPerSecText.text = String.format("%.1f", metrics.dbQueriesPerSec)
        }
    }
    
    private fun updateThreatFeedUI(threats: List<RealtimeMonitoringViewModel.LiveThreat>) {
        binding.apply {
            if (threats.isEmpty()) {
                threatFeedEmptyText.visibility = android.view.View.VISIBLE
                threatFeedRecyclerView.visibility = android.view.View.GONE
            } else {
                threatFeedEmptyText.visibility = android.view.View.GONE
                threatFeedRecyclerView.visibility = android.view.View.VISIBLE
            }
            
            threatFeedCountText.text = "${threats.size} active threats"
            
            // Update threat level summary
            val criticalCount = threats.count { it.severity == "Critical" }
            val highCount = threats.count { it.severity == "High" }
            val mediumCount = threats.count { it.severity == "Medium" }
            
            criticalThreatsText.text = criticalCount.toString()
            highThreatsText.text = highCount.toString()
            mediumThreatsText.text = mediumCount.toString()
        }
    }
    
    private fun updateNetworkHealth(health: RealtimeMonitoringViewModel.NetworkHealth) {
        binding.apply {
            // Internet connectivity
            internetStatusText.text = if (health.internetConnected) "Connected" else "Disconnected"
            internetStatusText.setTextColor(
                if (health.internetConnected) {
                    getColor(R.color.success)
                } else {
                    getColor(R.color.threat_high)
                }
            )
            
            // API endpoints status
            apiEndpointsStatusText.text = "${health.activeEndpoints}/${health.totalEndpoints} Active"
            apiEndpointsProgress.progress = ((health.activeEndpoints.toFloat() / health.totalEndpoints) * 100).toInt()
            
            // DNS resolution time
            dnsResolutionText.text = "${health.dnsResolutionTime}ms"
            
            // Bandwidth usage
            bandwidthUsageText.text = formatBandwidth(health.bandwidthUsageKbps)
        }
    }
    
    private fun updateProtectionLayers(layers: List<RealtimeMonitoringViewModel.ProtectionLayer>) {
        binding.protectionLayersContainer.removeAllViews()
        
        layers.forEach { layer ->
            val layerView = layoutInflater.inflate(
                R.layout.item_protection_layer_status,
                binding.protectionLayersContainer,
                false
            )
            
            layerView.findViewById<TextView>(R.id.layer_name).text = layer.name
            layerView.findViewById<TextView>(R.id.layer_status).text = layer.status
            layerView.findViewById<TextView>(R.id.layer_response_time).text = "${layer.responseTime}ms"
            
            val statusIndicator = layerView.findViewById<View>(R.id.status_indicator)
            statusIndicator.setBackgroundColor(
                when (layer.status) {
                    "Active" -> getColor(R.color.success)
                    "Warning" -> getColor(R.color.warning)
                    "Error" -> getColor(R.color.threat_high)
                    else -> getColor(R.color.on_surface_variant)
                }
            )
            
            val progressBar = layerView.findViewById<ProgressBar>(R.id.layer_load_progress)
            progressBar.progress = layer.loadPercentage
            
            binding.protectionLayersContainer.addView(layerView)
        }
    }
    
    private fun updateMonitoringStatus(isMonitoring: Boolean) {
        binding.apply {
            monitoringStatusText.text = if (isMonitoring) "ACTIVE" else "STOPPED"
            monitoringStatusText.setTextColor(
                if (isMonitoring) {
                    getColor(R.color.success)
                } else {
                    getColor(R.color.threat_high)
                }
            )
            
            monitoringIndicator.setColorFilter(
                if (isMonitoring) {
                    getColor(R.color.success)
                } else {
                    getColor(R.color.on_surface_variant)
                }
            )
            
            refreshButton.isEnabled = isMonitoring
        }
    }
    
    private fun formatUptime(seconds: Long): String {
        val hours = seconds / 3600
        val minutes = (seconds % 3600) / 60
        return if (hours > 0) {
            "${hours}h ${minutes}m"
        } else {
            "${minutes}m"
        }
    }
    
    private fun formatBandwidth(kbps: Float): String {
        return when {
            kbps >= 1024 -> "${String.format("%.1f", kbps / 1024)} MB/s"
            else -> "${String.format("%.1f", kbps)} KB/s"
        }
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                onBackPressed()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}
