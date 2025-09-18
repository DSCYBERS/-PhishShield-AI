package com.phishshieldai.android.ui.analytics

import android.graphics.Color
import android.os.Bundle
import android.view.MenuItem
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.github.mikephil.charting.components.Description
import com.github.mikephil.charting.components.XAxis
import com.github.mikephil.charting.data.*
import com.github.mikephil.charting.formatter.IndexAxisValueFormatter
import com.github.mikephil.charting.formatter.PercentFormatter
import com.phishshieldai.android.R
import com.phishshieldai.android.databinding.ActivityAnalyticsBinding
import com.phishshieldai.android.ui.adapters.ScanHistoryAdapter
import com.phishshieldai.android.data.model.ScanHistoryItem
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class AnalyticsActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityAnalyticsBinding
    private val viewModel: AnalyticsViewModel by viewModels()
    private lateinit var scanHistoryAdapter: ScanHistoryAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityAnalyticsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setupUI()
        setupObservers()
        setupCharts()
        
        viewModel.loadAnalytics()
    }
    
    private fun setupUI() {
        // Setup toolbar
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Security Analytics"
        
        // Setup scan history list
        scanHistoryAdapter = ScanHistoryAdapter { scanItem ->
            viewModel.showScanDetails(scanItem)
        }
        
        binding.scanHistoryRecyclerView.apply {
            adapter = scanHistoryAdapter
            layoutManager = LinearLayoutManager(this@AnalyticsActivity)
        }
        
        // Setup time period filter
        setupTimePeriodFilter()
    }
    
    private fun setupObservers() {
        lifecycleScope.launch {
            viewModel.analyticsData.collect { data ->
                updateAnalyticsUI(data)
            }
        }
        
        lifecycleScope.launch {
            viewModel.scanHistory.collect { history ->
                scanHistoryAdapter.submitList(history)
                updateScanHistoryUI(history)
            }
        }
        
        lifecycleScope.launch {
            viewModel.chartData.collect { chartData ->
                updateCharts(chartData)
            }
        }
    }
    
    private fun setupTimePeriodFilter() {
        binding.timePeriodGroup.setOnCheckedChangeListener { _, checkedId ->
            val period = when (checkedId) {
                R.id.btn_24h -> AnalyticsViewModel.TimePeriod.LAST_24H
                R.id.btn_7d -> AnalyticsViewModel.TimePeriod.LAST_7D
                R.id.btn_30d -> AnalyticsViewModel.TimePeriod.LAST_30D
                else -> AnalyticsViewModel.TimePeriod.ALL_TIME
            }
            viewModel.setTimePeriod(period)
        }
        
        // Set default selection
        binding.btn7d.isChecked = true
    }
    
    private fun setupCharts() {
        // Setup Threat Level Distribution Pie Chart
        binding.threatLevelChart.apply {
            setUsePercentValues(true)
            description.isEnabled = false
            setExtraOffsets(5f, 10f, 5f, 5f)
            dragDecelerationFrictionCoef = 0.95f
            isDrawHoleEnabled = true
            setHoleColor(Color.WHITE)
            setTransparentCircleColor(Color.WHITE)
            setTransparentCircleAlpha(110)
            holeRadius = 58f
            transparentCircleRadius = 61f
            setDrawCenterText(true)
            centerText = "Threat\nDistribution"
            rotationAngle = 0f
            isRotationEnabled = true
            isHighlightPerTapEnabled = true
            
            legend.isEnabled = true
            legend.textSize = 12f
        }
        
        // Setup Detection Over Time Line Chart
        binding.detectionTimeChart.apply {
            description.isEnabled = false
            setTouchEnabled(true)
            setDragEnabled(true)
            setScaleEnabled(true)
            setPinchZoom(true)
            
            xAxis.apply {
                position = XAxis.XAxisPosition.BOTTOM
                setDrawGridLines(false)
                textSize = 10f
            }
            
            axisLeft.apply {
                setDrawGridLines(true)
                textSize = 10f
            }
            
            axisRight.isEnabled = false
            legend.isEnabled = true
        }
        
        // Setup Detection Layers Bar Chart
        binding.detectionLayersChart.apply {
            description.isEnabled = false
            setMaxVisibleValueCount(60)
            setPinchZoom(false)
            setDrawBarShadow(false)
            setDrawGridBackground(false)
            
            xAxis.apply {
                position = XAxis.XAxisPosition.BOTTOM
                setDrawGridLines(false)
                granularity = 1f
                textSize = 10f
                setLabelRotationAngle(-45f)
            }
            
            axisLeft.apply {
                setLabelCount(8, false)
                setPosition(YAxis.YAxisLabelPosition.OUTSIDE_CHART)
                spaceTop = 15f
                axisMinimum = 0f
                textSize = 10f
            }
            
            axisRight.isEnabled = false
            legend.isEnabled = true
        }
    }
    
    private fun updateAnalyticsUI(data: AnalyticsViewModel.AnalyticsData) {
        binding.apply {
            // Summary statistics
            totalScansText.text = data.totalScans.toString()
            threatsBlockedText.text = data.threatsBlocked.toString()
            successRateText.text = "${String.format("%.1f", data.successRate)}%"
            avgResponseTimeText.text = "${data.avgResponseTime}ms"
            
            // Detection accuracy
            detectionAccuracyText.text = "${String.format("%.1f", data.detectionAccuracy)}%"
            detectionAccuracyProgress.progress = data.detectionAccuracy.toInt()
            
            // False positive rate
            falsePositiveRateText.text = "${String.format("%.2f", data.falsePositiveRate)}%"
            falsePositiveProgress.progress = (data.falsePositiveRate * 10).toInt()
            
            // Most blocked categories
            updateTopThreatCategories(data.topThreatCategories)
            
            // Active protection layers
            activeLayersText.text = "${data.activeProtectionLayers}/7"
            activeLayersProgress.progress = ((data.activeProtectionLayers / 7.0f) * 100).toInt()
        }
    }
    
    private fun updateScanHistoryUI(history: List<ScanHistoryItem>) {
        binding.apply {
            if (history.isEmpty()) {
                scanHistoryEmptyText.visibility = android.view.View.VISIBLE
                scanHistoryRecyclerView.visibility = android.view.View.GONE
            } else {
                scanHistoryEmptyText.visibility = android.view.View.GONE
                scanHistoryRecyclerView.visibility = android.view.View.VISIBLE
            }
            
            scanHistoryCountText.text = "${history.size} entries"
        }
    }
    
    private fun updateTopThreatCategories(categories: List<Pair<String, Int>>) {
        binding.topThreatCategoriesContainer.removeAllViews()
        
        categories.take(5).forEach { (category, count) ->
            val categoryView = layoutInflater.inflate(
                R.layout.item_threat_category_stat, 
                binding.topThreatCategoriesContainer, 
                false
            )
            
            categoryView.findViewById<TextView>(R.id.category_name).text = category
            categoryView.findViewById<TextView>(R.id.category_count).text = count.toString()
            
            val progressBar = categoryView.findViewById<ProgressBar>(R.id.category_progress)
            val maxCount = categories.maxOfOrNull { it.second } ?: 1
            progressBar.progress = ((count.toFloat() / maxCount) * 100).toInt()
            
            binding.topThreatCategoriesContainer.addView(categoryView)
        }
    }
    
    private fun updateCharts(chartData: AnalyticsViewModel.ChartData) {
        updateThreatLevelChart(chartData.threatLevelDistribution)
        updateDetectionTimeChart(chartData.detectionOverTime)
        updateDetectionLayersChart(chartData.layerEffectiveness)
    }
    
    private fun updateThreatLevelChart(data: Map<String, Int>) {
        val entries = ArrayList<PieEntry>()
        val colors = ArrayList<Int>()
        
        data.forEach { (level, count) ->
            entries.add(PieEntry(count.toFloat(), level))
            colors.add(when (level) {
                "Critical" -> resources.getColor(R.color.threat_critical, theme)
                "High" -> resources.getColor(R.color.threat_high, theme)
                "Medium" -> resources.getColor(R.color.threat_medium, theme)
                "Low" -> resources.getColor(R.color.threat_low, theme)
                else -> resources.getColor(R.color.safe, theme)
            })
        }
        
        val dataSet = PieDataSet(entries, "Threat Levels").apply {
            setDrawIcons(false)
            sliceSpace = 3f
            iconsOffset = MPPointF(0f, 40f)
            selectionShift = 5f
            setColors(colors)
        }
        
        val pieData = PieData(dataSet).apply {
            setValueFormatter(PercentFormatter())
            setValueTextSize(11f)
            setValueTextColor(Color.WHITE)
        }
        
        binding.threatLevelChart.apply {
            this.data = pieData
            invalidate()
        }
    }
    
    private fun updateDetectionTimeChart(data: List<Pair<String, Float>>) {
        val entries = ArrayList<Entry>()
        val labels = ArrayList<String>()
        
        data.forEachIndexed { index, (time, detections) ->
            entries.add(Entry(index.toFloat(), detections))
            labels.add(time)
        }
        
        val dataSet = LineDataSet(entries, "Detections").apply {
            color = resources.getColor(R.color.primary, theme)
            setCircleColor(resources.getColor(R.color.primary, theme))
            lineWidth = 2f
            circleRadius = 4f
            setDrawCircleHole(false)
            valueTextSize = 9f
            setDrawFilled(true)
            fillColor = resources.getColor(R.color.primary_light, theme)
        }
        
        val lineData = LineData(dataSet)
        
        binding.detectionTimeChart.apply {
            this.data = lineData
            xAxis.valueFormatter = IndexAxisValueFormatter(labels)
            invalidate()
        }
    }
    
    private fun updateDetectionLayersChart(data: Map<String, Float>) {
        val entries = ArrayList<BarEntry>()
        val labels = ArrayList<String>()
        
        data.entries.forEachIndexed { index, (layer, effectiveness) ->
            entries.add(BarEntry(index.toFloat(), effectiveness))
            labels.add(layer)
        }
        
        val dataSet = BarDataSet(entries, "Layer Effectiveness").apply {
            setColors(
                resources.getColor(R.color.primary, theme),
                resources.getColor(R.color.secondary, theme),
                resources.getColor(R.color.success, theme),
                resources.getColor(R.color.warning, theme),
                resources.getColor(R.color.info, theme),
                resources.getColor(R.color.threat_medium, theme),
                resources.getColor(R.color.threat_high, theme)
            )
            valueTextSize = 10f
        }
        
        val barData = BarData(dataSet).apply {
            barWidth = 0.9f
        }
        
        binding.detectionLayersChart.apply {
            this.data = barData
            xAxis.valueFormatter = IndexAxisValueFormatter(labels)
            setFitBars(true)
            invalidate()
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
